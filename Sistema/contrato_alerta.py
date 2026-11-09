# -*- coding: utf-8 -*-
"""
Contrato de alerta de ThreatLens.

Implementa las entidades Alerta, ResultadoAnalisis y Recomendaciones del
modelo de dominio del reporte de PT1 (Figura 7, seccion 5.5).

Es la UNICA definicion del registro de alerta en el sistema. Los tres
detectores la importan y la usan para construir su salida; el repositorio
la guarda tal cual; el frontend la consume tal cual. Si un campo cambia,
cambia aqui y en ningun otro lado.
"""

import hashlib
from datetime import datetime


# --- Vocabulario cerrado ------------------------------------------------
# Son los unicos valores validos. Cerrarlos evita que un detector escriba
# "ALTO" y otro "alto", que es como empiezan los bugs del frontend.

VECTORES = ("phishing", "acceso_remoto", "malware")

NIVELES = ("alto", "medio", "bajo")

ESTADOS = ("nueva", "confirmada", "falso_positivo")

# De donde salio la deteccion. Importa para la interfaz: una alerta de
# modelo muestra su probabilidad, una de regla muestra que regla se
# cumplio. Son cosas distintas y presentarlas igual engana al analista.
ORIGENES = ("modelo", "regla", "modelo+regla")

# Tecnicas MITRE ATT&CK por vector. El reporte las muestra en la pantalla
# de detalle (Figura 22) pero no las modela, asi que se fijan aqui.
# Catalogo de tecnicas MITRE ATT&CK que el sistema puede citar. Vive
# aqui para que los tres detectores usen el mismo identificador y el
# mismo nombre, y para poder revisarlo en un solo lugar.
TECNICAS = {
    "T1018": "Remote System Discovery",
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.004": "SSH",
    "T1027": "Obfuscated Files or Information",
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.003": "Password Spraying",
    "T1219": "Remote Access Software",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
}


def tecnicas(*ids):
    """
    Devuelve las tecnicas en el formato del contrato.

    Se usa en lugar de escribir los diccionarios a mano: un
    identificador mal escrito falla aqui y no llega a la pantalla de
    detalle como una tecnica que no existe.
    """
    salida = []
    for t in ids:
        if t not in TECNICAS:
            raise ValueError(f"tecnica MITRE desconocida: {t}")
        salida.append({"id": t, "nombre": TECNICAS[t]})
    return salida


# Tecnicas por omision, para cuando el detector no precisa cuales
# aplican. Son las mas generales de cada vector: citar una especifica
# sin haberla observado seria atribuir al ataque algo que no se vio.
MITRE = {
    "phishing": tecnicas("T1566"),
    "acceso_remoto": tecnicas("T1021"),
    "malware": tecnicas("T1059"),
}

def normalizar_fecha(valor):
    """
    Devuelve la fecha en ISO 8601: 2019-09-23T13:23:30

    Si el valor ya trae desplazamiento horario (-04:00, Z) se respeta tal
    cual. Esa informacion no se inventa ni se descarta: el corpus OpTC la
    trae y Advanced Hunting tambien.
    """
    if not valor:
        return ""
    texto = str(valor).strip()
    if "T" in texto:
        return texto
    for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(texto, formato).isoformat()
        except ValueError:
            continue
    return texto


# --- Identificador ------------------------------------------------------

def generar_id(tipo_amenaza, equipo, fecha, huella):
    """
    Construye el campo ID de la entidad Alerta.

    Es determinista a proposito: la misma deteccion procesada dos veces
    produce el mismo ID, de modo que el repositorio puede rechazar el
    duplicado en vez de guardar la alerta dos veces. Eso importa porque
    el modulo de gestion de logs consulta ventanas que se traslapan.

    huella: lo que distingue a esta alerta de otra del mismo vector en el
            mismo equipo y la misma hora. Para malware, el actor_id del
            proceso. Para accesos, la cuenta y el destino. Para phishing,
            el identificador del correo.
    """
    crudo = f"{tipo_amenaza}|{equipo}|{fecha}|{huella}"
    resumen = hashlib.sha1(crudo.encode("utf-8")).hexdigest()
    return f"alert-{resumen[:12]}"

# --- Construccion de la alerta -----------------------------------------

def nueva_alerta(tipo_amenaza, nivel_severidad, descripcion, equipo, fecha,
                 probabilidad, modelo, evento, vector=None, motivos=None,
                 huella="", n_eventos=1, origen_deteccion="modelo",
                 reglas=None, mitre=None):
    """
    Devuelve el documento de alerta completo.

    Los nombres de los campos siguen el modelo de dominio del reporte, en
    minusculas y con guion bajo. La correspondencia es directa:

        Alerta.ID                -> id
        Alerta.Tipo_Amenaza      -> tipo_amenaza
        Alerta.Nivel_Severidad   -> nivel_severidad
        Alerta.Descripcion       -> descripcion
        Alerta.Equipo            -> equipo
        Alerta.Resultado_Analisis-> resultado_analisis
        Alerta.Recomendaciones   -> recomendaciones

    probabilidad admite None, y solo cuando origen_deteccion es "regla".
    Una regla determinista no produce una probabilidad, y poner un numero
    inventado ahi haria que la interfaz presentara como medida algo que
    no se midio.
    """
    if tipo_amenaza not in VECTORES:
        raise ValueError(f"tipo_amenaza invalido: {tipo_amenaza}")
    if nivel_severidad not in NIVELES:
        raise ValueError(f"nivel_severidad invalido: {nivel_severidad}")
    if origen_deteccion not in ORIGENES:
        raise ValueError(f"origen_deteccion invalido: {origen_deteccion}")

    if probabilidad is None:
        if origen_deteccion != "regla":
            raise ValueError(
                "probabilidad None solo se admite con origen_deteccion='regla'")
    elif not 0.0 <= probabilidad <= 1.0:
        raise ValueError(f"probabilidad fuera de [0,1]: {probabilidad}")

    fecha = normalizar_fecha(fecha)

    resultado = {
        "probabilidad": (None if probabilidad is None
                         else round(float(probabilidad), 4)),
        "origen_deteccion": origen_deteccion,
        "reglas": reglas or [],
        "es_malicioso": True,
        "nivel_riesgo": nivel_severidad,
        "modelo": modelo,
        "vector": vector or {},
        "evento": evento,
    }

    return {
        "id": generar_id(tipo_amenaza, equipo, fecha, huella),
        "tipo_amenaza": tipo_amenaza,
        "nivel_severidad": nivel_severidad,
        "descripcion": descripcion,
        "equipo": equipo,
        "fecha": fecha,
        "estado": "nueva",
        "notificar": nivel_severidad == "alto",
        "n_eventos": n_eventos,
        "motivos": motivos or [],
        "mitre": mitre if mitre else MITRE[tipo_amenaza],
        "resultado_analisis": resultado,
        "recomendaciones": None,
    }

# --- Validacion ---------------------------------------------------------

OBLIGATORIOS = ("id", "tipo_amenaza", "nivel_severidad", "descripcion",
                "equipo", "fecha", "estado", "resultado_analisis")


def validar(alerta):
    """
    Revisa que un documento cumpla el contrato. Devuelve la lista de
    problemas encontrados; si esta vacia, el documento es valido.

    Se usa en las pruebas de los tres detectores y antes de escribir en
    MongoDB. No lanza excepcion: devuelve todos los problemas de una vez
    para que no tengas que corregirlos de uno en uno.
    """
    fallas = []

    for campo in OBLIGATORIOS:
        if campo not in alerta:
            fallas.append(f"falta el campo '{campo}'")

    if alerta.get("tipo_amenaza") not in VECTORES:
        fallas.append(f"tipo_amenaza invalido: {alerta.get('tipo_amenaza')}")
    if alerta.get("nivel_severidad") not in NIVELES:
        fallas.append(f"nivel_severidad invalido: {alerta.get('nivel_severidad')}")
    if alerta.get("estado") not in ESTADOS:
        fallas.append(f"estado invalido: {alerta.get('estado')}")

    resultado = alerta.get("resultado_analisis") or {}
    for campo in ("probabilidad", "origen_deteccion", "es_malicioso",
                  "modelo", "evento"):
        if campo not in resultado:
            fallas.append(f"falta resultado_analisis.{campo}")

    origen = resultado.get("origen_deteccion")
    if origen not in ORIGENES:
        fallas.append(f"origen_deteccion invalido: {origen}")

    p = resultado.get("probabilidad")
    if p is None:
        if origen != "regla":
            fallas.append("probabilidad None con origen_deteccion distinto de 'regla'")
    elif not 0.0 <= p <= 1.0:
        fallas.append(f"probabilidad fuera de [0,1]: {p}")

    return fallas

