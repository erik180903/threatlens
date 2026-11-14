"""
ThreatLens - Deteccion de accesos remotos no autorizados.

Es el modulo que importa el sistema. Recibe lo que entrega Advanced Hunting
y devuelve el veredicto con su nivel de severidad.

ENTRADAS
    ventana    <- DeviceLogonEvents agregados por (cuenta, origen, destino, hora)
    rafaga     <- DeviceLogonEvents, fallos por (origen, destino, 5 min)
    conexion   <- DeviceNetworkEvents.RemotePort / RemoteIP / ActionType
    procesos   <- DeviceProcessEvents.FileName / ProcessCommandLine

TRES DETECTORES, NO UNO
    A2  modelo     autenticacion anomala: credenciales validas, destino
                   nuevo para ese usuario. Random Forest, 28 caracteristicas.
    A1  regla      fuerza bruta y spraying. Umbral calibrado sobre 58 dias
                   de trafico corporativo real.
    B   inventario herramientas de acceso remoto no autorizadas.

    Se verifico que A1 y A2 no se solapan: de los 702 eventos del red team
    de LANL, 701 fueron autenticaciones EXITOSAS, asi que ninguna rafaga de
    fallos coincide con actividad del red team. Cada uno ve lo que el otro
    no puede ver.

LAS REGLAS NUNCA BAJAN LA SEVERIDAD
    CONCLUYENTES  disparan por si solas aunque el modelo no sospeche:
                  herramienta remota fuera del inventario, RDP/SSH entrante
                  desde una IP publica, Telnet o FTP entrante.
    ESCALADORAS   solo suben un nivel que el modelo ya marco.

PERFILES
    Los umbrales dependen del tamaño del entorno, no del ataque. El mismo
    Hydra dispara igual en 4 equipos que en 4,000; lo que cambia es cuanto
    ruido de fondo hay que tolerar. Por eso los umbrales se guardan por
    perfil y se elige cual operar.

LIMITACION DEL MODELO A2 EN ENTORNOS PEQUEÑOS
    A2 se ajusto en un entorno de 17,684 equipos donde un usuario toca 7.5
    destinos en promedio. Sus caracteristicas son relacionales: "nunca habia
    tocado este destino", "cuantos destinos distintos toca". En un entorno
    de 3 o 4 equipos esas caracteristicas se degradan -- a los pocos dias
    todos tocaron todo -- y el modelo extrapola fuera del rango en el que
    fue ajustado.

    El detector NO desactiva A2 por eso. Lo marca: cuando el perfil declara
    pocos equipos, cada resultado lleva 'a2_fuera_de_rango': True. Apagarlo
    escondería la limitacion; marcarlo la documenta en cada alerta.

    python detectar_accesos.py
"""

import ipaddress
import json
import os
import sys
from datetime import datetime

# El contrato de alerta vive en Sistema\, carpeta hermana de esta.
_AQUI = os.path.dirname(os.path.abspath(__file__))
_SISTEMA = os.path.join(os.path.dirname(_AQUI), "Sistema")
sys.path.insert(0, _SISTEMA)
from contrato_alerta import nueva_alerta, validar, tecnicas        # noqa: E402

NIVELES_ORDEN = ["ninguna", "bajo", "medio", "alto"]

# --------------------------------------------------------------------
# Inventario de herramientas de acceso remoto
# --------------------------------------------------------------------

# De terceros: no vienen con Windows. Su sola presencia es un hallazgo
# si no estan declaradas como autorizadas.
HERRAMIENTAS_TERCEROS = {
    "anydesk.exe", "teamviewer.exe", "tv_w32.exe", "tv_x64.exe",
    "mobaxterm.exe", "rustdesk.exe", "screenconnect.clientservice.exe",
    "connectwisecontrol.client.exe", "vncserver.exe", "winvnc.exe",
    "tightvnc.exe", "ultravnc.exe", "radmin.exe", "rutserv.exe",
    "supremo.exe", "ammyy.exe", "aa_v3.exe", "logmein.exe", "lmiguardiansvc.exe",
    "gotoassist.exe", "dwservice.exe", "splashtop.exe", "srmanager.exe",
    "ngrok.exe", "chrome-remote-desktop-host.exe",
}

# Nativas de Windows o de administracion legitima. Presentes por defecto,
# asi que solo importan en contexto.
HERRAMIENTAS_NATIVAS = {
    "mstsc.exe", "psexec.exe", "psexesvc.exe", "winrs.exe", "wmic.exe",
    "powershell.exe", "pwsh.exe", "sshd.exe", "ssh.exe", "putty.exe",
}

# --------------------------------------------------------------------
# Puertos de acceso remoto
# --------------------------------------------------------------------

PUERTOS_REMOTOS = {
    3389: "RDP", 22: "SSH", 23: "Telnet", 21: "FTP",
    5900: "VNC", 5938: "TeamViewer", 7070: "AnyDesk",
}

# Protocolos sin cifrado: el trafico viaja en claro, incluidas credenciales.
PUERTOS_EN_CLARO = {23, 21}


def _es_publica(ip):
    """True si la IP esta fuera de los rangos privados (RFC 1918 y vecinos).
    Una conexion entrante a RDP desde una IP publica es un hallazgo distinto
    de una entre dos equipos de la misma oficina."""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_reserved or a.is_multicast)


def _nombre_archivo(ruta):
    """Ultimo componente de una ruta, cortando en / y en \\.

    No se usa os.path.basename: Advanced Hunting devuelve SIEMPRE rutas de
    Windows, y si el detector corre sobre Linux basename no corta en '\\',
    asi que 'C:\\Program Files\\AnyDesk\\AnyDesk.exe' no coincidiria
    nunca con el inventario.
    """
    t = str(ruta).strip().strip('"').replace("\\", "/")
    return t.rsplit("/", 1)[-1].lower()


def _max_nivel(a, b):
    return a if NIVELES_ORDEN.index(a) >= NIVELES_ORDEN.index(b) else b


# --------------------------------------------------------------------

class DetectorAccesosRemotos:
    """Combina el modelo A2 con las reglas A1 y B.

    dir_modelos   carpeta con contrato_accesos.json, umbrales_accesos.json,
                  umbrales_fuerza_bruta.json y el .joblib del modelo
    inventario    nombres de proceso autorizados en esta organizacion
                  (minusculas). Lo que no este aqui y sea herramienta de
                  acceso remoto de terceros genera alerta.
    modo_alerta   'verificacion' (por omision) pide confirmar y da el motivo;
                  'veredicto' afirma. Ver NOTA al final sobre por que el
                  valor por omision no es 'veredicto'.
    equipos       numero de equipos del entorno. Solo se usa para marcar
                  cuando A2 esta fuera de su rango de ajuste.
    """

    MIN_EQUIPOS_A2 = 25      # por debajo de esto A2 extrapola

    @classmethod
    def desde_config(cls, ruta="config_accesos.json"):
        """Construye el detector leyendo config_accesos.json.

        Es la forma en que deberia instanciarlo el sistema: los parametros
        del entorno (cuantos equipos, que herramientas estan autorizadas,
        como se redacta la alerta) viven en un archivo, no repartidos por
        el codigo. Pasar de laboratorio a produccion es cambiar una
        palabra en 'activo', no buscar constructores.
        """
        if not os.path.exists(ruta):
            raise FileNotFoundError(
                f"Falta {ruta}. Copia el que viene con el modulo y ajusta "
                f"'activo' al perfil que vayas a operar.")
        with open(ruta, encoding="utf-8") as f:
            cfg = json.load(f)

        nombre = cfg["activo"]
        if nombre not in cfg["perfiles"]:
            raise KeyError(f"El perfil '{nombre}' no existe en {ruta}. "
                           f"Disponibles: {list(cfg['perfiles'])}")
        p = cfg["perfiles"][nombre]

        det = cls(dir_modelos=p.get("dir_modelos", "modelos_accesos"),
                  inventario=p.get("inventario_autorizado"),
                  modo_alerta=p.get("modo_alerta", "verificacion"),
                  equipos=p.get("equipos"))
        det.perfil = nombre
        return det

    def __init__(self, dir_modelos="modelos_accesos", inventario=None,
                 modo_alerta="verificacion", equipos=None):
        self.dir = dir_modelos
        self.inventario = {s.lower() for s in (inventario or [])}
        self.modo_alerta = modo_alerta
        self.modelo = None
        self.nombre_modelo = None
        self.caracteristicas = []
        self.umbrales = {}
        self.umbral_fb = None
        self.umbral_sp = None
        self.equipos = equipos
        self.avisos = []

        self._cargar_modelo()
        self._cargar_umbrales_a2()
        self._cargar_umbrales_a1()

        if self.equipos is None:
            self.equipos = self._equipos_declarados()
        self.a2_fuera_de_rango = (self.equipos is not None
                                  and self.equipos < self.MIN_EQUIPOS_A2)
        if self.a2_fuera_de_rango:
            self.avisos.append(
                f"A2 opera fuera de su rango de ajuste: el entorno declara "
                f"{self.equipos} equipos y el modelo se ajusto sobre 17,684. "
                f"Sus caracteristicas relacionales se degradan; los puntajes "
                f"no son comparables con los del reporte.")

    # -- carga -------------------------------------------------------

    def _leer(self, nombre):
        ruta = os.path.join(self.dir, nombre)
        if not os.path.exists(ruta):
            return None
        with open(ruta, encoding="utf-8") as f:
            return json.load(f)

    def _cargar_modelo(self):
        contrato = self._leer("contrato_accesos.json")
        if not contrato:
            self.avisos.append("Sin contrato_accesos.json: A2 desactivado, "
                               "solo operan las reglas A1 y B.")
            return
        nombre = contrato["seleccionado"]
        # Se guarda para poder reportarlo en el campo
        # resultado_analisis.modelo de la alerta.
        self.nombre_modelo = nombre
        self.caracteristicas = contrato["modelos"][nombre]["caracteristicas"]
        ruta = os.path.join(self.dir, f"{nombre}.joblib")
        if not os.path.exists(ruta):
            self.avisos.append(f"Falta {nombre}.joblib (lo genera "
                               "umbrales_accesos.py): A2 desactivado.")
            return
        import joblib
        self.modelo = joblib.load(ruta)

    def _cargar_umbrales_a2(self):
        u = self._leer("umbrales_accesos.json")
        if not u:
            if self.modelo is not None:
                self.avisos.append("Sin umbrales_accesos.json: A2 no puede "
                                   "asignar severidad.")
            return
        self.umbrales = {k: v["umbral"] for k, v in u["niveles"].items()}
        self._equipos_a2 = u.get("equipos_referencia")

    def _cargar_umbrales_a1(self):
        u = self._leer("umbrales_fuerza_bruta.json")
        if not u:
            self.avisos.append("Sin umbrales_fuerza_bruta.json: A1 desactivado.")
            return
        self.umbral_fb = u["fuerza_bruta"]["recomendado"]["umbral"]
        self.umbral_sp = u["spraying"]["recomendado"]["umbral"]
        self._equipos_a1 = u.get("equipos_referencia")
        self.ventana_a1 = u.get("ventana_segundos", 300)

        if not u["fuerza_bruta"].get("cumple_presupuesto", True):
            self.avisos.append(
                f"El umbral de fuerza bruta ({self.umbral_fb}) no alcanza el "
                f"presupuesto de alertas del perfil: es el mas exigente "
                f"disponible, no uno que cumpla la meta.")

        a1 = getattr(self, "_equipos_a1", None)
        a2 = getattr(self, "_equipos_a2", None)
        if a1 is not None and a2 is not None and a1 != a2:
            self.avisos.append(
                f"Los umbrales no son del mismo perfil: A1 calibrado para "
                f"{a1} equipos, A2 para {a2}. Re-deriva A1 con "
                f"'--desde-json --equipos {a2}' o acepta la mezcla a sabiendas.")

    def _equipos_declarados(self):
        for attr in ("_equipos_a1", "_equipos_a2"):
            v = getattr(self, attr, None)
            if v is not None:
                return v
        return None

    # -- A2: modelo --------------------------------------------------

    def evaluar_ventana(self, caracteristicas):
        """caracteristicas: dict {nombre: valor} con las 28 del contrato.

        Se valida contra la lista del contrato y se arma el vector en ese
        orden. Es el mismo contrato de espacio de caracteristicas que en
        phishing: si entrenamiento e inferencia calcularan el vector por
        separado, cualquier divergencia daria un modelo que funciona en las
        pruebas y basura en produccion, sin error visible.
        """
        if self.modelo is None or not self.umbrales:
            return {"nivel": "ninguna", "probabilidad": None,
                    "motivos": [], "disponible": False}

        faltan = [c for c in self.caracteristicas if c not in caracteristicas]
        if faltan:
            raise ValueError(
                f"Faltan {len(faltan)} caracteristicas requeridas por el "
                f"contrato: {faltan[:5]}{'...' if len(faltan) > 5 else ''}")

        vector = [[float(caracteristicas[c]) for c in self.caracteristicas]]
        p = float(self.modelo.predict_proba(vector)[0][1])

        nivel = "ninguna"
        for etq in ("alto", "medio", "bajo"):
            if etq in self.umbrales and p >= self.umbrales[etq]:
                nivel = etq
                break

        motivos = []
        if nivel != "ninguna":
            if caracteristicas.get("his_par_nuevo"):
                motivos.append("la cuenta nunca habia accedido a este equipo")
            if caracteristicas.get("his_origen_nuevo"):
                motivos.append("el equipo de origen es nuevo para esta cuenta")
            if float(caracteristicas.get("ven_frac_ntlm", 0)) > 0.5:
                motivos.append("autenticacion NTLM predominante")
            if not motivos:
                motivos.append("patron de autenticacion atipico para la cuenta")

        return {"nivel": nivel, "probabilidad": p, "motivos": motivos,
                "disponible": True,
                "fuera_de_rango": self.a2_fuera_de_rango}

    # -- A1: fuerza bruta y spraying ---------------------------------

    def evaluar_rafaga(self, fallos=0, cuentas_distintas=0, destino=None,
                       origen=None):
        """fallos             fallos contra un mismo destino desde un origen
                              en la ventana (por omision 5 min)
           cuentas_distintas  cuentas distintas con fallo desde ese origen
        """
        nivel, motivos = "ninguna", []
        concluyente = False

        if self.umbral_fb is not None and fallos >= self.umbral_fb:
            nivel = "alto"
            concluyente = True
            motivos.append(
                f"{fallos} autenticaciones fallidas contra "
                f"{destino or 'el equipo'} en {self.ventana_a1 // 60} min "
                f"(umbral {self.umbral_fb})")

        if self.umbral_sp is not None and cuentas_distintas >= self.umbral_sp:
            nivel = "alto"
            concluyente = True
            motivos.append(
                f"intentos fallidos contra {cuentas_distintas} cuentas "
                f"distintas desde {origen or 'un mismo origen'} "
                f"(umbral {self.umbral_sp})")

        # A medio camino del umbral ya merece quedar registrado.
        if nivel == "ninguna" and self.umbral_fb and fallos >= self.umbral_fb / 2:
            nivel = "medio"
            motivos.append(f"{fallos} fallos de autenticacion, por debajo del "
                           f"umbral pero sobre el ruido habitual")

        return {"nivel": nivel, "motivos": motivos, "concluyente": concluyente}

    # -- B: herramientas de acceso remoto ----------------------------

    def evaluar_procesos(self, procesos=None):
        """procesos: nombres de archivo de DeviceProcessEvents.FileName"""
        nivel, motivos = "ninguna", []
        concluyente = False

        for p in (procesos or []):
            nombre = _nombre_archivo(p)
            if nombre in self.inventario:
                continue
            if nombre in HERRAMIENTAS_TERCEROS:
                nivel = "alto"
                concluyente = True
                motivos.append(f"herramienta de acceso remoto '{nombre}' "
                               f"fuera del inventario autorizado")
            elif nombre in HERRAMIENTAS_NATIVAS:
                nivel = _max_nivel(nivel, "bajo")
                motivos.append(f"uso de '{nombre}' (nativa, revisar contexto)")

        return {"nivel": nivel, "motivos": motivos, "concluyente": concluyente}

    # -- Conexiones de red -------------------------------------------

    def evaluar_conexion(self, puerto=None, ip_remota=None, entrante=False):
        """puerto <- DeviceNetworkEvents.RemotePort
           entrante: True si la conexion llega al equipo, no sale de el"""
        nivel, motivos = "ninguna", []
        concluyente = False

        if puerto is None or int(puerto) not in PUERTOS_REMOTOS:
            return {"nivel": nivel, "motivos": motivos, "concluyente": False}

        puerto = int(puerto)
        servicio = PUERTOS_REMOTOS[puerto]
        publica = _es_publica(ip_remota)

        if entrante and publica:
            nivel = "alto"
            concluyente = True
            motivos.append(f"conexion {servicio} entrante desde la IP publica "
                           f"{ip_remota}")
        elif entrante:
            nivel = "bajo"
            motivos.append(f"conexion {servicio} entrante desde {ip_remota}")

        if puerto in PUERTOS_EN_CLARO:
            nivel = _max_nivel(nivel, "medio")
            motivos.append(f"{servicio} transmite credenciales sin cifrar")

        return {"nivel": nivel, "motivos": motivos, "concluyente": concluyente}

    # -- Combinacion -------------------------------------------------

    def evaluar(self, caracteristicas=None, fallos=0, cuentas_distintas=0,
                procesos=None, puerto=None, ip_remota=None, entrante=False,
                cuenta=None, origen=None, destino=None):
        """Devuelve el veredicto combinado."""
        partes = {}
        nivel = "ninguna"
        motivos = []
        concluyentes = []

        if caracteristicas:
            a2 = self.evaluar_ventana(caracteristicas)
            partes["modelo"] = a2
            nivel = _max_nivel(nivel, a2["nivel"])
            motivos += a2["motivos"]

        for clave, res in (
            ("rafaga", self.evaluar_rafaga(fallos, cuentas_distintas,
                                           destino, origen)),
            ("procesos", self.evaluar_procesos(procesos)),
            ("conexion", self.evaluar_conexion(puerto, ip_remota, entrante)),
        ):
            partes[clave] = res
            nivel = _max_nivel(nivel, res["nivel"])
            motivos += res["motivos"]
            if res["concluyente"]:
                concluyentes.append(clave)

        return {
            "nivel_severidad": nivel,
            "notificar": nivel == "alto",
            "motivos": motivos,
            "reglas_concluyentes": concluyentes,
            "a2_fuera_de_rango": self.a2_fuera_de_rango,
            "mensaje": self.redactar(nivel, motivos, cuenta, destino),
            "detalle": partes,
        }

    # -- Texto de la alerta ------------------------------------------

    def redactar(self, nivel, motivos, cuenta=None, destino=None):
        if nivel == "ninguna":
            return ""
        quien = f"{cuenta or 'Una cuenta'} -> {destino or 'un equipo'}"
        razon = "; ".join(motivos) if motivos else "patron atipico"

        if self.modo_alerta == "veredicto":
            if nivel == "alto":
                return f"Acceso remoto no autorizado: {quien}. {razon}."
            return f"Acceso remoto sospechoso ({nivel}): {quien}. {razon}."

        # modo verificacion (por omision)
        if nivel == "alto":
            return (f"Acceso remoto inusual: {quien}. {razon}. "
                    f"Verifica si fue legitimo.")
        return f"Acceso remoto para revisar ({nivel}): {quien}. {razon}."

    # -- Traduccion al contrato de alerta -----------------------------

    def _titular(self, reglas, contexto):
        """
        Construye el campo Descripcion: el titulo que el analista lee en
        el historial y en la cabecera de la pantalla de detalle. Tiene
        que decir QUE paso, no cual fue el puntaje.
        """
        destino = contexto.get("destino") or "un equipo"

        if "rafaga" in reglas:
            fallos = int(contexto.get("fallos", 0) or 0)
            cuentas = int(contexto.get("cuentas_distintas", 0) or 0)
            if fallos:
                return (f"Fuerza bruta — {fallos} autenticaciones fallidas "
                        f"contra {destino}")
            if cuentas:
                origen = contexto.get("origen") or "un equipo"
                return (f"Password spraying — {cuentas} cuentas probadas "
                        f"desde {origen}")
            return f"Rafaga de autenticaciones fallidas — {destino}"

        if "conexion" in reglas:
            puerto = contexto.get("puerto")
            if puerto:
                return f"Conexion remota sospechosa — puerto {puerto} en {destino}"
            return f"Conexion remota sospechosa — {destino}"

        if "procesos" in reglas:
            proceso = contexto.get("proceso") or ""
            proceso = _nombre_archivo(proceso) or "herramienta no autorizada"
            return f"Herramienta de acceso remoto no autorizada — {proceso}"

        cuenta = contexto.get("cuenta") or "una cuenta"
        return f"Acceso remoto inusual — {cuenta} hacia {destino}"

    def a_contrato(self, veredicto, contexto):
        """
        Traduce el veredicto de evaluar() al documento del contrato.

        veredicto  lo que devuelve evaluar()
        contexto   dict con los datos crudos del evento: fecha, destino,
                   cuenta, origen, ip_local, ip_remota, protocolo,
                   puerto, procesos, fallos, cuentas_distintas,
                   tipo_logon

        Devuelve None si no hubo alerta.
        """
        if veredicto["nivel_severidad"] == "ninguna":
            return None

        contexto = dict(contexto)
        procesos = contexto.get("procesos") or []
        if not contexto.get("proceso") and procesos:
            contexto["proceso"] = procesos[0]

        # Que componente levanto la alerta. Un mismo evento puede
        # dispararse por el modelo, por una regla, o por los dos.
        reglas = []
        hubo_modelo = False
        for clave, parte in veredicto["detalle"].items():
            if parte.get("nivel", "ninguna") == "ninguna":
                continue
            if clave == "modelo":
                hubo_modelo = True
            else:
                reglas.append(clave)

        if hubo_modelo and reglas:
            origen_deteccion = "modelo+regla"
        elif hubo_modelo:
            origen_deteccion = "modelo"
        else:
            origen_deteccion = "regla"

        # La probabilidad se guarda siempre que el modelo haya corrido,
        # aunque no cruzara su umbral: es una medicion y sirve para
        # auditar despues. Si el modelo no corrio queda en None, y la
        # interfaz muestra la regla en lugar del recuadro de
        # probabilidad.
        parte_modelo = veredicto["detalle"].get("modelo") or {}
        probabilidad = parte_modelo.get("probabilidad")

        # Para spraying no hay un destino unico: el hecho ocurre en el
        # equipo de origen, y ese es el equipo de la alerta.
        equipo = contexto.get("destino") or contexto.get("origen") or ""

        evento = {
            "equipo": equipo,
            "cuenta": contexto.get("cuenta", ""),
            "origen": contexto.get("origen", ""),
            "ip_local": contexto.get("ip_local", ""),
            "ip_remota": contexto.get("ip_remota", ""),
            "protocolo": contexto.get("protocolo", ""),
            "puerto": contexto.get("puerto", ""),
            "proceso": contexto.get("proceso", ""),
            "intentos_fallidos": int(contexto.get("fallos", 0) or 0),
            "cuentas_distintas": int(contexto.get("cuentas_distintas", 0) or 0),
            "tipo_logon": contexto.get("tipo_logon", ""),
            "tabla_origen": "DeviceLogonEvents",
            "mensaje": veredicto.get("mensaje", ""),
            # Marca de honestidad: si el entorno declara menos equipos
            # que el rango en que se ajusto A2, su puntaje no es
            # comparable con el del reporte y la interfaz debe decirlo.
            "a2_fuera_de_rango": veredicto.get("a2_fuera_de_rango", False),
        }

        huella = "|".join([
            str(contexto.get("cuenta", "")),
            str(contexto.get("origen", "")),
            str(contexto.get("destino", "")),
            str(contexto.get("puerto", "")),
            str(contexto.get("proceso", "")),
        ])

        # Tecnicas segun lo que efectivamente se observo. Citarlas por
        # vector atribuia fuerza bruta a una conexion Telnet y servicios
        # remotos a un password spraying.
        ids = []
        if "rafaga" in reglas:
            if int(contexto.get("cuentas_distintas", 0) or 0):
                ids.append("T1110.003")
            else:
                ids.append("T1110")
        if "conexion" in reglas:
            ids.append("T1021")
            puerto = contexto.get("puerto")
            if puerto == 3389:
                ids.append("T1021.001")
            elif puerto == 22:
                ids.append("T1021.004")
        if "procesos" in reglas:
            ids.append("T1219")
        if hubo_modelo:
            # El modelo detecta autenticacion anomala de una cuenta que
            # si existe y si tiene permiso: eso es T1078, no fuerza bruta.
            ids.append("T1078")
        if not ids:
            ids.append("T1021")

        return nueva_alerta(
            tipo_amenaza="acceso_remoto",
            nivel_severidad=veredicto["nivel_severidad"],
            descripcion=self._titular(reglas, contexto),
            equipo=equipo,
            fecha=contexto.get("fecha", ""),
            probabilidad=probabilidad,
            # Si el modelo no corrio, decirlo. Nombrar el algoritmo en
            # una alerta que salio solo de una regla sugiere que
            # clasifico algo, y no clasifico nada.
            modelo=(self.nombre_modelo if probabilidad is not None
                    else "solo_reglas"),
            evento=evento,
            vector=contexto.get("caracteristicas") or {},
            motivos=veredicto.get("motivos", []),
            huella=huella,
            origen_deteccion=origen_deteccion,
            reglas=sorted(reglas),
            mitre=tecnicas(*ids),
        )


# --------------------------------------------------------------------

def _demo():
    det = DetectorAccesosRemotos(inventario=["mstsc.exe"])

    if det.avisos:
        print("AVISOS DE CARGA")
        for a in det.avisos:
            print(f"  - {a}")
        print()

    print(f"perfil: {det.equipos} equipos | "
          f"umbral fuerza bruta: {det.umbral_fb} | spraying: {det.umbral_sp}")
    print(f"modo de alerta: {det.modo_alerta}\n")

    casos = [
        ("Fuerza bruta contra un servidor",
         dict(fallos=180, destino="SRV-CONTA", origen="192.168.1.80",
              cuenta="administrador")),
        ("Password spraying desde un equipo",
         dict(cuentas_distintas=40, origen="192.168.1.80")),
        ("AnyDesk fuera del inventario",
         dict(procesos=[r"C:\Program Files\AnyDesk\AnyDesk.exe"],
              destino="PC-RECEPCION")),
        ("mstsc.exe, que si esta autorizado",
         dict(procesos=["mstsc.exe"], destino="PC-GERENCIA")),
        ("RDP entrante desde internet",
         dict(puerto=3389, ip_remota="201.141.22.9", entrante=True,
              destino="SRV-ARCHIVOS")),
        ("Telnet entrante desde la red interna",
         dict(puerto=23, ip_remota="192.168.1.44", entrante=True,
              destino="SWITCH-1")),
        ("Trafico normal",
         dict(puerto=443, ip_remota="20.42.65.92", fallos=1)),
        # Mismo ataque de fuerza bruta, pero entregando tambien el vector
        # de caracteristicas, para que corra el modelo A2 ademas de la
        # regla. El vector es de ceros: no pretende representar un ataque
        # real, solo obliga al modelo a correr para comprobar que su
        # probabilidad llega al documento.
        ("Fuerza bruta con el modelo A2 activo",
         dict(fallos=180, destino="SRV-NOMINA", origen="192.168.1.90",
              cuenta="respaldo",
              caracteristicas={c: 0.0 for c in det.caracteristicas})),
    ]

    for titulo, kwargs in casos:
        r = det.evaluar(**kwargs)
        marca = "NOTIFICA" if r["notificar"] else "        "
        print(f"[{r['nivel_severidad']:>7}] {marca}  {titulo}")
        if r["mensaje"]:
            print(f"            {r['mensaje']}")
        if r["reglas_concluyentes"]:
            print(f"            concluyentes: {r['reglas_concluyentes']}")
        print()
    
    print("=" * 70)
    print("COMPROBACION DEL CONTRATO DE ALERTA")
    print("=" * 70)

    ahora = datetime.now().isoformat(timespec="seconds")
    documentos = []

    for titulo, kwargs in casos:
        veredicto = det.evaluar(**kwargs)
        contexto = dict(kwargs)
        contexto["fecha"] = ahora

        doc = det.a_contrato(veredicto, contexto)
        if doc is None:
            print(f"  [ -- ] sin alerta: {titulo}")
            continue

        documentos.append(doc)
        fallas = validar(doc)
        resultado = doc["resultado_analisis"]
        p = resultado["probabilidad"]

        print(f"  [{'OK ' if not fallas else 'MAL'}] "
              f"{doc['nivel_severidad']:>5}  {doc['descripcion']}")
        print(f"         origen: {resultado['origen_deteccion']}   "
              f"reglas: {resultado['reglas']}   "
              f"probabilidad: {p if p is not None else '--'}")
        for f in fallas:
            print(f"         [!] {f}")
        print()

    ids = {d["id"] for d in documentos}
    print(f"  documentos            : {len(documentos)}")
    print(f"  identificadores unicos: {len(ids)}")
        # Temporal: mientras no exista el repositorio ni la API, la interfaz
    # lee las alertas como archivos estaticos. public/ es la carpeta que
    # Vite sirve tal cual en la raiz del sitio.
    salida = os.path.join(_SISTEMA, "interfaz", "public", "datos")
    os.makedirs(salida, exist_ok=True)
    destino = os.path.join(salida, "alertas_accesos.json")
    with open(destino, "w", encoding="utf-8") as f:
        json.dump(documentos, f, indent=2, ensure_ascii=False)
    print(f"  guardadas en {destino}")

if __name__ == "__main__":
    _demo()