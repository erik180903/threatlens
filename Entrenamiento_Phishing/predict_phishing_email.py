"""
ThreatLens - Deteccion de phishing en correo.

Es el modulo que importa el sistema. Recibe los campos que entrega Advanced
Hunting y devuelve el veredicto con su nivel de severidad, listo para
construir la alerta de RF11.

ENTRADAS
    remitente  <- EmailEvents.SenderFromAddress / SenderDisplayName
    asunto     <- EmailEvents.Subject
    urls       <- EmailUrlInfo.Url (join por NetworkMessageId)
    adjuntos   <- EmailAttachmentInfo.FileName       (opcional)
    auth       <- EmailEvents.AuthenticationDetails  (opcional)

TRES NIVELES DE SEVERIDAD
Los umbrales se leen de modelos/umbrales_severidad.json, generado por
umbrales_severidad.py con la prevalencia del entorno. Solo el nivel ALTO
genera notificacion; MEDIO y BAJO quedan visibles sin interrumpir.

Si ese archivo no existe se usa el umbral unico del contrato. Sirve para
pruebas, NO para operacion: ese umbral esta calibrado para la prevalencia
del corpus (~55%), no para un buzon real.

ADJUNTOS: REGLAS, NO CARACTERISTICAS DEL MODELO
Se verifico que el corpus de Nazario contiene 304 correos con adjunto, de
los cuales 299 son imagenes incrustadas en el HTML: solo 8 son archivos de
riesgo. Sin volumen suficiente no hay entrenamiento supervisado posible,
asi que los adjuntos se evaluan con reglas deterministas.

Las reglas se dividen en dos:
  CONCLUYENTES  ejecutable adjunto, doble extension. Generan alerta por si
                solas, aunque el modelo no haya sospechado, porque son
                indicadores casi inequivocos.
  ESCALADORAS   comprimidos, documentos con macros. Solo suben el nivel de
                algo que el modelo ya marco, para no generar ruido.

Las reglas NUNCA bajan la severidad.

    python predict_phishing_email.py
"""

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import load

from features_email import NOMBRES_CARACTERISTICAS, extraer_caracteristicas
import sys
from datetime import datetime

# El contrato de alerta vive en Sistema\, carpeta hermana de esta.
_SISTEMA = Path(__file__).resolve().parent.parent / "Sistema"
sys.path.insert(0, str(_SISTEMA))
from contrato_alerta import nueva_alerta, validar, tecnicas                # noqa: E402

DIR_MODELOS = Path("modelos")
ORDEN_SEVERIDAD = ["ninguna", "bajo", "medio", "alto"]

# Reglas de adjunto. Conocimiento de dominio, no aprendido de datos.
EXT_EJECUTABLE = {"exe", "scr", "hta", "js", "jse", "vbs", "vbe", "jar", "bat",
                  "cmd", "com", "pif", "msi", "ps1", "lnk", "wsf", "reg", "cpl"}
EXT_MACRO = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "xll"}
EXT_COMPRIMIDO = {"zip", "rar", "7z", "iso", "img", "cab", "gz", "tgz", "ace"}
EXT_INOCUA = {"gif", "png", "jpg", "jpeg", "bmp", "webp", "svg", "ico"}

# factura.pdf.exe : extension aparente seguida de la real
RE_DOBLE_EXT = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|zip)\."
    r"([A-Za-z0-9]{1,6})$", re.I)


def _extension(nombre: str) -> str:
    m = re.search(r"\.([A-Za-z0-9]{1,8})$", (nombre or "").strip())
    return m.group(1).lower() if m else ""


def evaluar_adjuntos(adjuntos) -> dict:
    """Aplica las reglas deterministas sobre los nombres de adjunto."""
    nombres = [n for n in (adjuntos or []) if n]
    hallazgos, escalar, concluyente = [], 0, False

    for n in nombres:
        ext = _extension(n)
        if RE_DOBLE_EXT.search(n):
            hallazgos.append(f"doble extension: {n}")
            escalar, concluyente = max(escalar, 3), True
        if ext in EXT_EJECUTABLE:
            hallazgos.append(f"adjunto ejecutable: {n}")
            escalar, concluyente = max(escalar, 3), True
        elif ext in EXT_MACRO:
            hallazgos.append(f"documento con macros: {n}")
            escalar = max(escalar, 1)
        elif ext in EXT_COMPRIMIDO:
            hallazgos.append(f"archivo comprimido: {n}")
            escalar = max(escalar, 1)

    return {"total": len(nombres), "nombres": nombres[:10],
            "inocuos": sum(1 for n in nombres if _extension(n) in EXT_INOCUA),
            "hallazgos": hallazgos, "escalamiento": escalar,
            "concluyente": concluyente}


def evaluar_autenticacion(auth) -> dict:
    """SPF/DKIM/DMARC como evidencia corroborante.

    No entran al modelo porque el ham publico de 2002-2008 no trae esos
    encabezados -el estandar no existia- y su sola presencia seria un
    atajo hacia la etiqueta. En produccion si estan disponibles.
    """
    if not auth:
        return {}
    fallidos = [k.upper() for k, v in auth.items()
                if str(v).lower() in ("fail", "softfail", "none", "temperror")]
    return {"resultados": auth, "mecanismos_no_superados": fallidos,
            # Los tres fallando a la vez es señal fuerte de suplantacion.
            "escalamiento": 1 if len(fallidos) >= 3 else 0,
            "nota": "Evidencia corroborante; no participa en la clasificacion."}


class DetectorPhishingCorreo:
    def __init__(self, dir_modelos: Path = DIR_MODELOS, modelo: str = None):
        ruta_contrato = dir_modelos / "contrato_phishing_email.json"
        if not ruta_contrato.exists():
            raise FileNotFoundError(
                f"No se encontro {ruta_contrato}. "
                "Ejecuta train_phishing_email.py primero.")
        self.contrato = json.loads(ruta_contrato.read_text(encoding="utf-8"))

        # Permite forzar un modelo distinto al que eligio el entrenamiento.
        # La seleccion final depende del escenario de operacion, que se
        # evalua con umbrales_severidad.py, no del corpus de evaluacion.
        self.modelo_id = modelo or self.contrato["modelo_seleccionado"]
        metricas = self.contrato["metricas"].get(self.modelo_id, {})
        self.orden = metricas.get("caracteristicas",
                                  self.contrato["orden_caracteristicas"])

        # Verificacion de contrato: si el extractor cambio desde el
        # entrenamiento, el vector ya no vive en el mismo espacio.
        # Fallar aqui es mejor que devolver probabilidades sin sentido.
        faltan = set(self.orden) - set(NOMBRES_CARACTERISTICAS)
        if faltan:
            raise RuntimeError(
                "features_email.py no coincide con el modelo entrenado. "
                f"Faltan: {sorted(faltan)}. Hay que reentrenar.")

        self.modelo = load(dir_modelos / f"phishing_email_{self.modelo_id}.joblib")

        # Umbrales por severidad, calibrados con la prevalencia del entorno.
        self.umbrales, self.prevalencia = None, None
        ruta_umbrales = dir_modelos / "umbrales_severidad.json"
        if ruta_umbrales.exists():
            u = json.loads(ruta_umbrales.read_text(encoding="utf-8"))
            niveles = u.get("modelos", {}).get(self.modelo_id)
            if niveles:
                self.umbrales = {k: v["umbral"] for k, v in niveles.items()
                                 if v and "umbral" in v}
                self.prevalencia = u.get("prevalencia")
        if not self.umbrales:
            self.umbrales = {"alto": float(self.contrato["umbral"])}

    def _probabilidad(self, X) -> float:
        if hasattr(self.modelo, "predict_proba"):
            return float(self.modelo.predict_proba(X)[0, 1])
        return 1.0 / (1.0 + np.exp(-float(self.modelo.decision_function(X)[0])))

    def _severidad_modelo(self, p: float) -> str:
        for nivel in ("alto", "medio", "bajo"):
            u = self.umbrales.get(nivel)
            if u is not None and p >= u:
                return nivel
        return "ninguna"

    @staticmethod
    def _escalar(severidad: str, pasos: int) -> str:
        i = ORDEN_SEVERIDAD.index(severidad)
        return ORDEN_SEVERIDAD[min(i + pasos, len(ORDEN_SEVERIDAD) - 1)]

    def analizar(self, remitente: str, asunto: str, urls=None,
                 adjuntos=None, auth: dict = None) -> dict:
        caracteristicas = extraer_caracteristicas(remitente, asunto, urls or [])
        X = pd.DataFrame([[caracteristicas[k] for k in self.orden]],
                         columns=self.orden, dtype=np.float64)
        X = X.replace([np.inf, -np.inf], 0.0).fillna(0.0)
        p = self._probabilidad(X)

        sev_modelo = self._severidad_modelo(p)
        ev_adj = evaluar_adjuntos(adjuntos)
        ev_auth = evaluar_autenticacion(auth)

        sev, motivos = sev_modelo, []
        if ev_adj["concluyente"]:
            # Actua aunque el modelo no haya sospechado.
            base = max(sev, "bajo", key=ORDEN_SEVERIDAD.index)
            sev = self._escalar(base, ev_adj["escalamiento"])
            motivos += ev_adj["hallazgos"]
        elif sev_modelo != "ninguna" and ev_adj["escalamiento"]:
            sev = self._escalar(sev, ev_adj["escalamiento"])
            motivos += ev_adj["hallazgos"]
        if sev != "ninguna" and ev_auth.get("escalamiento"):
            sev = self._escalar(sev, ev_auth["escalamiento"])
            motivos.append("SPF, DKIM y DMARC no superados")

        resultado = {
            "tipo_amenaza": "phishing",
            "probabilidad": round(p, 4),
            "modelo_id": self.modelo_id,
            "umbrales_aplicados": self.umbrales,
            "prevalencia_calibracion": self.prevalencia,
            "es_malicioso": sev != "ninguna",
            "nivel_severidad": sev,
            "severidad_modelo": sev_modelo,
            "notificar": sev == "alto",
            "motivos_escalamiento": motivos,
            "vector_caracteristicas": caracteristicas,
        }
        if ev_adj["total"]:
            resultado["evidencia_adjuntos"] = ev_adj
        if ev_auth:
            resultado["evidencia_autenticacion"] = ev_auth
        return resultado
    
    def a_contrato(self, resultado, contexto):
        """
        Traduce la salida de analizar() al documento del contrato.

        resultado  lo que devuelve analizar()
        contexto   dict con el correo y su destino: equipo, fecha,
                   remitente, asunto, destinatario, urls, adjuntos,
                   mensaje_id

        Devuelve None si no hubo alerta.
        """
        if not resultado.get("es_malicioso"):
            return None

        # Que componente levanto la alerta. El modelo siempre corre, pero
        # las reglas de adjuntos pueden disparar por si solas: un
        # ejecutable disfrazado es concluyente aunque el modelo no haya
        # sospechado del texto del correo.
        reglas = []
        adjuntos = resultado.get("evidencia_adjuntos") or {}
        if adjuntos.get("concluyente") or adjuntos.get("escalamiento"):
            reglas.append("adjuntos")
        autenticacion = resultado.get("evidencia_autenticacion") or {}
        if autenticacion.get("escalamiento"):
            reglas.append("autenticacion")

        hubo_modelo = resultado.get("severidad_modelo", "ninguna") != "ninguna"
        if hubo_modelo and reglas:
            origen_deteccion = "modelo+regla"
        elif hubo_modelo:
            origen_deteccion = "modelo"
        else:
            origen_deteccion = "regla"

        remitente = contexto.get("remitente", "")
        # Solo la direccion: el titulo se lee en una fila del historial y
        # el nombre para mostrar es justo lo que un suplantador controla.
        m = re.search(r"<([^>]+)>", remitente)
        direccion = m.group(1) if m else remitente
        hallazgos = adjuntos.get("hallazgos") or []
        if adjuntos.get("concluyente") and hallazgos:
            descripcion = f"Phishing detectado — {hallazgos[0]}"
        else:
            descripcion = (f"Phishing detectado — "
                           f"{direccion or 'remitente desconocido'}")
        motivos = list(resultado.get("motivos_escalamiento") or [])
        if not motivos:
            motivos.append("el modelo clasifico el correo como phishing a "
                           "partir del remitente, el asunto y sus enlaces")

        evento = {
            "remitente": remitente,
            "asunto": contexto.get("asunto", ""),
            "destinatario": contexto.get("destinatario", ""),
            "urls": list(contexto.get("urls") or [])[:10],
            "adjuntos": adjuntos.get("nombres", []),
            "hallazgos_adjuntos": hallazgos,
            "autenticacion": autenticacion.get("resultados", {}),
            "mecanismos_no_superados":
                autenticacion.get("mecanismos_no_superados", []),
            "severidad_modelo": resultado.get("severidad_modelo", ""),
            # Marca de honestidad: los umbrales de severidad dependen de
            # la prevalencia que se supuso al calibrarlos. Si el entorno
            # real tiene otra, la precision cambia, y la interfaz debe
            # poder decirlo.
            "prevalencia_calibracion": resultado.get("prevalencia_calibracion"),
            "tabla_origen": "EmailEvents",
        }

        huella = contexto.get("mensaje_id") or f"{remitente}|{contexto.get('asunto', '')}"

        ids = ["T1566"]
        if "adjuntos" in reglas:
            ids.append("T1566.001")
        elif contexto.get("urls"):
            ids.append("T1566.002")

        return nueva_alerta(
            tipo_amenaza="phishing",
            nivel_severidad=resultado["nivel_severidad"],
            descripcion=descripcion,
            equipo=contexto.get("equipo") or contexto.get("destinatario", ""),
            fecha=contexto.get("fecha", ""),
            probabilidad=resultado["probabilidad"],
            modelo=resultado.get("modelo_id", "desconocido"),
            evento=evento,
                        # Solo las caracteristicas que el modelo consume. El extractor
            # produce 47; la ablacion dejo fuera 10, y guardar esas
            # sugeriria que participaron en la clasificacion.
            vector={k: (resultado.get("vector_caracteristicas") or {}).get(k)
                    for k in self.orden},
            motivos=motivos,
            huella=huella,
            origen_deteccion=origen_deteccion,
            reglas=sorted(reglas),
            mitre=tecnicas(*ids),
        )


def _demo():
    # El SVM resulto el mejor en el escenario de operacion, aunque el
    # entrenamiento seleccionara otro sobre el corpus de evaluacion.
    d = DetectorPhishingCorreo(modelo="svm")
    print(f"modelo: {d.modelo_id} | caracteristicas: {len(d.orden)}")
    print(f"umbrales: {d.umbrales}")
    print(f"prevalencia de calibracion: {d.prevalencia}")
    if d.prevalencia is None:
        print("\n[!] Sin umbrales_severidad.json: se usa el umbral del")
        print("    contrato. Ejecuta umbrales_severidad.py para operacion.")

    casos = [
        ("Microsoft account team <no-reply@access-accsec.com>",
         "Microsoft account unusual signin activity",
         ["http://login-microsoftonline.access-accsec.com/verify?id=88213"],
         None, {"spf": "fail", "dkim": "none", "dmarc": "fail"}),
        ("Notificaciones BBVA <avisos@bbva.mx>",
         "Estado de cuenta de noviembre",
         ["https://www.bbva.mx/personas/estado-cuenta"],
         ["estado_cuenta.pdf"], {"spf": "pass", "dkim": "pass", "dmarc": "pass"}),
        ("Recursos Humanos <rh@empresa-interna.com>",
         "Actualizacion de nomina",
         [], ["Formato_2026.pdf.exe"], {"spf": "pass", "dkim": "pass"}),
    ]
    for rem, asu, urls, adj, auth in casos:
        r = d.analizar(rem, asu, urls, adj, auth)
        r.pop("vector_caracteristicas")
        r.pop("umbrales_aplicados")
        print(f"\n{'-' * 66}\nDe: {rem}\nAsunto: {asu}")
        print(json.dumps(r, indent=2, ensure_ascii=False))

    print("\n" + "=" * 70)
    print("COMPROBACION DEL CONTRATO DE ALERTA")
    print("=" * 70)

    ahora = datetime.now().isoformat(timespec="seconds")
    equipos = ["PC-GERENCIA", "PC-CONTABILIDAD", "PC-RRHH"]
    documentos = []

    for i, (rem, asu, urls, adj, auth) in enumerate(casos):
        # analizar() se llama de nuevo porque el bucle anterior modifico
        # su resultado al quitarle campos para imprimirlo.
        resultado = d.analizar(rem, asu, urls, adj, auth)
        contexto = {
            "equipo": equipos[i % len(equipos)],
            "fecha": ahora,
            "remitente": rem,
            "asunto": asu,
            "destinatario": "usuario@empresa.com",
            "urls": urls,
            "adjuntos": adj,
        }

        doc = d.a_contrato(resultado, contexto)
        if doc is None:
            print(f"  [ -- ] sin alerta: {asu}")
            continue

        documentos.append(doc)
        fallas = validar(doc)
        r2 = doc["resultado_analisis"]

        print(f"  [{'OK ' if not fallas else 'MAL'}] "
              f"{doc['nivel_severidad']:>5}  {doc['descripcion']}")
        print(f"         origen: {r2['origen_deteccion']}   "
              f"reglas: {r2['reglas']}   "
              f"probabilidad: {r2['probabilidad']}")
        print(f"         vector: {len(r2['vector'])} caracteristicas")
        for f in fallas:
            print(f"         [!] {f}")
        print()

    ids = {d_["id"] for d_ in documentos}
    print(f"  documentos            : {len(documentos)}")
    print(f"  identificadores unicos: {len(ids)}")
    salida = _SISTEMA / "datos"
    salida.mkdir(parents=True, exist_ok=True)
    destino = salida / "alertas_phishing.json"
    destino.write_text(json.dumps(documentos, indent=2, ensure_ascii=False),
                       encoding="utf-8")
    print(f"  guardadas en {destino}")


if __name__ == "__main__":
    _demo()