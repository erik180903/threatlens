"""
ThreatLens - Conversion de corpus .eml al esquema comun de entrenamiento.

Los corpus de Kaggle ya vienen como tablas con las columnas sender, subject,
body y label. phishing_pot viene como archivos .eml sueltos en formato MIME.
Este script los convierte al mismo esquema para que el resto del codigo no
tenga que distinguir el origen de cada correo.

    python parse_eml.py <directorio> <etiqueta 0|1> <csv de salida>
    python parse_eml.py phishing_pot-main/email 1 datos/PhishingPot.csv

COLUMNAS DE SALIDA
    sender, subject, body, label        -> esquema comun, entran al pipeline
    auth_spf, auth_dkim, auth_dmarc     -> NO entran al modelo
    n_adjuntos, adjuntos                -> NO entran al modelo
    anio                                -> NO entra al modelo

Las columnas de la segunda mitad se extraen igual porque sirven para dos
cosas: caracterizar el corpus en el reporte, y alimentar las reglas
deterministas de adjunto y la evidencia de autenticacion en la alerta.
Pero NO son caracteristicas del modelo: el ham publico de 2002-2008 no
trae encabezados de autenticacion -el estandar no existia-, asi que su
sola presencia seria un atajo hacia la etiqueta.
"""

import csv
import email
import email.policy
import re
import sys
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from pathlib import Path

# El encabezado Authentication-Results trae texto del estilo
#   spf=pass smtp.mailfrom=ejemplo.com; dkim=fail; dmarc=none
RE_AUTH = {
    "spf": re.compile(r"\bspf=(\w+)", re.I),
    "dkim": re.compile(r"\bdkim=(\w+)", re.I),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.I),
}


def _texto(valor) -> str:
    """Decodifica encabezados MIME a texto legible.

    Los asuntos vienen codificados como =?utf-8?B?U3UgY3VlbnRh?= y si no se
    decodifican, caracteristicas como la entropia o la proporcion de
    mayusculas medirian la codificacion en vez del texto real.
    """
    if not valor:
        return ""
    try:
        return str(make_header(decode_header(str(valor)))).replace("\n", " ").strip()
    except Exception:
        return str(valor).replace("\n", " ").strip()


def _cuerpo(msg) -> str:
    """Concatena las partes de texto del mensaje.

    El cuerpo NO es una caracteristica del modelo. Se extrae unicamente
    para sacar de el las URLs, que es lo que EmailUrlInfo entrega en
    produccion. Se omiten las partes marcadas como adjunto.
    """
    partes = []
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_maintype() != "text":
                continue
            if p.get_content_disposition() == "attachment":
                continue
            try:
                partes.append(p.get_payload(decode=True).decode(
                    p.get_content_charset() or "utf-8", errors="replace"))
            except Exception:
                continue
    else:
        try:
            partes.append(msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8", errors="replace"))
        except Exception:
            partes.append(str(msg.get_payload()))
    # Tope de tamano: algunos correos traen imagenes en base64 dentro del
    # HTML y pueden ocupar varios megabytes.
    return " ".join(partes)[:200_000]


def _adjuntos(msg):
    """Nombres de los adjuntos reales.

    Se excluyen las partes 'inline', que son las imagenes incrustadas en el
    HTML del correo. Esa distincion importa: en el corpus de Nazario, 299
    de 304 adjuntos son imagenes inline y solo 8 son archivos de riesgo.
    """
    nombres = []
    if not msg.is_multipart():
        return nombres
    for p in msg.walk():
        disp = p.get_content_disposition()
        nombre = p.get_filename()
        if disp == "attachment" or (nombre and disp != "inline"):
            nombres.append(_texto(nombre) or "(sin_nombre)")
    return nombres


def procesar(directorio: Path, etiqueta: int, salida: Path):
    archivos = sorted(directorio.rglob("*.eml"))
    if not archivos:
        raise SystemExit(f"No se encontraron archivos .eml en {directorio}")
    print(f"Procesando {len(archivos):,} archivos de {directorio}...")

    salida.parent.mkdir(parents=True, exist_ok=True)
    escritos = fallidos = 0

    with salida.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sender", "subject", "body", "label",
                    "auth_spf", "auth_dkim", "auth_dmarc",
                    "n_adjuntos", "adjuntos", "anio"])

        for i, ruta in enumerate(archivos, 1):
            try:
                with ruta.open("r", encoding="utf-8", errors="replace") as f:
                    msg = email.message_from_file(f, policy=email.policy.compat32)

                cabecera = " ".join(msg.get_all("Authentication-Results") or [])
                auth = {k: (m.group(1).lower() if (m := r.search(cabecera)) else "")
                        for k, r in RE_AUTH.items()}

                anio = ""
                try:
                    anio = parsedate_to_datetime(msg.get("Date")).year
                except Exception:
                    pass

                adj = _adjuntos(msg)
                w.writerow([
                    _texto(msg.get("From")),
                    _texto(msg.get("Subject")),
                    _cuerpo(msg),
                    etiqueta,
                    auth["spf"], auth["dkim"], auth["dmarc"],
                    len(adj), "|".join(adj)[:500], anio,
                ])
                escritos += 1
            except Exception:
                # Un correo mal formado no debe detener la conversion de
                # los otros 8,600.
                fallidos += 1

            if i % 2000 == 0:
                print(f"  {i:,}/{len(archivos):,}")

    print(f"\n{escritos:,} correos escritos en {salida}"
          + (f"  ({fallidos} no se pudieron leer)" if fallidos else ""))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        raise SystemExit(1)
    procesar(Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3]))