"""
ThreatLens - Extractor de caracteristicas lexicas de URL.

ESTE MODULO ES EL CONTRATO entre entrenamiento e inferencia. El script de
entrenamiento y el modulo de analisis del sistema importan este mismo
archivo. Si se modifica una funcion, hay que reentrenar: el vector dejaria
de vivir en el mismo espacio y las probabilidades no significarian nada.

REGLA: todas las caracteristicas se calculan EXCLUSIVAMENTE a partir de la
cadena de la URL. Nada de descargar la pagina, consultar WHOIS o resolver
DNS. Esa restriccion viene de produccion: lo unico que entrega
EmailUrlInfo.Url es el texto del enlace.

Por eso quedan fuera caracteristicas habituales en la literatura -presencia
de iframes, antiguedad del dominio, PageRank, indexacion en buscadores-
que requieren consultar servicios externos.
"""

import math
import re
from collections import Counter
from urllib.parse import urlsplit

# TLDs con tasa historicamente alta de abuso. Lista corta y declarada:
# es una heuristica documentada, no una lista exhaustiva.
TLD_SOSPECHOSOS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "click", "link",
    "work", "fit", "loan", "men", "date", "download", "stream", "racing",
    "review", "country", "science", "party", "gdn", "bid", "win", "zip", "mov",
}

PUERTOS_ESTANDAR = {80, 443}

RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RE_TOKENS = re.compile(r"[A-Za-z0-9]+")

# ORDEN CANONICO. El vector que consume el modelo se arma siempre en este
# orden; por eso se guarda en el contrato JSON junto al modelo entrenado.
NOMBRES_CARACTERISTICAS = [
    # estructura
    "url_longitud", "dominio_longitud", "ruta_longitud", "query_longitud",
    "num_subdominios", "tld_longitud",
    # banderas estructurales
    "host_es_ip", "usa_https", "tiene_puerto", "puerto_no_estandar",
    "tld_sospechoso", "tiene_punycode", "token_https_en_dominio",
    "doble_barra_en_ruta", "tiene_query",
    # composicion de caracteres
    "num_digitos", "ratio_digitos", "num_letras", "ratio_letras",
    "num_mayusculas", "ratio_mayusculas",
    "num_guiones", "num_puntos", "num_barras", "num_arroba",
    "num_interrogacion", "num_igual", "num_ampersand", "num_porcentaje",
    "num_guion_bajo", "num_especiales", "ratio_especiales",
    # desorden y segmentacion
    "entropia_url", "entropia_dominio", "ratio_digitos_dominio",
    "num_segmentos_ruta", "num_tokens", "token_mas_largo",
]


def _entropia(s: str) -> float:
    """Entropia de Shannon en bits por caracter.

    Mide que tan desordenada es una cadena. Un dominio legitimo como
    'banorte' tiene entropia baja; uno generado al azar como 'x7k2p9qz'
    la tiene alta.
    """
    if not s:
        return 0.0
    conteo = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in conteo.values())


def _normalizar(url: str) -> str:
    """Anade esquema si falta.

    EmailUrlInfo a veces entrega 'www.ejemplo.com/x' sin protocolo, y sin
    el, urlsplit interpreta todo como ruta y el host sale vacio.
    """
    u = (url or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    return u


def extraer_caracteristicas(url: str) -> dict:
    """Devuelve {nombre: valor} con las 38 caracteristicas de una URL."""
    cruda = (url or "").strip()
    u = _normalizar(cruda)

    try:
        partes = urlsplit(u)
    except ValueError:
        partes = urlsplit("http://")

    host = (partes.hostname or "").lower()
    ruta = partes.path or ""
    query = partes.query or ""

    try:
        puerto = partes.port
    except ValueError:
        # Puertos invalidos como ':99999' lanzan excepcion al leerlos.
        puerto = None

    host_es_ip = bool(RE_IPV4.match(host))
    etiquetas = [e for e in host.split(".") if e]
    tld = etiquetas[-1] if len(etiquetas) > 1 and not host_es_ip else ""
    # host = subdominios + dominio + tld, asi que subdominios = len - 2
    num_subdominios = max(0, len(etiquetas) - 2) if not host_es_ip else 0
    dominio_sin_tld = ".".join(etiquetas[:-1]) if tld else host

    n = len(cruda) or 1
    digitos = sum(c.isdigit() for c in cruda)
    letras = sum(c.isalpha() for c in cruda)
    mayusculas = sum(c.isupper() for c in cruda)
    especiales = sum((not c.isalnum()) for c in cruda)
    dig_dom = sum(c.isdigit() for c in host)

    tokens = RE_TOKENS.findall(cruda)

    return {
        # --- estructura ---
        "url_longitud": len(cruda),
        "dominio_longitud": len(host),
        "ruta_longitud": len(ruta),
        "query_longitud": len(query),
        "num_subdominios": num_subdominios,
        "tld_longitud": len(tld),

        # --- banderas estructurales ---
        # Un enlace a una IP en vez de un nombre es atipico en correo
        # legitimo y comun en infraestructura de phishing desechable.
        "host_es_ip": int(host_es_ip),
        "usa_https": int(partes.scheme == "https"),
        "tiene_puerto": int(puerto is not None),
        "puerto_no_estandar": int(puerto is not None and puerto not in PUERTOS_ESTANDAR),
        "tld_sospechoso": int(tld in TLD_SOSPECHOSOS),
        # xn-- es la codificacion de caracteres internacionales, usada para
        # dominios homografos que se ven identicos a los legitimos.
        "tiene_punycode": int("xn--" in host),
        # 'https' dentro del nombre del dominio, no como protocolo:
        # https-banorte-seguro.tk
        "token_https_en_dominio": int("https" in host),
        "doble_barra_en_ruta": int("//" in ruta),
        "tiene_query": int(bool(query)),

        # --- composicion de caracteres ---
        "num_digitos": digitos,
        "ratio_digitos": digitos / n,
        "num_letras": letras,
        "ratio_letras": letras / n,
        "num_mayusculas": mayusculas,
        "ratio_mayusculas": mayusculas / n,
        "num_guiones": cruda.count("-"),
        "num_puntos": cruda.count("."),
        "num_barras": cruda.count("/"),
        # La arroba en una URL hace que el navegador ignore todo lo previo:
        # http://banco.com@sitio-falso.tk lleva a sitio-falso.tk
        "num_arroba": cruda.count("@"),
        "num_interrogacion": cruda.count("?"),
        "num_igual": cruda.count("="),
        "num_ampersand": cruda.count("&"),
        "num_porcentaje": cruda.count("%"),
        "num_guion_bajo": cruda.count("_"),
        "num_especiales": especiales,
        "ratio_especiales": especiales / n,

        # --- desorden y segmentacion ---
        "entropia_url": _entropia(cruda),
        "entropia_dominio": _entropia(dominio_sin_tld),
        "ratio_digitos_dominio": dig_dom / (len(host) or 1),
        "num_segmentos_ruta": len([s for s in ruta.split("/") if s]),
        "num_tokens": len(tokens),
        "token_mas_largo": max((len(t) for t in tokens), default=0),
    }


def vector(url: str) -> list:
    """Vector en el orden canonico. Es lo que consume el modelo."""
    c = extraer_caracteristicas(url)
    return [c[k] for k in NOMBRES_CARACTERISTICAS]