"""
ThreatLens - Extractor de caracteristicas de correo (phishing).

CONTRATO entre entrenamiento e inferencia. Se calcula a partir de tres
cosas que Advanced Hunting SI entrega:

    remitente  <- EmailEvents.SenderFromAddress / SenderDisplayName
    asunto     <- EmailEvents.Subject
    urls       <- EmailUrlInfo.Url (lista, unida por NetworkMessageId)

NO se usa el cuerpo del mensaje: Microsoft Defender for Office 365 no lo
expone en advanced hunting. En entrenamiento el cuerpo se usa UNICAMENTE
como fuente para extraer las URLs (urls_desde_cuerpo), no como
caracteristica.

CUATRO GRUPOS, declarados en GRUPOS al final del archivo. El entrenamiento
quita cada grupo y mide el efecto, para decidir con evidencia cual conservar
en lugar de suponerlo. La hipotesis a comprobar es que las caracteristicas
de MAGNITUD de URL dependen de la epoca del corpus -las URLs legitimas de
hoy son largas y enredadas- mientras que las RELACIONALES no, porque miden
la contradiccion entre lo que el correo dice ser y lo que es.
"""

import math
import re
from collections import Counter
from email.utils import parseaddr

from features_phishing import extraer_caracteristicas as url_feats

# --- Listas declaradas. Heuristicas documentadas, no exhaustivas. ---

FREEMAIL = {
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.com.mx",
    "live.com", "aol.com", "protonmail.com", "icloud.com", "mail.ru",
    "yandex.com", "gmx.com", "zoho.com", "hotmail.es", "live.com.mx",
}

# Marcas suplantadas con frecuencia, globales y mexicanas.
MARCAS = {
    "microsoft", "google", "apple", "amazon", "paypal", "netflix", "facebook",
    "linkedin", "dropbox", "whatsapp", "spotify", "outlook", "office365",
    "bbva", "banorte", "santander", "hsbc", "citibanamex", "banamex",
    "scotiabank", "mercadolibre", "telmex", "cfe", "imss", "sat", "infonavit",
}

URGENCIA = {
    "urgent", "urgente", "immediately", "inmediato", "verify", "verificar",
    "verification", "suspend", "suspendida", "suspended", "expire", "expira",
    "caducar", "confirm", "confirmar", "alert", "alerta", "security",
    "seguridad", "password", "contrasena", "contrasena", "update",
    "actualizar", "winner", "ganador", "congratulations", "felicidades",
    "premio", "prize", "claim", "reclamar", "action required", "bloqueada",
    "unusual", "inusual", "limited", "restringida",
}

TLD_SOSPECHOSOS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "click", "link",
    "work", "fit", "loan", "men", "date", "download", "stream", "bid", "win",
}

RE_URL = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'\)\]\},]{4,}""")
RE_PALABRA = re.compile(r"\w+", re.UNICODE)

# ORDEN CANONICO. Se guarda en el contrato junto al modelo entrenado.
NOMBRES_CARACTERISTICAS = [
    # --- remitente (19) ---
    "rem_dominio_longitud", "rem_dominio_entropia", "rem_local_longitud",
    "rem_local_ratio_digitos", "rem_num_subdominios", "rem_tld_sospechoso",
    "rem_es_freemail", "rem_dominio_tiene_digitos", "rem_dominio_tiene_guion",
    "rem_sin_remitente", "disp_presente", "disp_longitud",
    "disp_contiene_correo", "disp_menciona_marca", "disp_marca_no_coincide",
    "rem_distancia_marca", "rem_es_lookalike", "rem_dominio_en_display",
    "disp_marca_sin_respaldo_url",
    # --- asunto (10) ---
    "asu_longitud", "asu_num_palabras", "asu_ratio_mayusculas",
    "asu_num_exclamacion", "asu_num_interrogacion", "asu_tiene_no_ascii",
    "asu_num_digitos", "asu_tiene_urgencia", "asu_entropia", "asu_vacio",
    # --- url_magnitud (10) ---
    "url_num", "url_num_dominios", "url_max_longitud", "url_prom_longitud",
    "url_max_entropia", "url_prom_entropia", "url_max_subdominios",
    "url_max_ratio_digitos", "url_max_especiales", "url_max_longitud_dominio",
    # --- url_relacional (8) ---
    "url_algun_host_ip", "url_algun_tld_sospechoso", "url_algun_punycode",
    "url_algun_puerto_no_estandar", "url_alguna_https", "url_todas_https",
    "url_dominio_coincide_remitente", "url_marca_en_subdominio",
]

# Grupos para la ablacion. El entrenamiento entrena un modelo sin cada uno
# y compara el resultado sobre phishing moderno.
GRUPOS = {
    "remitente": [c for c in NOMBRES_CARACTERISTICAS
                  if c.startswith(("rem_", "disp_"))],
    "asunto": [c for c in NOMBRES_CARACTERISTICAS if c.startswith("asu_")],
    "url_magnitud": ["url_num", "url_num_dominios", "url_max_longitud",
                     "url_prom_longitud", "url_max_entropia",
                     "url_prom_entropia", "url_max_subdominios",
                     "url_max_ratio_digitos", "url_max_especiales",
                     "url_max_longitud_dominio"],
    "url_relacional": ["url_algun_host_ip", "url_algun_tld_sospechoso",
                       "url_algun_punycode", "url_algun_puerto_no_estandar",
                       "url_alguna_https", "url_todas_https",
                       "url_dominio_coincide_remitente",
                       "url_marca_en_subdominio"],
}


def _entropia(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _levenshtein(a: str, b: str) -> int:
    """Numero minimo de ediciones para convertir a en b.

    'rnicrosoft' -> 'microsoft' son 2 ediciones. Es como se detecta la
    suplantacion por dominio parecido, que es la tecnica dominante hoy.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def urls_desde_cuerpo(cuerpo: str) -> list:
    """Extrae URLs del texto.

    SOLO se usa en entrenamiento, para simular lo que EmailUrlInfo entrega
    en produccion. El texto del cuerpo nunca es una caracteristica.
    """
    if not cuerpo:
        return []
    vistas, salida = set(), []
    for m in RE_URL.findall(str(cuerpo)):
        u = m.rstrip(".,;:!?")
        if u.lower() not in vistas:
            vistas.add(u.lower())
            salida.append(u)
    # Tope: correos con cientos de enlaces son atipicos y solo anaden ruido.
    return salida[:50]


def _partes_remitente(remitente: str):
    """Separa el campo From en (nombre visible, parte local, dominio).

    'Soporte Microsoft <no-reply@access-accsec.com>' devuelve
    ('Soporte Microsoft', 'no-reply', 'access-accsec.com')
    """
    disp, correo = parseaddr(str(remitente or "").strip())
    if "@" in correo:
        local, _, dominio = correo.rpartition("@")
    else:
        local, dominio = "", ""
    return disp.strip(), local.lower(), dominio.lower().strip("<>[] ")


def extraer_caracteristicas(remitente: str, asunto: str, urls: list) -> dict:
    disp, local, dominio = _partes_remitente(remitente)
    asunto = str(asunto or "")
    urls = [u for u in (urls or []) if u]

    # ---------- remitente ----------
    etiquetas = [e for e in dominio.split(".") if e]
    tld = etiquetas[-1] if len(etiquetas) > 1 else ""
    dom_sin_tld = ".".join(etiquetas[:-1]) if tld else dominio
    raiz = etiquetas[-2] if len(etiquetas) >= 2 else dominio

    # Distancia a la marca conocida mas parecida. 0 = es la marca;
    # 1 o 2 = imitacion; alto = no tiene relacion.
    dist = min((_levenshtein(raiz, m) for m in MARCAS), default=99) if raiz else 99
    es_lookalike = int(0 < dist <= 2)

    disp_low = disp.lower()
    marca_en_disp = next((m for m in MARCAS if m in disp_low), None)

    # ---------- urls ----------
    uf = [url_feats(u) for u in urls]
    dominios_url = {u.split("//")[-1].split("/")[0].lower() for u in urls}

    def mx(k):
        return max((f[k] for f in uf), default=0.0)

    def pr(k):
        return (sum(f[k] for f in uf) / len(uf)) if uf else 0.0

    # ¿Los enlaces apuntan al mismo dominio del remitente? Un correo que
    # dice venir de BBVA cuyos enlaces van a otro lado es la señal mas
    # directa de suplantacion.
    coincide = 0
    if dominio and dominios_url:
        raiz_rem = ".".join(etiquetas[-2:]) if len(etiquetas) >= 2 else dominio
        coincide = int(any(raiz_rem in d for d in dominios_url))

    n_asu = len(asunto) or 1

    return {
        # ===================== REMITENTE =====================
        "rem_dominio_longitud": len(dominio),
        "rem_dominio_entropia": _entropia(dom_sin_tld),
        "rem_local_longitud": len(local),
        "rem_local_ratio_digitos": sum(c.isdigit() for c in local) / (len(local) or 1),
        "rem_num_subdominios": max(0, len(etiquetas) - 2),
        "rem_tld_sospechoso": int(tld in TLD_SOSPECHOSOS),
        "rem_es_freemail": int(dominio in FREEMAIL),
        "rem_dominio_tiene_digitos": int(any(c.isdigit() for c in dominio)),
        "rem_dominio_tiene_guion": int("-" in dominio),
        "rem_sin_remitente": int(not dominio),
        "disp_presente": int(bool(disp)),
        "disp_longitud": len(disp),
        # Una arroba dentro del nombre visible: 'soporte@banorte.com <x@mal.tk>'
        "disp_contiene_correo": int("@" in disp),
        "disp_menciona_marca": int(marca_en_disp is not None),

        # --- RELACIONALES del remitente: miden contradiccion ---
        # El nombre dice 'Microsoft' y el dominio no es de Microsoft.
        "disp_marca_no_coincide": int(
            marca_en_disp is not None and marca_en_disp not in dominio),
        "rem_distancia_marca": float(min(dist, 20)),
        "rem_es_lookalike": es_lookalike,
        # Patron LEGITIMO: el nombre visible refleja el dominio real.
        "rem_dominio_en_display": int(bool(raiz) and raiz in disp_low),
        # El nombre dice una marca y NINGUNA url la respalda.
        "disp_marca_sin_respaldo_url": int(
            marca_en_disp is not None
            and not any(marca_en_disp in d for d in dominios_url)),

        # ======================= ASUNTO =======================
        "asu_longitud": len(asunto),
        "asu_num_palabras": len(RE_PALABRA.findall(asunto)),
        "asu_ratio_mayusculas": sum(c.isupper() for c in asunto) / n_asu,
        "asu_num_exclamacion": asunto.count("!"),
        "asu_num_interrogacion": asunto.count("?"),
        "asu_tiene_no_ascii": int(any(ord(c) > 127 for c in asunto)),
        "asu_num_digitos": sum(c.isdigit() for c in asunto),
        "asu_tiene_urgencia": int(any(k in asunto.lower() for k in URGENCIA)),
        "asu_entropia": _entropia(asunto),
        "asu_vacio": int(not asunto.strip()),

        # ==================== URL MAGNITUD ====================
        # Grupo bajo sospecha de caducar: mide "que tan larga y enredada
        # es la URL", y eso cambio mucho en veinte anos.
        "url_num": len(urls),
        "url_num_dominios": len(dominios_url),
        "url_max_longitud": mx("url_longitud"),
        "url_prom_longitud": pr("url_longitud"),
        "url_max_entropia": mx("entropia_url"),
        "url_prom_entropia": pr("entropia_url"),
        "url_max_subdominios": mx("num_subdominios"),
        "url_max_ratio_digitos": mx("ratio_digitos"),
        "url_max_especiales": mx("num_especiales"),
        "url_max_longitud_dominio": mx("dominio_longitud"),

        # =================== URL RELACIONAL ===================
        "url_algun_host_ip": int(any(f["host_es_ip"] for f in uf)),
        "url_algun_tld_sospechoso": int(any(f["tld_sospechoso"] for f in uf)),
        "url_algun_punycode": int(any(f["tiene_punycode"] for f in uf)),
        "url_algun_puerto_no_estandar": int(any(f["puerto_no_estandar"] for f in uf)),
        "url_alguna_https": int(any(f["usa_https"] for f in uf)),
        "url_todas_https": int(bool(uf) and all(f["usa_https"] for f in uf)),
        "url_dominio_coincide_remitente": coincide,
        # paypal.com.evil.tk : la marca vive en el subdominio, no en el
        # dominio registrable. Tecnica moderna y ajena a la epoca.
        "url_marca_en_subdominio": int(any(
            any(m in ".".join(d.split(".")[:-2]) for m in MARCAS)
            and not any(m in ".".join(d.split(".")[-2:]) for m in MARCAS)
            for d in dominios_url if d.count(".") >= 2)),
    }


def vector(remitente: str, asunto: str, urls: list) -> list:
    c = extraer_caracteristicas(remitente, asunto, urls)
    return [c[k] for k in NOMBRES_CARACTERISTICAS]