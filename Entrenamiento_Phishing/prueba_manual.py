"""
ThreatLens - Prueba manual sobre correos reales.

Puntua correos reales y muestra como se reparten entre los niveles de
severidad. Sirve para dos cosas que las metricas agregadas no responden:

  1. ¿El modelo transfiere al espanol? El corpus es mayormente ingles,
     aleman y portugues. Tu entorno sera espanol con marcas mexicanas.
  2. ¿Que aspecto tienen los correos que se le escapan? Leer los falsos
     negativos dice mas que un F1.

TRES FUENTES, en orden de valor:

  A. PhishingPot filtrado por idioma  -> phishing real, automatico
  B. Tus propios correos              -> lo mas parecido a tu entorno
  C. Casos construidos                -> solo prueban que el codigo corre,
                                         NO miden desempeno

La fuente C no sirve para medir: si los correos los escribe quien diseno
las caracteristicas, el modelo los detecta porque fueron escritos para
eso. Es una prueba de humo, no una evaluacion.

    python prueba_manual.py              # PhishingPot en espanol
    python prueba_manual.py --mios       # tus correos desde mis_correos.csv
"""

import json
import sys
from pathlib import Path

import pandas as pd

from features_email import urls_desde_cuerpo
from predict_phishing_email import DetectorPhishingCorreo

DATOS = Path("datos")
MODELO = "svm"          # el que gano en el escenario de operacion
N_MUESTRA = 20

# Terminos frecuentes en phishing en espanol y portugues. Sirven para
# filtrar el corpus por idioma, no son caracteristicas del modelo.
MARCADORES_ES = ["microsoft", "paypal", "bbva", "banorte", "santander",
                 "bradesco", "amazon", "netflix", "apple", "banco"]


def cargar_phishing_pot(n=N_MUESTRA, solo_espanol=True):
    ruta = DATOS / "PhishingPot.csv"
    if not ruta.exists():
        raise SystemExit(f"No se encontro {ruta}")
    df = pd.read_csv(ruta, low_memory=False).fillna("")

    if solo_espanol:
        texto = (df["subject"].astype(str) + " " + df["body"].astype(str)).str.lower()
        mascara = texto.apply(lambda t: any(m in t for m in MARCADORES_ES))
        sub = df[mascara]
        print(f"  {len(sub):,} correos con marcadores en espanol/portugues "
              f"de {len(df):,} totales")
        if len(sub) < n:
            print("  [!] pocos resultados, se completa con el resto del corpus")
            sub = pd.concat([sub, df.drop(sub.index)])
    else:
        sub = df

    sub = sub.drop_duplicates(subset=["sender", "subject"])
    return sub.sample(n=min(n, len(sub)), random_state=7)


def cargar_mios():
    """Lee mis_correos.csv con columnas: sender, subject, body, adjuntos, etiqueta

    'etiqueta' es tu juicio: 1 = phishing, 0 = legitimo. Es lo que permite
    contar aciertos. 'adjuntos' es opcional, nombres separados por |.
    """
    ruta = Path("mis_correos.csv")
    if not ruta.exists():
        print(f"No existe {ruta}. Creala con estas columnas:")
        print("  sender,subject,body,adjuntos,etiqueta")
        print("\nPara exportar desde Outlook: abre el correo, Archivo >")
        print("Guardar como > Texto sin formato, y copia remitente, asunto")
        print("y cuerpo a la tabla. Veinte de cada clase es suficiente.")
        raise SystemExit(1)
    return pd.read_csv(ruta, low_memory=False).fillna("")


def main():
    mios = "--mios" in sys.argv

    print(f"Cargando detector (modelo {MODELO})...")
    d = DetectorPhishingCorreo(modelo=MODELO)
    print(f"  umbrales: {d.umbrales}")
    print(f"  prevalencia de calibracion: {d.prevalencia}\n")

    if mios:
        df = cargar_mios()
        etiquetas = df["etiqueta"].astype(int).tolist()
        print(f"Correos propios: {len(df)} "
              f"({sum(etiquetas)} phishing, {len(etiquetas) - sum(etiquetas)} legitimos)\n")
    else:
        print("Cargando PhishingPot...")
        df = cargar_phishing_pot()
        etiquetas = [1] * len(df)
        print()

    conteo = {"alto": 0, "medio": 0, "bajo": 0, "ninguna": 0}
    filas = []

    for i, (_, r) in enumerate(df.iterrows(), 1):
        adj = [a for a in str(r.get("adjuntos", "")).split("|") if a.strip()]
        res = d.analizar(str(r["sender"]), str(r["subject"]),
                         urls_desde_cuerpo(str(r["body"])), adj or None)
        sev = res["nivel_severidad"]
        conteo[sev] += 1
        filas.append((i, sev, res["probabilidad"], res["notificar"],
                      str(r["sender"])[:38], str(r["subject"])[:46]))

    print(f"{'#':>3s} {'severidad':>10s} {'prob':>7s} {'notif':>6s}  "
          f"{'remitente':38s} asunto")
    print("-" * 118)
    for i, sev, p, notif, rem, asu in filas:
        print(f"{i:>3d} {sev:>10s} {p:>7.4f} {'SI' if notif else '':>6s}  "
              f"{rem:38s} {asu}")

    total = len(filas)
    print(f"\n{'=' * 60}\nDISTRIBUCION ({total} correos)")
    for nivel in ("alto", "medio", "bajo", "ninguna"):
        n = conteo[nivel]
        print(f"  {nivel:10s} {n:>4d}  {n / max(total, 1):>6.1%}")

    detectados = total - conteo["ninguna"]
    print(f"\n  cubiertos por algun nivel: {detectados}/{total} "
          f"({detectados / max(total, 1):.1%})")
    print(f"  notificados (severidad alta): {conteo['alto']}/{total} "
          f"({conteo['alto'] / max(total, 1):.1%})")

    if mios:
        # Con etiquetas propias se puede contar aciertos por clase.
        tp = sum(1 for (i, sev, *_), y in zip(filas, etiquetas)
                 if y == 1 and sev != "ninguna")
        fp = sum(1 for (i, sev, *_), y in zip(filas, etiquetas)
                 if y == 0 and sev != "ninguna")
        n_pos = sum(etiquetas)
        n_neg = len(etiquetas) - n_pos
        print(f"\n  phishing detectado : {tp}/{n_pos}")
        print(f"  legitimos marcados : {fp}/{n_neg}  <- falsos positivos")

    print("\nLee los que quedaron en 'ninguna': son los que se escapan,")
    print("y dicen mas sobre los limites del modelo que cualquier metrica.")


if __name__ == "__main__":
    main()