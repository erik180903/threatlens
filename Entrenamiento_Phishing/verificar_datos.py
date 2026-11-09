"""
ThreatLens - Verificacion de los corpus antes de entrenar.

Detecta dos errores que NO producen excepciones ni numeros raros, sino
metricas que parecen correctas pero miden otra cosa:

  1. POLARIDAD INVERTIDA. Si en algun corpus label=1 fuera "legitimo" en
     vez de "phishing", el recall mediria exactamente lo contrario de lo
     que crees y el modelo seguiria entrenando sin quejarse.

  2. CLASE POSITIVA EQUIVOCADA. En CEAS_08 y SpamAssasin los correos con
     label=1 son SPAM COMERCIAL -seguros, dietas, contenido para adultos-,
     no phishing de credenciales. Entrenar con ellos convierte el problema
     en "spam contra correo normal", que es mas facil y no es el problema
     del sistema.

Por eso el script imprime ejemplos reales de cada clase: hay que LEERLOS.
Ninguna verificacion automatica sustituye mirar veinte correos.

    python verificar_datos.py
"""

from pathlib import Path

import pandas as pd

DATOS = Path("datos")

# archivo -> que papel juega y que etiquetas se van a usar de el
ESPERADOS = {
    "Nazario.csv":        ("phishing de entrenamiento", {1}),
    "SpamAssasin.csv":    ("correo legitimo",           {0}),
    "CEAS_08.csv":        ("correo legitimo",           {0}),
    "Nigerian_Fraud.csv": ("phishing externo A",        {1}),
    "PhishingPot.csv":    ("phishing externo B",        {1}),
}
REQUERIDAS = {"sender", "subject", "body", "label"}


def leer(ruta: Path) -> pd.DataFrame:
    """Lee el CSV tolerando corpus antiguos con codificacion no UTF-8."""
    try:
        return pd.read_csv(ruta, low_memory=False)
    except UnicodeDecodeError:
        print("   [!] UTF-8 fallo, se reintenta con latin-1")
        return pd.read_csv(ruta, low_memory=False, encoding="latin-1")


def main():
    if not DATOS.exists():
        raise SystemExit(f"No existe la carpeta ./{DATOS}/")

    print("Archivos en ./datos/:")
    for f in sorted(DATOS.glob("*.csv")):
        print(f"   {f.name}")
    print()

    problemas = 0
    for nombre, (papel, etiquetas_usadas) in ESPERADOS.items():
        ruta = DATOS / nombre
        print(f"--- {nombre}  ({papel}) ---")

        if not ruta.exists():
            print("   [X] NO ENCONTRADO\n")
            problemas += 1
            continue

        df = leer(ruta)
        cols = {c.lower().strip() for c in df.columns}
        print(f"   filas    : {len(df):,}")
        print(f"   columnas : {list(df.columns)}")

        faltan = REQUERIDAS - cols
        if faltan:
            print(f"   [X] FALTAN COLUMNAS: {sorted(faltan)}\n")
            problemas += 1
            continue

        c_lab = next(c for c in df.columns if c.lower().strip() == "label")
        c_send = next(c for c in df.columns if c.lower().strip() == "sender")
        c_subj = next(c for c in df.columns if c.lower().strip() == "subject")

        conteo = df[c_lab].value_counts().to_dict()
        print(f"   etiquetas: {conteo}")

        # Cuantas filas se van a usar realmente de este corpus.
        usadas = int(df[c_lab].isin(etiquetas_usadas).sum())
        descartadas = len(df) - usadas
        print(f"   se usaran: {usadas:,} filas con label en {etiquetas_usadas}"
              + (f"   ({descartadas:,} se descartan)" if descartadas else ""))

        # Lo importante: ejemplos para leer a ojo.
        for val in sorted(conteo):
            marca = "  <- SE USA" if val in etiquetas_usadas else "  <- se descarta"
            print(f"   ejemplos con label={val}{marca}")
            for _, r in df[df[c_lab] == val].head(2).iterrows():
                s = str(r[c_send])[:44]
                a = str(r[c_subj])[:56]
                print(f"      de: {s:46s} | {a}")
        print()

    print("=" * 66)
    if problemas:
        print(f"[X] {problemas} problema(s). Corrigelos antes de entrenar.")
        return

    print("[OK] Formato correcto. Ahora revisa a ojo:")
    print()
    print("  1. Que los ejemplos marcados SE USA con label=1 sean phishing")
    print("     de credenciales: suplantacion de marca, peticion de datos,")
    print("     enlaces a sitios falsos.")
    print()
    print("  2. Que en CEAS_08 y SpamAssasin los label=1 que se descartan")
    print("     sean spam comercial. Si fueran phishing, habria que")
    print("     reconsiderar la particion.")
    print()
    print("  3. Que los label=0 sean correo normal de trabajo o personal.")


if __name__ == "__main__":
    main()