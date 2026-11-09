"""
umbrales_accesos.py
-------------------
Fija los tres niveles de severidad del detector de accesos remotos y
guarda el modelo ajustado.

POR QUE TRES NIVELES Y NO UN UMBRAL
    Igual que en phishing. Una alerta afirmativa solo sirve si acierta,
    y a esta prevalencia (1 ventana positiva de cada ~95,000) un solo
    umbral obliga a elegir entre no avisar casi nunca o avisar mal.

POR QUE EL UMBRAL SE FIJA POR FPR Y NO POR PRECISION
    La precision depende de la prevalencia, que en el tenant de la PyME
    todavia no se ha medido. El FPR no: se mide sobre trafico benigno y
    se traduce directo a falsas alarmas por dia, que es lo que el
    operador siente. La precision se reconstruye con la formula.

DONDE SE CALIBRA Y DONDE SE VERIFICA
    benigno_cal   dias 31-44   fija el umbral
    benigno_ver   dias 45-58   verifica que el FPR se sostiene
    prueba        dias 17-30   mide el recall

    Tres bloques, tres trabajos. Ninguno hace dos.

PISO DE MEDICION
    El bloque benigno tiene ~543,700 ventanas muestreadas. Un FPR de
    1e-6 serian menos de una ventana. Por debajo de FPR_MINIMO la
    estimacion la deciden una o dos ventanas y no significa nada: el
    script lo marca en vez de reportar un numero inventado.

Uso:
    python umbrales_accesos.py ventanas.csv
    python umbrales_accesos.py ventanas.csv --equipos 50
    python umbrales_accesos.py ventanas.csv --equipos 120 --modelo xgboost
"""

import json
import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

SEMILLA = 42
DIR_MODELOS = "modelos_accesos"

# Niveles. El FPR objetivo es lo que se mide; el nombre es lo que ve el
# operador. Solo "alto" notifica.
# 'alto' esta en 3e-5 y no en 1e-5 por el piso de medicion: con ~271,850
# ventanas en benigno_cal, 1e-5 son 2.7 ventanas y el umbral lo decidirian
# dos observaciones. 3e-5 son ~8, que ya es estimable.
NIVELES = [
    ("alto",  3e-5, "Alerta afirmativa y notificacion"),
    ("medio", 1e-4, "Aparece en el panel como sospechoso"),
    ("bajo",  1e-3, "Queda registrado para revision"),
]

FPR_MINIMO = 1e-5          # piso de medicion: por debajo no es estimable
EQUIPOS_PYME = 50          # tamaño de referencia de la organizacion destino
EQUIPOS_LANL = 15744       # equipos distintos en el corpus de calibracion

BLOQUES = {
    "ajuste":      (1, 12),
    "validacion":  (13, 16),
    "prueba":      (17, 30),
    "benigno_cal": (31, 44),
    "benigno_ver": (45, 58),
}

NO_CARACTERISTICAS = {"dia", "hora", "usuario", "origen", "destino", "etiqueta"}


def poisson_ic(k, n):
    """Intervalo exacto de Poisson para una tasa estimada con k eventos
    sobre n observaciones. Con k pequeño (4 falsos positivos, por ejemplo)
    el intervalo es enorme y reportar solo la estimacion puntual seria
    enganoso."""
    from scipy.stats import chi2
    bajo = chi2.ppf(0.025, 2 * k) / 2 if k > 0 else 0.0
    alto = chi2.ppf(0.975, 2 * k + 2) / 2
    return (bajo / n, alto / n)


def wilson(exitos, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = exitos / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - m), min(1.0, c + m))


def precision_en_prevalencia(tpr, fpr, pi):
    den = pi * tpr + (1 - pi) * fpr
    return (pi * tpr / den) if den > 0 else 0.0


def construir(nombre, params, peso_pos, semilla=SEMILLA):
    if nombre == "random_forest":
        m = RandomForestClassifier(random_state=semilla, n_jobs=-1,
                                   class_weight="balanced_subsample")
        m.set_params(**params)
        return m
    if nombre == "xgboost":
        m = XGBClassifier(random_state=semilla, n_jobs=-1, eval_metric="aucpr",
                          tree_method="hist", scale_pos_weight=peso_pos)
        m.set_params(**params)
        return m
    if nombre == "svm":
        m = Pipeline([("esc", StandardScaler()),
                      ("clf", CalibratedClassifierCV(
                          LinearSVC(random_state=semilla, max_iter=5000,
                                    class_weight="balanced", dual="auto"),
                          method="sigmoid", cv=3))])
        m.set_params(**params)
        return m
    raise ValueError(nombre)


def umbral_para_fpr(proba_neg, objetivo):
    """Umbral tal que la proporcion de negativos por encima sea <= objetivo.

    Se calcula como cuantil sobre los puntajes de las ventanas benignas,
    que es exactamente lo que se haria en produccion: observar el propio
    trafico y cortar donde el presupuesto de alertas lo permita.
    """
    n = len(proba_neg)
    k = int(np.floor(n * objetivo))        # cuantas se permiten pasar
    orden = np.sort(proba_neg)[::-1]
    if k <= 0:
        return float(orden[0]) + 1e-12     # ninguna
    if k >= n:
        return 0.0
    return float(orden[k - 1])


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(1)
    ruta = args[0]

    equipos = EQUIPOS_PYME
    if "--equipos" in sys.argv:
        equipos = int(sys.argv[sys.argv.index("--equipos") + 1])
    forzado = None
    if "--modelo" in sys.argv:
        forzado = sys.argv[sys.argv.index("--modelo") + 1]

    ruta_contrato = os.path.join(DIR_MODELOS, "contrato_accesos.json")
    if not os.path.exists(ruta_contrato):
        print(f"[!] Falta {ruta_contrato}. Corre antes entrenar_accesos.py")
        sys.exit(1)
    with open(ruta_contrato, encoding="utf-8") as f:
        contrato = json.load(f)

    nombre = forzado or contrato["seleccionado"]
    info = contrato["modelos"][nombre]
    cols = info["caracteristicas"]
    pi = contrato["prevalencia"]
    ventanas_dia_lanl = contrato["ventanas_por_dia"]

    print(f"Modelo        : {nombre}")
    print(f"Caracteristicas: {len(cols)}")
    print(f"Prevalencia   : {pi:.3e}  (1 de cada {1/pi:,.0f})")

    df = pd.read_csv(ruta)
    todas = [c for c in df.columns if c not in NO_CARACTERISTICAS]
    idx = [todas.index(c) for c in cols]

    datos = {}
    for b, (d0, d1) in BLOQUES.items():
        sub = df[(df.dia >= d0) & (df.dia <= d1)]
        datos[b] = (sub[todas].to_numpy(dtype=np.float32)[:, idx],
                    sub.etiqueta.to_numpy(dtype=np.int8))

    Xa, ya = datos["ajuste"]
    Xp, yp = datos["prueba"]
    Xc, yc = datos["benigno_cal"]
    Xv, yv = datos["benigno_ver"]

    print(f"\n  ajuste      {len(ya):>9,}  {int(ya.sum()):>4} positivas")
    print(f"  prueba      {len(yp):>9,}  {int(yp.sum()):>4} positivas")
    print(f"  benigno_cal {len(yc):>9,}  {int(yc.sum()):>4} positivas  <- fija umbral")
    print(f"  benigno_ver {len(yv):>9,}  {int(yv.sum()):>4} positivas  <- verifica")

    for b, y in (("benigno_cal", yc), ("benigno_ver", yv)):
        if y.sum():
            print(f"\n  [!] {b} tiene {int(y.sum())} positivas; deberia tener 0.")

    # --- escala -----------------------------------------------------
    por_equipo = ventanas_dia_lanl / EQUIPOS_LANL
    ventanas_dia_pyme = por_equipo * equipos
    print(f"\n  escala:")
    print(f"    LANL  {EQUIPOS_LANL:,} equipos -> {ventanas_dia_lanl:,.0f} ventanas/dia")
    print(f"    ratio {por_equipo:.1f} ventanas por equipo por dia")
    print(f"    PyME  {equipos} equipos -> {ventanas_dia_pyme:,.0f} ventanas/dia")

    # --- piso de medicion -------------------------------------------
    print(f"\n  piso de medicion: FPR {FPR_MINIMO:.0e} = "
          f"{len(yc) * FPR_MINIMO:.1f} ventanas en benigno_cal")
    print("    Por debajo de ese FPR el umbral lo deciden una o dos")
    print("    ventanas y la estimacion no es confiable.")

    # --- ajuste -----------------------------------------------------
    peso_pos = float((ya == 0).sum() / max(1, (ya == 1).sum()))
    print(f"\n  Ajustando {nombre}...")
    modelo = construir(nombre, info["hiperparametros"], peso_pos)
    modelo.fit(Xa, ya)

    pp = modelo.predict_proba(Xp)[:, 1]
    pc = modelo.predict_proba(Xc)[:, 1]
    pv = modelo.predict_proba(Xv)[:, 1]

    # --- niveles ----------------------------------------------------
    print("\n" + "=" * 78)
    print("NIVELES DE SEVERIDAD")
    print("=" * 78)
    print(f"  {'nivel':<7} {'umbral':>9} {'recall prueba':>21} "
          f"{'FPR ver':>10} {'precision':>10} {'falsas alarmas PyME':>22}")

    salida = {"modelo": nombre, "caracteristicas": cols, "prevalencia": pi,
              "equipos_referencia": equipos,
              "ventanas_dia_pyme": ventanas_dia_pyme,
              "fpr_minimo_estimable": FPR_MINIMO, "niveles": {}}

    for etiqueta, objetivo, descripcion in NIVELES:
        u = umbral_para_fpr(pc, objetivo)

        tp = int(((pp >= u) & (yp == 1)).sum())
        fn = int(((pp < u) & (yp == 1)).sum())
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        ic = wilson(tp, tp + fn)

        fp_ver = int((pv >= u).sum())
        fpr_ver = fp_ver / len(pv)

        fpr_lo, fpr_hi = poisson_ic(fp_ver, len(pv))
        prec = precision_en_prevalencia(recall, fpr_ver, pi)
        prec_lo = precision_en_prevalencia(recall, fpr_hi, pi)   # mas FPR, menos precision
        prec_hi = precision_en_prevalencia(recall, fpr_lo, pi)
        fp_dia = ventanas_dia_pyme * fpr_ver
        fp_dia_lo = ventanas_dia_pyme * fpr_lo
        fp_dia_hi = ventanas_dia_pyme * fpr_hi

        if fp_dia > 0:
            if fp_dia >= 1:
                leyenda = f"{fp_dia:.1f} al dia"
            else:
                leyenda = f"1 cada {1/fp_dia:.0f} dias"
        else:
            leyenda = "ninguna observada"

        aviso = ""
        if objetivo < FPR_MINIMO or fp_ver < 5:
            aviso = "  [bajo el piso]"

        print(f"  {etiqueta:<7} {u:>9.4f} "
              f"{recall:>8.4f} [{ic[0]:.2f}-{ic[1]:.2f}] "
              f"{fpr_ver:>10.2e} {prec:>10.4f} {leyenda:>22}{aviso}")

        def _ritmo(x):
            if x <= 0:
                return "nunca"
            return f"{x:.1f}/dia" if x >= 1 else f"1 cada {1/x:.0f} d"

        print(f"{'':>10} IC95  FPR [{fpr_lo:.1e}-{fpr_hi:.1e}]   "
              f"precision [{prec_lo:.2f}-{prec_hi:.2f}]   "
              f"alarmas [{_ritmo(fp_dia_hi)} - {_ritmo(fp_dia_lo)}]")

        salida["niveles"][etiqueta] = {
            "umbral": u, "fpr_objetivo": objetivo,
            "fpr_verificado": fpr_ver, "fp_en_verificacion": fp_ver,
            "fpr_ic95": [fpr_lo, fpr_hi],
            "precision_ic95": [prec_lo, prec_hi],
            "falsas_alarmas_dia_ic95": [fp_dia_lo, fp_dia_hi],
            "recall": recall, "recall_ic": list(ic),
            "precision_estimada": prec,
            "falsas_alarmas_dia_pyme": fp_dia,
            "notifica": etiqueta == "alto",
            "descripcion": descripcion,
            "estimacion_confiable": fp_ver >= 5,
        }

    print("\n  Solo 'alto' notifica. 'medio' y 'bajo' alimentan el panel:")
    print("  recuperan cobertura sin gastar credibilidad, porque no afirman.")

    print("\n  Cobertura acumulada (cae en algun nivel):")
    u_bajo = salida["niveles"]["bajo"]["umbral"]
    cob = int(((pp >= u_bajo) & (yp == 1)).sum()) / max(1, int(yp.sum()))
    print(f"    {cob:.1%} de los accesos no autorizados de los dias 17-30")

    print("\n  ADVERTENCIAS")
    print("  1. El recall sale de 46 ventanas positivas de 7 episodios.")
    print("     Los intervalos son anchos y ademas optimistas, porque las")
    print("     ventanas de un mismo episodio estan correlacionadas.")
    print("  2. La precision supone la prevalencia de LANL. La del tenant")
    print("     hay que medirla y volver a correr este script.")
    print("  3. La traduccion a la PyME es lineal por numero de equipos.")
    print("     Es una aproximacion, no una medicion.")

    os.makedirs(DIR_MODELOS, exist_ok=True)
    joblib.dump(modelo, os.path.join(DIR_MODELOS, f"{nombre}.joblib"))
    with open(os.path.join(DIR_MODELOS, "umbrales_accesos.json"), "w",
              encoding="utf-8") as f:
        json.dump(salida, f, indent=2, ensure_ascii=False)
    print(f"\nModelo   -> {DIR_MODELOS}/{nombre}.joblib")
    print(f"Umbrales -> {DIR_MODELOS}/umbrales_accesos.json")


if __name__ == "__main__":
    main()