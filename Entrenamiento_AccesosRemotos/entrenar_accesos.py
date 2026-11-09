"""
entrenar_accesos.py
-------------------
Entrena y selecciona el modelo A2: autenticacion remota anomala
(movimiento lateral con credenciales validas).

Lee ventanas.csv, que produjo construir_ventanas.py.

PARTICION  (temporal, cuatro bloques)
    ajuste       dias  1-12   ajusta el modelo
    validacion   dias 13-16   DECIDE: hiperparametros, ablacion, umbral
    prueba       dias 17-30   MIDE, una sola vez
    benigno      dias 31-58   sin ataques: FPR a escala real

    validacion decide y prueba mide. Es la misma disciplina de B1/B2 del
    entrenamiento de phishing, movida al eje del tiempo.

IDENTIFICADORES FUERA
    usuario, origen y destino son enteros arbitrarios. Si entraran como
    caracteristicas el modelo memorizaria las 104 cuentas del red team y
    daria metricas perfectas que no transfieren a nada. Se excluyen de
    forma explicita, no por omision.

NEGATIVOS MUESTREADOS
    ventanas.csv trae todas las positivas y una fraccion TASA_NEGATIVOS
    de las negativas. El muestreo uniforme deja insesgados el recall y el
    FPR, pero NO la precision: esa se reconstruye con la formula de
    prevalencia sobre la prevalencia real del corpus completo.

Uso:
    python entrenar_accesos.py ventanas.csv
    python entrenar_accesos.py ventanas.csv --tasa 0.02 --prevalencia 1.051e-5
    python entrenar_accesos.py ventanas.csv --busqueda 10 --semillas 3

    --busqueda N   combinaciones de hiperparametros (por omision 20)
    --semillas N   reajustes con semilla distinta (por omision 5)

    Bajar esos dos recorta bastante el tiempo a costa de peores
    hiperparametros e intervalos mas anchos. Sirve para una primera
    corrida de prueba; los numeros del reporte salen de la corrida
    completa.
"""

import json
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# --------------------------------------------------------------------
SEMILLA = 42
CV = 5
N_BUSQUEDA = 20
REPETICIONES = 5

TASA_NEGATIVOS = 0.02          # debe coincidir con construir_ventanas.py
PREVALENCIA = None             # si es None se deduce del archivo y la tasa

# Puntos de operacion: tasas de falso positivo objetivo.
# A esta prevalencia un umbral por "precision >= 0.9" no es alcanzable,
# asi que el punto de operacion se fija por FPR y se traduce a alertas
# por dia, que es lo que el operador realmente siente.
OBJETIVOS_FPR = [1e-3, 1e-4, 1e-5]

DIR_SALIDA = "modelos_accesos"

BLOQUES = {
    "ajuste":     (1, 12),
    "validacion": (13, 16),
    "prueba":     (17, 30),
    "benigno":    (31, 58),
}

# Columnas que NUNCA son caracteristicas.
NO_CARACTERISTICAS = {"dia", "hora", "usuario", "origen", "destino", "etiqueta"}

GRUPOS = {
    "ventana": ["ven_eventos", "ven_logon", "ven_logoff", "ven_tgs", "ven_tgt",
                "ven_fallos", "ven_tasa_fallo", "ven_tipos_logon",
                "ven_frac_network", "ven_frac_remoteint", "ven_frac_ntlm",
                "ven_frac_kerberos", "ven_duracion", "ven_hora_dia"],
    "historial_usuario": ["his_usr_eventos", "his_usr_destinos",
                          "his_usr_origenes", "his_par_visto", "his_par_nuevo",
                          "his_origen_visto", "his_origen_nuevo",
                          "his_frac_destino", "his_usr_frac_hora"],
    "historial_destino": ["his_dst_eventos", "his_dst_usuarios",
                          "his_dst_nuevo", "his_frac_usr_en_dst",
                          "his_dst_por_usuario"],
    "concurrencia": ["con_destinos_usr", "con_origenes_usr", "con_eventos_usr",
                     "con_usuarios_dst", "con_eventos_dst",
                     "con_destinos_nuevos_usr"],
}


# --------------------------------------------------------------------
# Utilidades estadisticas
# --------------------------------------------------------------------

def wilson(exitos, n, z=1.96):
    """Intervalo de Wilson. Con 46 positivas el intervalo normal da
    limites fuera de [0,1]; este no."""
    if n == 0:
        return (0.0, 0.0)
    p = exitos / n
    d = 1 + z * z / n
    centro = (p + z * z / (2 * n)) / d
    margen = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centro - margen), min(1.0, centro + margen))


def precision_en_prevalencia(tpr, fpr, pi):
    """P = pi*TPR / (pi*TPR + (1-pi)*FPR).  La precision que el operador
    observa realmente, no la del conjunto muestreado."""
    den = pi * tpr + (1 - pi) * fpr
    return (pi * tpr / den) if den > 0 else 0.0


def umbral_para_fpr(y, proba, objetivo):
    """Umbral mas bajo cuyo FPR no supera el objetivo (maximiza recall
    sujeto a la restriccion de FPR)."""
    fpr, tpr, umbrales = roc_curve(y, proba)
    ok = np.where(fpr <= objetivo)[0]
    if len(ok) == 0:
        return 1.0
    i = ok[-1]                      # el ultimo que cumple = mayor TPR
    u = umbrales[i]
    return float(min(u, 1.0)) if np.isfinite(u) else 1.0


def medir(y, proba, umbral):
    pred = (proba >= umbral).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": rec, "fpr": fpr,
            "recall_ic": wilson(tp, tp + fn)}


# --------------------------------------------------------------------
# Diagnostico previo: ¿alguna caracteristica resuelve el problema sola?
# --------------------------------------------------------------------

def diagnostico_univariado(X, y, nombres):
    """La leccion de asu_prefijo_re_fw en phishing: una caracteristica que
    sola alcanza AUC ~1 casi nunca es una buena noticia. Suele ser un
    artefacto de como se recolecto el corpus."""
    print("=" * 70)
    print("DIAGNOSTICO UNIVARIADO  (antes de entrenar)")
    print("=" * 70)
    print("  AUC de cada caracteristica POR SI SOLA sobre el bloque de ajuste.")
    print("  Un valor cercano a 1.00 es una alarma, no un logro.\n")

    filas = []
    for i, n in enumerate(nombres):
        col = X[:, i]
        if np.all(col == col[0]):
            filas.append((n, 0.5, "constante"))
            continue
        try:
            auc = roc_auc_score(y, col)
        except ValueError:
            auc = 0.5
        filas.append((n, auc, ""))

    filas.sort(key=lambda f: abs(f[1] - 0.5), reverse=True)

    print(f"    {'caracteristica':<26} {'AUC':>7}   separacion")
    for n, auc, nota in filas[:12]:
        marca = ""
        if abs(auc - 0.5) >= 0.45:
            marca = "  <<< REVISAR"
        elif abs(auc - 0.5) >= 0.40:
            marca = "  <-- fuerte"
        print(f"    {n:<26} {auc:>7.4f}   {nota}{marca}")

    sospechosas = [n for n, auc, _ in filas if abs(auc - 0.5) >= 0.45]
    if sospechosas:
        print("\n  [!] " + ", ".join(sospechosas))
        print("      Separan casi perfectamente por si solas. Antes de creer")
        print("      el resultado hay que preguntarse si eso describe el")
        print("      ataque o la forma en que se construyo el corpus.")
        print("      La ablacion por grupo de mas abajo lo acota.")
    else:
        print("\n  [OK] Ninguna caracteristica resuelve el problema sola.")
    return filas


# --------------------------------------------------------------------
# Modelos
# --------------------------------------------------------------------

def espacios(peso_pos):
    return {
        "random_forest": (
            RandomForestClassifier(random_state=SEMILLA, n_jobs=-1,
                                   class_weight="balanced_subsample"),
            {"n_estimators": [200, 300, 400],
             "max_depth": [8, 12, 16, None],
             "min_samples_leaf": [1, 5, 20],
             "max_features": ["sqrt", "log2"]},
        ),
        "svm": (
            Pipeline([("esc", StandardScaler()),
                      ("clf", CalibratedClassifierCV(
                          LinearSVC(random_state=SEMILLA, max_iter=5000,
                                    class_weight="balanced", dual="auto"),
                          method="sigmoid", cv=3))]),
            {"clf__estimator__C": [0.001, 0.01, 0.1, 1.0, 10.0]},
        ),
        "xgboost": (
            XGBClassifier(random_state=SEMILLA, n_jobs=-1,
                          eval_metric="aucpr", tree_method="hist",
                          scale_pos_weight=peso_pos),
            {"n_estimators": [200, 400, 600],
             "max_depth": [4, 6, 8],
             "learning_rate": [0.03, 0.05, 0.1],
             "subsample": [0.8, 1.0],
             "colsample_bytree": [0.8, 1.0],
             "min_child_weight": [1, 5]},
        ),
    }


def proba_de(modelo, X):
    return modelo.predict_proba(X)[:, 1]


# --------------------------------------------------------------------

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(1)
    ruta = args[0]

    tasa = TASA_NEGATIVOS
    if "--tasa" in sys.argv:
        tasa = float(sys.argv[sys.argv.index("--tasa") + 1])
    prev_forzada = None
    if "--prevalencia" in sys.argv:
        prev_forzada = float(sys.argv[sys.argv.index("--prevalencia") + 1])

    global N_BUSQUEDA, REPETICIONES
    if "--busqueda" in sys.argv:
        N_BUSQUEDA = int(sys.argv[sys.argv.index("--busqueda") + 1])
    if "--semillas" in sys.argv:
        REPETICIONES = int(sys.argv[sys.argv.index("--semillas") + 1])

    print("Cargando ventanas...")
    df = pd.read_csv(ruta)
    nombres = [c for c in df.columns if c not in NO_CARACTERISTICAS]

    # Verificacion: ningun identificador se cuela como caracteristica.
    colados = [c for c in nombres if c in {"usuario", "origen", "destino"}]
    if colados:
        print(f"  [!] identificadores en las caracteristicas: {colados}")
        sys.exit(1)

    print(f"  {len(df):,} filas  |  {len(nombres)} caracteristicas")
    print(f"  positivas: {int(df.etiqueta.sum()):,}  "
          f"negativas: {int((df.etiqueta == 0).sum()):,}  "
          f"(muestreo {tasa:.1%})")

    # Prevalencia real del corpus completo, no la del archivo muestreado.
    n_pos = int(df.etiqueta.sum())
    n_neg_real = int((df.etiqueta == 0).sum() / tasa)
    pi = prev_forzada if prev_forzada else n_pos / (n_pos + n_neg_real)
    ventanas_dia = (n_pos + n_neg_real) / 58
    print(f"  prevalencia real: {pi:.3e}  (1 de cada {1/pi:,.0f})")
    print(f"  ventanas por dia: {ventanas_dia:,.0f}")

    # --- bloques ----------------------------------------------------
    datos = {}
    print("\n  bloques:")
    for nombre, (d0, d1) in BLOQUES.items():
        sub = df[(df.dia >= d0) & (df.dia <= d1)]
        X = sub[nombres].to_numpy(dtype=np.float32)
        y = sub.etiqueta.to_numpy(dtype=np.int8)
        dias_ataque = sub[sub.etiqueta == 1].dia.nunique()
        datos[nombre] = (X, y)
        print(f"    {nombre:<12} dias {d0:>2}-{d1:<2}  "
              f"{len(sub):>9,} ventanas  {int(y.sum()):>5} positivas  "
              f"{dias_ataque:>2} dias con ataque")

    Xa, ya = datos["ajuste"]
    Xv, yv = datos["validacion"]
    Xp, yp = datos["prueba"]
    Xb, yb = datos["benigno"]

    if ya.sum() == 0 or yv.sum() == 0:
        print("\n  [!] Un bloque de decision quedo sin positivas. Revisa los dias.")
        sys.exit(1)
    if yb.sum() != 0:
        print(f"\n  [!] El bloque benigno tiene {int(yb.sum())} positivas. "
              "Deberia tener 0.")

    print("\n  Advertencia sobre los intervalos: las ventanas positivas vienen")
    print("  de 18 episodios de ataque, no de 563 eventos independientes. Los")
    print("  intervalos calculados sobre el conteo de ventanas son optimistas.")

    print()
    diagnostico_univariado(Xa, ya, nombres)

    peso_pos = float((ya == 0).sum() / max(1, (ya == 1).sum()))
    print(f"\n  peso de la clase positiva: {peso_pos:,.1f}")

    # --- hiperparametros --------------------------------------------
    mejores = {}
    for nombre, (est, rejilla) in espacios(peso_pos).items():
        print("\n" + "=" * 70)
        print(nombre.upper())
        print("=" * 70)
        print(f"  Hiperparametros ({N_BUSQUEDA} x {CV} pliegues, objetivo PR-AUC)...")
        bus = RandomizedSearchCV(
            est, rejilla, n_iter=N_BUSQUEDA,
            scoring="average_precision",
            cv=StratifiedKFold(CV, shuffle=True, random_state=SEMILLA),
            random_state=SEMILLA, n_jobs=-1, refit=False)
        bus.fit(Xa, ya)
        mejores[nombre] = bus.best_params_
        print(f"  PR-AUC cv = {bus.best_score_:.4f}")
        print(f"  {bus.best_params_}")

    # --- ablacion por grupo, medida en VALIDACION -------------------
    print("\n" + "=" * 70)
    print("ABLACION POR GRUPO  (medida en VALIDACION)")
    print("=" * 70)
    print("  Validacion decide. Prueba no participa y se mide al final.\n")

    cols_por_modelo = {}
    for nombre in mejores:
        print(f"  {nombre}")
        resultados = {}
        configs = {"completo": nombres}
        for g, cols_g in GRUPOS.items():
            configs[f"sin_{g}"] = [c for c in nombres if c not in cols_g]

        for etiqueta, cols in configs.items():
            idx = [nombres.index(c) for c in cols]
            est, _ = espacios(peso_pos)[nombre]
            est.set_params(**mejores[nombre])
            est.fit(Xa[:, idx], ya)
            ap = average_precision_score(yv, proba_de(est, Xv[:, idx]))
            resultados[etiqueta] = (ap, cols)
            print(f"    {etiqueta:<24} PR-AUC val = {ap:.4f}  "
                  f"({len(cols)} caracts.)")

        ganador = max(resultados, key=lambda k: resultados[k][0])
        cols_por_modelo[nombre] = resultados[ganador][1]
        print(f"    -> conserva: {ganador} "
              f"({len(cols_por_modelo[nombre])} caracteristicas)\n")

    # --- reajuste con semillas y medicion final ---------------------
    contrato = {"prevalencia": pi, "tasa_negativos": tasa,
                "ventanas_por_dia": ventanas_dia,
                "bloques": {k: list(v) for k, v in BLOQUES.items()},
                "caracteristicas": nombres, "modelos": {}}

    resumen = []
    for nombre in mejores:
        cols = cols_por_modelo[nombre]
        idx = [nombres.index(c) for c in cols]
        print("=" * 70)
        print(f"{nombre.upper()}  -  ajuste final "
              f"({len(cols)} caracteristicas, {REPETICIONES} semillas)")
        print("=" * 70)

        acum = {obj: {"recall": [], "fpr_benigno": [], "precision": [],
                      "alertas_dia": []} for obj in OBJETIVOS_FPR}
        ap_prueba = []

        for s in range(REPETICIONES):
            est, _ = espacios(peso_pos)[nombre]
            est.set_params(**mejores[nombre])
            if hasattr(est, "random_state"):
                est.set_params(random_state=SEMILLA + s)
            est.fit(Xa[:, idx], ya)

            pv = proba_de(est, Xv[:, idx])
            pp = proba_de(est, Xp[:, idx])
            pb = proba_de(est, Xb[:, idx])
            ap_prueba.append(average_precision_score(yp, pp))

            for obj in OBJETIVOS_FPR:
                u = umbral_para_fpr(yv, pv, obj)      # umbral desde validacion
                mp = medir(yp, pp, u)                 # recall en prueba
                mb = medir(yb, pb, u)                 # FPR en benigno
                prec = precision_en_prevalencia(mp["recall"], mb["fpr"], pi)
                alertas = ventanas_dia * (pi * mp["recall"]
                                          + (1 - pi) * mb["fpr"])
                acum[obj]["recall"].append(mp["recall"])
                acum[obj]["fpr_benigno"].append(mb["fpr"])
                acum[obj]["precision"].append(prec)
                acum[obj]["alertas_dia"].append(alertas)

        print(f"\n  PR-AUC en prueba: {np.mean(ap_prueba):.4f} "
              f"+-{np.std(ap_prueba):.4f}")
        print("  (sobre negativos muestreados: sirve para comparar modelos,")
        print("   NO es la precision que vera el operador)\n")

        print(f"    {'FPR obj':>9} {'recall prueba':>22} "
              f"{'FPR benigno':>13} {'precision real':>15} {'alertas/dia':>12}")
        for obj in OBJETIVOS_FPR:
            a = acum[obj]
            r = np.mean(a["recall"])
            ic = wilson(int(round(r * yp.sum())), int(yp.sum()))
            print(f"    {obj:>9.0e} "
                  f"{r:>8.4f} [{ic[0]:.2f}-{ic[1]:.2f}] "
                  f"{np.mean(a['fpr_benigno']):>13.2e} "
                  f"{np.mean(a['precision']):>15.4f} "
                  f"{np.mean(a['alertas_dia']):>12.1f}")

        contrato["modelos"][nombre] = {
            "hiperparametros": mejores[nombre],
            "caracteristicas": cols,
            "pr_auc_prueba": float(np.mean(ap_prueba)),
            "operacion": {f"{o:.0e}": {
                "recall": float(np.mean(acum[o]["recall"])),
                "fpr": float(np.mean(acum[o]["fpr_benigno"])),
                "precision": float(np.mean(acum[o]["precision"])),
                "alertas_dia": float(np.mean(acum[o]["alertas_dia"]))}
                for o in OBJETIVOS_FPR},
        }
        resumen.append((nombre, np.mean(ap_prueba),
                        np.mean(acum[1e-4]["recall"]),
                        np.mean(acum[1e-4]["precision"]),
                        np.mean(acum[1e-4]["alertas_dia"])))
        print()

    # --- resumen ----------------------------------------------------
    print("=" * 70)
    print("RESUMEN  (punto de operacion FPR = 1e-4)")
    print("=" * 70)
    print(f"  {'modelo':<16} {'PR-AUC prueba':>14} {'recall':>9} "
          f"{'precision':>11} {'alertas/dia':>12}")
    for n, ap, r, p, al in resumen:
        print(f"  {n:<16} {ap:>14.4f} {r:>9.4f} {p:>11.4f} {al:>12.1f}")

    ganador = max(resumen, key=lambda f: f[1])[0]
    print(f"\n>>> Mejor PR-AUC en prueba: {ganador}")
    print("    Criterio: capacidad de ordenamiento sobre los dias 17-30,")
    print("    que no intervinieron en ninguna decision. El umbral de")
    print("    despliegue se fija despues, segun el presupuesto de alertas.")

    os.makedirs(DIR_SALIDA, exist_ok=True)
    contrato["seleccionado"] = ganador
    with open(os.path.join(DIR_SALIDA, "contrato_accesos.json"), "w",
              encoding="utf-8") as f:
        json.dump(contrato, f, indent=2, ensure_ascii=False)
    print(f"\nContrato en {DIR_SALIDA}/contrato_accesos.json")


if __name__ == "__main__":
    main()