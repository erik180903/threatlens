"""
ThreatLens - Entrenamiento del modelo de phishing por correo.

DISENO EXPERIMENTAL
===================
No existe corpus publico de correo legitimo moderno: todo el ham disponible
es de 2001-2008. Por eso el ENTRENAMIENTO se mantiene emparejado en epoca
-phishing de 2005-2007 contra ham de 2002-2008- de modo que el modelo no
pueda aprender "epoca" en vez de "phishing".

Cuatro particiones. El ham se reparte entre las cuatro para que su
distribucion sea identica en todas, y asi lo UNICO que varia entre ellas
sea la fuente del phishing:

  ENTRENAMIENTO  Nazario 2005-2007        + 1/3 del ham
  EXTERNO A      Nigerian_Fraud           + 1/3 del ham   otra campana
  EXTERNO B1     mitad de PhishingPot     + 1/6 del ham   DECIDE
  EXTERNO B2     otra mitad de PhishingPot+ 1/6 del ham   MIDE

B1 y B2 estan separados a proposito. B1 decide que grupo de caracteristicas
conserva cada algoritmo; B2 no participa en ninguna decision y se mide una
sola vez al final. Sin esa separacion, usar la ablacion para elegir
caracteristicas filtraria el conjunto de prueba en la seleccion.

PROTOCOLO
=========
  1. Busqueda aleatoria de hiperparametros, validacion cruzada
     estratificada de 5 pliegues, optimizando PR-AUC.
  2. Ablacion por grupo medida en B1.
  3. Reajuste con 5 semillas; metricas como media +- desviacion.
  4. Umbral optimizado sobre validacion, nunca sobre prueba. Dos puntos de
     operacion: maximo F1 y maximo recall sujeto a precision >= 0.90.
  5. Seleccion por F1 sobre B2 en el punto de operacion que se despliega.

    python train_phishing_email.py
"""

import json
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import (RandomizedSearchCV, StratifiedKFold,
                                     train_test_split)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier

from features_email import (GRUPOS, NOMBRES_CARACTERISTICAS,
                            extraer_caracteristicas, urls_desde_cuerpo)

warnings.filterwarnings("ignore", category=UserWarning)

DATOS, SALIDA = Path("datos"), Path("modelos")
SEMILLA, CV, N_BUSQUEDA, REPETICIONES = 42, 5, 25, 5
PRECISION_MINIMA = 0.90

# archivo -> (particion, etiquetas que se conservan)
# De CEAS_08 y SpamAssasin solo se toma label=0: sus label=1 son spam
# comercial, no phishing de credenciales.
CORPUS = {
    "Nazario.csv":        ("train", {1}),
    "SpamAssasin.csv":    ("ham",   {0}),
    "CEAS_08.csv":        ("ham",   {0}),
    "Nigerian_Fraud.csv": ("ext_a", {1}),
    "PhishingPot.csv":    ("ext_b", {1}),
}


# ===================================================================== datos

def _col(df, *nombres):
    bajas = {c.lower().strip(): c for c in df.columns}
    for n in nombres:
        if n in bajas:
            return bajas[n]
    return None


def cargar_corpus():
    partes = {"train": [], "ham": [], "ext_a": [], "ext_b": []}
    for archivo, (particion, etiquetas_ok) in CORPUS.items():
        ruta = DATOS / archivo
        if not ruta.exists():
            print(f"  [!] falta {ruta}, se omite")
            continue
        try:
            df = pd.read_csv(ruta, low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(ruta, low_memory=False, encoding="latin-1")

        cols = (_col(df, "sender", "from"), _col(df, "subject"),
                _col(df, "body", "text"), _col(df, "label"))
        if not all(cols):
            print(f"  [!] {archivo}: columnas inesperadas")
            continue
        c_s, c_su, c_b, c_l = cols

        sub = pd.DataFrame({
            "sender": df[c_s].fillna("").astype(str),
            "subject": df[c_su].fillna("").astype(str),
            "body": df[c_b].fillna("").astype(str),
            "label": pd.to_numeric(df[c_l], errors="coerce").fillna(0).astype(int),
        })
        antes = len(sub)
        sub = sub[sub.label.isin(etiquetas_ok)].reset_index(drop=True)
        desc = antes - len(sub)
        print(f"  {archivo:22s} -> {particion:8s} | {len(sub):6,}"
              + (f"  ({desc:,} descartadas)" if desc else ""))
        partes[particion].append(sub)

    if not partes["train"] or not partes["ham"]:
        raise SystemExit(f"Faltan corpus obligatorios en ./{DATOS}/")

    # PhishingPot se parte en dos: B1 decide, B2 evalua.
    pot = pd.concat(partes["ext_b"], ignore_index=True) if partes["ext_b"] else None
    pot_b1 = pot.sample(frac=0.5, random_state=SEMILLA) if pot is not None else None
    pot_b2 = pot.drop(pot_b1.index) if pot is not None else None

    # El ham se reparte: 1/3 train, 1/3 ext_a, 1/6 ext_b1, 1/6 ext_b2.
    ham = pd.concat(partes["ham"], ignore_index=True)
    h_tr = ham.sample(frac=1 / 3, random_state=SEMILLA)
    resto = ham.drop(h_tr.index)
    h_a = resto.sample(frac=0.5, random_state=SEMILLA)
    resto2 = resto.drop(h_a.index)
    h_b1 = resto2.sample(frac=0.5, random_state=SEMILLA)
    h_b2 = resto2.drop(h_b1.index)
    print(f"  {'ham repartido':22s} -> {len(h_tr):,} train / {len(h_a):,} ext_a "
          f"/ {len(h_b1):,} ext_b1 / {len(h_b2):,} ext_b2")

    def unir(frames):
        frames = [f for f in frames if f is not None and len(f)]
        return pd.concat(frames, ignore_index=True) if frames else None

    return (unir(partes["train"] + [h_tr]), unir(partes["ext_a"] + [h_a]),
            unir([pot_b1, h_b1]), unir([pot_b2, h_b2]))


def matriz(df, etiqueta):
    """Aplica el extractor a cada correo. Este paso es el que garantiza que
    entrenamiento e inferencia compartan el mismo espacio de caracteristicas."""
    if df is None:
        return None, None
    print(f"  caracteristicas ({etiqueta}, {len(df):,})...", end="", flush=True)
    t0 = time.time()
    filas = [extraer_caracteristicas(s, a, urls_desde_cuerpo(b))
             for s, a, b in zip(df["sender"], df["subject"], df["body"])]
    X = pd.DataFrame(filas, columns=NOMBRES_CARACTERISTICAS).astype(np.float64)
    X = X.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    print(f" {time.time() - t0:.1f}s")
    return X, df["label"].to_numpy()


# =================================================================== modelos

def espacios(peso_pos):
    """Rejillas de hiperparametros. Cada algoritmo compite con su mejor
    configuracion, no con parametros elegidos a ojo."""
    return {
        "random_forest": (
            RandomForestClassifier(class_weight="balanced", n_jobs=-1,
                                   random_state=SEMILLA),
            {"n_estimators": [200, 400, 600], "max_depth": [None, 10, 16, 24],
             "min_samples_leaf": [1, 2, 4, 8],
             "max_features": ["sqrt", "log2", 0.4]}),

        # LinearSVC no da probabilidades, solo distancia al hiperplano.
        # CalibratedClassifierCV la convierte en probabilidad real mediante
        # validacion cruzada. El sistema decide por umbral de probabilidad
        # (RF10), asi que sin esto el SVM competiria en desventaja tecnica.
        "svm": (
            Pipeline([("escala", StandardScaler()),
                      ("clf", CalibratedClassifierCV(
                          LinearSVC(class_weight="balanced", dual="auto",
                                    max_iter=8000, random_state=SEMILLA),
                          method="sigmoid", cv=3))]),
            {"clf__estimator__C": [0.01, 0.1, 0.5, 1.0, 5.0, 10.0]}),

        "xgboost": (
            XGBClassifier(eval_metric="logloss", tree_method="hist", n_jobs=-1,
                          scale_pos_weight=peso_pos, random_state=SEMILLA),
            {"n_estimators": [300, 500, 800], "max_depth": [4, 6, 8, 10],
             "learning_rate": [0.03, 0.05, 0.1, 0.2],
             "subsample": [0.7, 0.85, 1.0], "colsample_bytree": [0.6, 0.8, 1.0],
             "min_child_weight": [1, 3, 6]}),
    }


def umbral_optimo(y, proba, precision_minima=None):
    """Umbral optimo sobre la curva precision-recall.

    Sin precision_minima devuelve el de maximo F1. Con ella, el que da
    mayor recall entre los que alcanzan esa precision.
    """
    p, r, t = precision_recall_curve(y, proba)
    p, r = p[:-1], r[:-1]
    if len(t) == 0:
        return 0.5
    if precision_minima is None:
        f1 = 2 * p * r / np.maximum(p + r, 1e-12)
        return float(t[int(np.nanargmax(f1))])
    viables = np.where(p >= precision_minima)[0]
    if len(viables) == 0:
        return umbral_optimo(y, proba)
    return float(t[int(viables[np.argmax(r[viables])])])


def medir(y, proba, umbral):
    y_pred = (proba >= umbral).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, y_pred, labels=[0, 1]).ravel()
    return {
        "umbral": round(float(umbral), 4),
        "precision": round(float(precision_score(y, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y, proba)), 4),
        "pr_auc": round(float(average_precision_score(y, proba)), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "tasa_falsos_positivos": round(fp / max(tn + fp, 1), 4),
    }


def proba_de(modelo, X):
    if hasattr(modelo, "predict_proba"):
        return modelo.predict_proba(X)[:, 1]
    return 1.0 / (1.0 + np.exp(-modelo.decision_function(X)))


def agrega(lista):
    """Media y desviacion estandar sobre las repeticiones."""
    claves = [k for k in lista[0] if isinstance(lista[0][k], (int, float))]
    out = {}
    for k in claves:
        v = np.array([d[k] for d in lista], dtype=float)
        out[k] = round(float(v.mean()), 4)
        out[k + "_sd"] = round(float(v.std(ddof=1)) if len(v) > 1 else 0.0, 4)
    return out


def tabla_ds(nombre, m):
    print(f"    {nombre:14s} P={m['precision']:.4f}+-{m['precision_sd']:.4f}  "
          f"R={m['recall']:.4f}+-{m['recall_sd']:.4f}  "
          f"F1={m['f1_score']:.4f}+-{m['f1_score_sd']:.4f}  "
          f"PR-AUC={m['pr_auc']:.4f}  FP={m['fp']:.0f} "
          f"({m['tasa_falsos_positivos']:.1%})")


# ====================================================================== main

def main():
    SALIDA.mkdir(exist_ok=True)
    print("Cargando corpus...")
    tr, ea, eb1, eb2 = cargar_corpus()
    print()
    X, y = matriz(tr, "entrenamiento")
    X_ea, y_ea = matriz(ea, "externo A")
    X_b1, y_b1 = matriz(eb1, "externo B1 (decide)")
    X_b2, y_b2 = matriz(eb2, "externo B2 (mide)")

    X_fit, X_val, y_fit, y_val = train_test_split(
        X, y, test_size=0.25, random_state=SEMILLA, stratify=y)
    print(f"\n  ajuste={len(X_fit):,}  validacion={len(X_val):,}  "
          f"extA={0 if X_ea is None else len(X_ea):,}  "
          f"extB1={0 if X_b1 is None else len(X_b1):,}  "
          f"extB2={0 if X_b2 is None else len(X_b2):,}")

    peso = int((y_fit == 0).sum()) / max(int((y_fit == 1).sum()), 1)
    cv = StratifiedKFold(n_splits=CV, shuffle=True, random_state=SEMILLA)
    resultados, mejores = {}, {}

    # ------------------------------------------- 1. hiperparametros
    for nombre, (base, rejilla) in espacios(peso).items():
        print(f"\n{'=' * 70}\n{nombre.upper()}")
        print(f"  Hiperparametros ({N_BUSQUEDA} combinaciones x {CV} pliegues)...")
        t0 = time.time()
        bus = RandomizedSearchCV(base, rejilla, n_iter=N_BUSQUEDA, cv=cv,
                                 scoring="average_precision", n_jobs=-1,
                                 random_state=SEMILLA, refit=True)
        bus.fit(X_fit, y_fit)
        print(f"  {time.time() - t0:.1f}s | PR-AUC cv = {bus.best_score_:.4f}")
        print(f"  {bus.best_params_}")
        mejores[nombre] = (bus.best_estimator_, bus.best_score_, bus.best_params_)

    # ------------------------------------------- 2. ablacion sobre B1
    print(f"\n{'=' * 70}\nSELECCION DE CARACTERISTICAS (ablacion medida en EXTERNO B1)")
    print("  B1 decide; B2 no participa y solo se mide al final.\n")
    seleccion = {}
    todas = list(NOMBRES_CARACTERISTICAS)
    for nombre, (est, _, _) in mejores.items():
        print(f"  {nombre}")
        candidatos = {"completo": todas}
        for g, cols in GRUPOS.items():
            restantes = [c for c in todas if c not in cols]
            if restantes:
                candidatos[f"sin_{g}"] = restantes

        puntajes = {}
        for etq, cols in candidatos.items():
            m = clone(est)
            m.fit(X_fit[cols], y_fit)
            u = umbral_optimo(y_val, proba_de(m, X_val[cols]))
            f1v = medir(y_val, proba_de(m, X_val[cols]), u)["f1_score"]
            f1b1 = (medir(y_b1, proba_de(m, X_b1[cols]), u)["f1_score"]
                    if X_b1 is not None else 0.0)
            puntajes[etq] = (f1b1, cols)
            print(f"    {etq:22s} F1val={f1v:.4f}   F1extB1={f1b1:.4f}")

        elegido = max(puntajes, key=lambda k: puntajes[k][0])
        seleccion[nombre] = (elegido, puntajes[elegido][1])
        print(f"    -> conserva: {elegido} "
              f"({len(puntajes[elegido][1])} caracteristicas)\n")

    # ------------------------------------------- 3. ajuste final
    for nombre, (est, cv_score, params) in mejores.items():
        etq_sel, cols = seleccion[nombre]
        print(f"\n{'=' * 70}\n{nombre.upper()}  -  ajuste final "
              f"({etq_sel}, {len(cols)} caracteristicas, {REPETICIONES} semillas)")
        acum, modelo_final = {}, None

        for rep in range(REPETICIONES):
            sem = SEMILLA + rep
            Xf, Xv, yf, yv = train_test_split(
                X[cols], y, test_size=0.25, random_state=sem, stratify=y)
            m = clone(est)
            try:
                m.set_params(random_state=sem)
            except ValueError:
                pass
            m.fit(Xf, yf)
            if rep == 0:
                modelo_final = m

            pv = proba_de(m, Xv)
            for etq, u in (("max-F1", umbral_optimo(yv, pv)),
                           (f"P>={PRECISION_MINIMA}",
                            umbral_optimo(yv, pv, PRECISION_MINIMA))):
                acum.setdefault(f"validacion_{etq}", []).append(medir(yv, pv, u))
                for clave, Xe, ye in (("externo_a", X_ea, y_ea),
                                      ("externo_b2", X_b2, y_b2)):
                    if Xe is None:
                        continue
                    acum.setdefault(f"{clave}_{etq}", []).append(
                        medir(ye, proba_de(m, Xe[cols]), u))

            # Cota superior: umbral recalibrado sobre el propio B2. NO se usa
            # para decidir nada. Separa lo que se pierde por limitacion del
            # modelo de lo que se pierde por un umbral de otra epoca.
            if X_b2 is not None:
                pb2 = proba_de(m, X_b2[cols])
                acum.setdefault("oraculo_b2_recalibrado", []).append(
                    medir(y_b2, pb2,
                          umbral_optimo(y_b2, pb2, PRECISION_MINIMA)))

        r = {"cv_pr_auc": round(float(cv_score), 4),
             "mejores_parametros": {k: str(v) for k, v in params.items()},
             "grupo_excluido": etq_sel, "caracteristicas": cols,
             "repeticiones": REPETICIONES}
        for titulo, prefijo in (
                ("VALIDACION INTERNA", "validacion"),
                ("EXTERNO A - Nigerian Fraud", "externo_a"),
                ("EXTERNO B2 - PhishingPot (nunca usado)", "externo_b2"),
                ("COTA SUPERIOR - umbral recalibrado sobre B2", "oraculo")):
            claves = [k for k in acum if k.startswith(prefijo)]
            if not claves:
                continue
            print(f"\n  {titulo}   (media +- desv, {REPETICIONES} semillas)")
            for k in sorted(claves):
                ag = agrega(acum[k])
                r[k] = ag
                tabla_ds(k[len(prefijo) + 1:] if "_" in k[len(prefijo):] else k, ag)

        resultados[nombre] = r
        dump(modelo_final, SALIDA / f"phishing_email_{nombre}.joblib")

    # ------------------------------------------- 4. seleccion final
    # El criterio usa el MISMO punto de operacion que se despliega.
    # Elegir con un umbral y desplegar con otro seria incoherente.
    op = f"P>={PRECISION_MINIMA}"
    CLAVE_OP = f"externo_b2_{op}"

    def f1b2(k):
        return resultados[k].get(CLAVE_OP, {}).get("f1_score", 0.0)

    ganador = max(resultados, key=f1b2)

    for titulo, suf in ((f"RESUMEN  (F1 en el punto de operacion {op})", op),
                        ("RESUMEN  (F1 en maximo F1, referencia)", "max-F1")):
        print(f"\n{'=' * 70}\n{titulo}")
        print(f"  {'modelo':16s}{'caracts':>9s}{'validacion':>15s}"
              f"{'externo A':>15s}{'externo B2':>15s}{'  FP en B2':>12s}")
        for k, v in resultados.items():
            va = v.get(f'validacion_{suf}', {})
            ea_ = v.get(f'externo_a_{suf}', {})
            eb_ = v.get(f'externo_b2_{suf}', {})
            print(f"  {k:16s}{len(v['caracteristicas']):>9d}"
                  f"{va.get('f1_score', float('nan')):>9.4f}+-{va.get('f1_score_sd', 0):.3f}"
                  f"{ea_.get('f1_score', float('nan')):>9.4f}+-{ea_.get('f1_score_sd', 0):.3f}"
                  f"{eb_.get('f1_score', float('nan')):>9.4f}+-{eb_.get('f1_score_sd', 0):.3f}"
                  f"{eb_.get('tasa_falsos_positivos', float('nan')):>11.1%}")

    print("\n  Cota superior en B2 (umbral recalibrado sobre B2):")
    for k, v in resultados.items():
        o = v.get("oraculo_b2_recalibrado", {})
        d = o.get("f1_score", float('nan')) - v.get(CLAVE_OP, {}).get("f1_score", 0.0)
        print(f"    {k:16s} F1={o.get('f1_score', float('nan')):.4f}  "
              f"R={o.get('recall', float('nan')):.4f}   "
              f"margen perdido por umbral desfasado: {d:+.4f}")

    print(f"\n>>> Seleccionado: {ganador} ({resultados[ganador]['grupo_excluido']}, "
          f"F1 externo B2 = {f1b2(ganador):.4f} en el punto {op})")
    print("    Criterio: mismo punto de operacion que se despliega, medido")
    print("    sobre phishing real 2022-2026 nunca usado en ninguna decision.")

    contrato = {
        "tipo_amenaza": "phishing", "modo": "completo_correo",
        "modelo_seleccionado": ganador,
        "archivo_modelo": f"phishing_email_{ganador}.joblib",
        "umbral": resultados[ganador][f"validacion_{op}"]["umbral"],
        "criterio_umbral": f"maximo recall sujeto a precision >= {PRECISION_MINIMA}",
        "criterio_seleccion": "mayor F1 sobre externo B2 en el punto de "
                              "operacion desplegado; B2 no participa en "
                              "ninguna decision previa",
        "orden_caracteristicas": resultados[ganador]["caracteristicas"],
        "grupo_excluido": resultados[ganador]["grupo_excluido"],
        "grupos_caracteristicas": GRUPOS,
        "particiones": {
            "entrenamiento": "Nazario (2005-2007) + 1/3 del ham (2002-2008)",
            "externo_a": "Nigerian_Fraud + 1/3 del ham",
            "externo_b1": "50% de PhishingPot + 1/6 del ham (decide features)",
            "externo_b2": "50% de PhishingPot + 1/6 del ham (evaluacion final)"},
        "campos_origen_advanced_hunting": {
            "remitente": "EmailEvents.SenderFromAddress / SenderDisplayName",
            "asunto": "EmailEvents.Subject",
            "urls": "EmailUrlInfo.Url (join por NetworkMessageId)"},
        "excluido_deliberadamente": [
            "cuerpo del mensaje: advanced hunting no lo expone",
            "ThreatTypes / DetectionMethods: veredicto de Microsoft, seria circular",
            "SPF/DKIM/DMARC: presentes en PhishingPot pero ausentes en el ham "
            "de 2002-2008; su sola presencia seria un atajo hacia la etiqueta",
            "SHA256 del adjunto: identificador, no patron; memoriza muestras"],
        "nota_prevalencia":
            "La precision medida corresponde a la prevalencia del corpus de "
            "evaluacion (~55%). En un buzon real es de 0.5% a 1%, por lo que "
            "el umbral debe recalibrarse con umbrales_severidad.py antes de "
            "poner el sistema en operacion.",
        "metricas": resultados,
    }
    (SALIDA / "contrato_phishing_email.json").write_text(
        json.dumps(contrato, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nModelos y contrato en ./{SALIDA}/")


if __name__ == "__main__":
    main()