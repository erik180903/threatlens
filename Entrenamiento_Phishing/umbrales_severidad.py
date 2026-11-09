"""
ThreatLens - Calculo de los umbrales por nivel de severidad.

EL PROBLEMA
===========
El modelo se evalua sobre corpus con ~55% de phishing. Un buzon real tiene
entre 0.5% y 1%. La precision depende de la prevalencia, asi que un umbral
calibrado sobre el corpus produce demasiadas alertas falsas en operacion.

Ejemplo con recall 0.46 y tasa de falsos positivos 2%:

    prevalencia 55%  ->  precision 0.965   (lo que mide el entrenamiento)
    prevalencia  1%  ->  precision 0.189   (lo que pasaria en un buzon real)

El modelo no cambio. Cambio el entorno.

LA CONVERSION
=============
El recall (TPR) y la tasa de falsos positivos (FPR) NO dependen de la
prevalencia; la precision si:

    P(pi) = pi*TPR / (pi*TPR + (1-pi)*FPR)

Se recorre la curva del modelo y, para cada umbral, se traslada la
precision a la prevalencia indicada.

LOS TRES NIVELES
================
Un solo umbral obliga a elegir entre perder detecciones o inundar de
alertas falsas. Con tres niveles la notificacion se reserva al nivel ALTO:

    ALTO   precision >= 0.90   alerta con notificacion
    MEDIO  precision >= 0.50   visible en el dashboard, sin notificar
    BAJO   precision >= 0.20   solo queda en el historial

Siguen siendo alertas con veredicto, no una lista ordenada.

Uso:
    python umbrales_severidad.py            # prevalencia 1% por defecto
    python umbrales_severidad.py 0.005      # 0.5%
    python umbrales_severidad.py 0.01 xgboost
"""

import json
import sys
from pathlib import Path

import numpy as np
from joblib import load

from train_phishing_email import cargar_corpus, matriz, proba_de

SALIDA = Path("modelos")
NIVELES = [("alto", 0.90), ("medio", 0.50), ("bajo", 0.20)]
PREVALENCIA_DEFECTO = 0.01
LOTE = 1000          # correos sobre los que se expresa el volumen de alertas


def precision_en_prevalencia(tpr, fpr, pi):
    tp, fp = pi * tpr, (1.0 - pi) * fpr
    return tp / (tp + fp) if (tp + fp) > 0 else 0.0


def curva(y, proba, n=400):
    """Recorre umbrales y devuelve (umbral, tpr, fpr) en cada punto."""
    pos, neg = y == 1, y == 0
    n_pos, n_neg = max(int(pos.sum()), 1), max(int(neg.sum()), 1)
    puntos = np.unique(np.quantile(proba, np.linspace(0.0, 1.0, n)))
    return [(float(t),
             float(((proba >= t) & pos).sum()) / n_pos,
             float(((proba >= t) & neg).sum()) / n_neg)
            for t in puntos]


def umbral_para(pts, pi, objetivo):
    """Umbral mas BAJO que alcanza la precision objetivo.

    El mas bajo porque, entre todos los que cumplen el objetivo, ese es el
    que deja pasar mas phishing, es decir el de mayor recall.
    """
    viables = [(t, tpr, fpr) for t, tpr, fpr in pts
               if tpr > 0 and precision_en_prevalencia(tpr, fpr, pi) >= objetivo]
    return min(viables, key=lambda x: x[0]) if viables else None


def main():
    pi = float(sys.argv[1]) if len(sys.argv) > 1 else PREVALENCIA_DEFECTO
    filtro = sys.argv[2] if len(sys.argv) > 2 else None

    ruta_contrato = SALIDA / "contrato_phishing_email.json"
    if not ruta_contrato.exists():
        raise SystemExit("Ejecuta train_phishing_email.py primero.")
    contrato = json.loads(ruta_contrato.read_text(encoding="utf-8"))

    # Cada algoritmo pudo quedarse con un conjunto distinto de
    # caracteristicas durante la ablacion, asi que se leen por modelo.
    cols_por_modelo = {k: v["caracteristicas"]
                       for k, v in contrato["metricas"].items()
                       if "caracteristicas" in v}

    print(f"Prevalencia objetivo: {pi:.2%}")
    print("Ajustala con la que midas en tu laboratorio.\n")
    print("Cargando corpus...")
    _, _, _, eb2 = cargar_corpus()
    print()
    X, y = matriz(eb2, "externo B2")
    print(f"\n  prevalencia del corpus de evaluacion: {y.mean():.1%}")
    print(f"  los umbrales se trasladan a {pi:.2%}\n")

    salida = {}
    for nombre in ("random_forest", "svm", "xgboost"):
        if filtro and nombre != filtro:
            continue
        ruta = SALIDA / f"phishing_email_{nombre}.joblib"
        if not ruta.exists():
            continue

        modelo = load(ruta)
        cols = cols_por_modelo.get(nombre, list(X.columns))
        pts = curva(y, proba_de(modelo, X[cols]))

        print(f"{'=' * 72}\n{nombre.upper()}  ({len(cols)} caracteristicas)")
        print(f"  {'nivel':8s}{'umbral':>10s}{'recall':>9s}{'precision':>11s}"
              f"{'FPR':>9s}{'alertas/1000':>14s}{'de ellas reales':>18s}")

        niveles = {}
        for etq, objetivo in NIVELES:
            r = umbral_para(pts, pi, objetivo)
            if r is None:
                print(f"  {etq:8s}{'---':>10s}   no alcanzable a esta prevalencia")
                niveles[etq] = None
                continue
            t, tpr, fpr = r
            p = precision_en_prevalencia(tpr, fpr, pi)
            # Volumen esperado en un lote de LOTE correos.
            esperadas = LOTE * (pi * tpr + (1 - pi) * fpr)
            reales = LOTE * pi * tpr
            print(f"  {etq:8s}{t:>10.4f}{tpr:>9.4f}{p:>11.4f}{fpr:>9.3%}"
                  f"{esperadas:>14.1f}{reales:>18.1f}")
            niveles[etq] = {"umbral": round(t, 6), "recall": round(tpr, 4),
                            "precision_esperada": round(p, 4),
                            "fpr": round(fpr, 5),
                            "alertas_por_1000": round(esperadas, 2),
                            "verdaderas_por_1000": round(reales, 2)}

        alto, bajo = niveles.get("alto"), niveles.get("bajo")
        if alto:
            print(f"\n  Severidad ALTA: {alto['alertas_por_1000']:.1f} "
                  f"notificaciones por cada 1000 correos, "
                  f"{alto['precision_esperada']:.0%} de ellas reales")
        if bajo:
            print(f"  Cobertura total (cualquier nivel): "
                  f"{bajo['recall']:.1%} del phishing entrante")

        # Si los tres niveles caen en el mismo umbral, el esquema de
        # severidad pierde sentido y conviene revisar la curva.
        us = [v["umbral"] for v in niveles.values() if v]
        if len(us) > 1 and (max(us) - min(us)) < 1e-4:
            print("\n  [!] Los tres niveles cayeron en el mismo umbral.")
            print("      Revisa la curva PR o la prevalencia indicada.")

        salida[nombre] = niveles
        print()

    destino = SALIDA / "umbrales_severidad.json"
    destino.write_text(json.dumps(
        {"prevalencia": pi,
         "objetivos_precision": dict(NIVELES),
         "nota": "Umbrales derivados de la curva PR del corpus de evaluacion "
                 "y trasladados a la prevalencia indicada. Recalcular con la "
                 "prevalencia real del entorno antes de operar.",
         "modelos": salida}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Guardado en {destino}")
    print("predict_phishing_email.py lo lee automaticamente si existe.")


if __name__ == "__main__":
    main()