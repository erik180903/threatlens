"""
Pre-genera las recomendaciones de todas las alertas que aun no las tienen y
las guarda en la base (MongoDB). Idempotente: solo procesa las que tienen
'recomendaciones' vacio, asi que re-correrlo retoma donde quedo.

Maneja el limite de cuota del tier gratuito (429 RESOURCE_EXHAUSTED):
cuando lo topa, espera a que se libere la ventana por minuto y reintenta.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "repositorio"))

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / "repositorio" / ".env")

from google.genai import errors
from repositorio import Repositorio
from respuesta import generar_recomendaciones

PAUSA = 1          # segundos entre alertas (ritmo base)
ESPERA_429 = 60    # segundos a esperar cuando topa el limite por minuto
MAX_ESPERAS = 5    # cuantas veces esperar por una misma alerta antes de rendirse


def es_429(e):
    return getattr(e, "code", None) == 429 or "RESOURCE_EXHAUSTED" in str(e)


def main():
    repo = Repositorio()
    alertas = repo.obtener_alertas(limite=100000)
    pendientes = [a for a in alertas if not a.get("recomendaciones")]
    print(f"alertas en la base: {len(alertas)} | sin recomendaciones: {len(pendientes)}")

    hechas = 0
    errores = 0
    for i, alerta in enumerate(pendientes, 1):
        esperas = 0
        while True:
            try:
                rec = generar_recomendaciones(alerta)
                alerta["recomendaciones"] = rec
                repo.guardar_alerta(alerta)
                hechas += 1
                print(f"[{i}/{len(pendientes)}] {alerta['id']}: {len(rec['lista'])} recomendaciones")
                break
            except errors.ClientError as e:
                if es_429(e) and esperas < MAX_ESPERAS:
                    esperas += 1
                    print(f"[{i}/{len(pendientes)}] limite de cuota; espera {ESPERA_429}s ({esperas}/{MAX_ESPERAS})...")
                    time.sleep(ESPERA_429)
                    continue   # reintenta la MISMA alerta
                errores += 1
                print(f"[{i}/{len(pendientes)}] {alerta['id']}: ERROR {type(e).__name__}: {str(e)[:60]}")
                break
            except Exception as e:
                errores += 1
                print(f"[{i}/{len(pendientes)}] {alerta['id']}: ERROR {type(e).__name__}: {str(e)[:60]}")
                break
        time.sleep(PAUSA)

    print(f"\nListo. Generadas {hechas}, errores {errores}.")
    repo.cerrar()


if __name__ == "__main__":
    main()