"""
Enganche para alertas nuevas (actividad 24, flujo en vivo).

Cuando el sistema produce una alerta (un detector la crea con nueva_alerta),
esta funcion le genera las recomendaciones con Gemini y la guarda en la base.
Es el unico punto por el que pasa cada alerta nueva antes de quedar persistida.

Robusto a fallos del API: si Gemini no responde (saturacion/limite), la alerta
se guarda igual con recomendaciones en None, y generar_todas.py las rellena
despues. Asi una alerta NUNCA se pierde por un fallo del API.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "repositorio"))

from repositorio import Repositorio
from respuesta import generar_recomendaciones


def procesar_alerta(alerta, repo=None, cliente=None):
    # Si no se pasa un repositorio/cliente, se crea uno propio y se cierra al
    # final. En un flujo que procesa muchas alertas conviene pasar los mismos
    # para reutilizar la conexion y el cliente.
    repo_propio = repo is None
    if repo_propio:
        repo = Repositorio()

    try:
        alerta["recomendaciones"] = generar_recomendaciones(alerta, cliente=cliente)
    except Exception as e:
        print(f"[respuesta] sin recomendaciones para {alerta.get('id')}: {type(e).__name__}")
        alerta["recomendaciones"] = None

    repo.guardar_alerta(alerta)

    if repo_propio:
        repo.cerrar()
    return alerta