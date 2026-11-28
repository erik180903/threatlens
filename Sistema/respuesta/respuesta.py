"""
Modulo de respuesta de ThreatLens (actividad 24).

Toma una alerta ya detectada y genera, con la API de Gemini, una lista de
recomendaciones accionables adaptadas a esa alerta. Las recomendaciones se
anclan en los datos reales de la alerta (vector, motivos, tecnicas MITRE,
equipo) para que sean concretas y no genericas. El resultado tiene la forma
{ "lista": [...] }, que es la que ya consume el componente Recomendaciones.
"""
import os
import time
from google.genai import errors


from google import genai
from google.genai import types
from pydantic import BaseModel

MODELO = "gemini-3.5-flash-lite"

INSTRUCCION_SISTEMA = (
    "Eres un asesor de ciberseguridad para una pequena o mediana empresa "
    "mexicana que NO cuenta con personal de TI ni con un tecnico a quien "
    "recurrir. Tus recomendaciones van dirigidas al personal general de la "
    "empresa, que no tiene conocimientos tecnicos. "
    "Regla principal: cada recomendacion debe ser una accion que esa misma "
    "persona pueda realizar POR SI SOLA, con lo que tiene a la mano y sin "
    "conocimientos tecnicos. NO recomiendes contactar, llamar ni pedir ayuda a "
    "un tecnico, especialista, proveedor o area de TI; el valor del sistema es "
    "que la persona sepa exactamente que hacer por su cuenta. "
    "Usa lenguaje claro y cotidiano, sin jerga; si un termino tecnico es "
    "inevitable, explicalo en pocas palabras. Ordena de la mas urgente a la "
    "menos urgente: primero contener el problema, luego proteger las cuentas y "
    "equipos, y por ultimo evitar que se repita. Cada recomendacion es una sola "
    "oracion. Te basas unicamente en los datos de la alerta; no inventas hechos. "
    "Entregas entre 3 y 5 recomendaciones."
)


class Recomendaciones(BaseModel):
    lista: list[str]


def _contexto(alerta):
    mitre = alerta.get("mitre") or []
    tecnicas = ", ".join(f"{m.get('id')} ({m.get('nombre')})" for m in mitre)
    motivos = alerta.get("motivos") or []
    evento = (alerta.get("resultado_analisis") or {}).get("evento") or {}

    lineas = [
        f"Tipo de amenaza: {alerta.get('tipo_amenaza')}",
        f"Severidad: {alerta.get('nivel_severidad')}",
        f"Equipo afectado: {alerta.get('equipo')}",
        f"Descripcion: {alerta.get('descripcion')}",
        f"Tecnicas MITRE: {tecnicas or 'ninguna'}",
        "Motivos de la deteccion:",
    ]
    for m in motivos:
        lineas.append(f"  - {m}")
    if evento:
        lineas.append("Detalles del evento:")
        for k, v in evento.items():
            if v not in (None, "", 0, [], {}):
                lineas.append(f"  - {k}: {v}")
    return "\n".join(lineas)


def generar_recomendaciones(alerta, cliente=None, reintentos=3):
    if cliente is None:
        cliente = genai.Client(
            api_key=os.environ["GEMINI_API_KEY"],
            http_options=types.HttpOptions(
                timeout=60000,  # 60 s maximo por peticion (en milisegundos)
                retry_options=types.HttpRetryOptions(attempts=1),  # sin reintentos internos
            ),
        )

    prompt = "Genera las recomendaciones para la siguiente alerta:\n\n" + _contexto(alerta)
    config = types.GenerateContentConfig(
        system_instruction=INSTRUCCION_SISTEMA,
        response_mime_type="application/json",
        response_schema=Recomendaciones,
        temperature=0.3,
    )

    for intento in range(reintentos):
        try:
            respuesta = cliente.models.generate_content(
                model=MODELO, contents=prompt, config=config
            )
            datos = Recomendaciones.model_validate_json(respuesta.text)
            return {"lista": datos.lista}
        except errors.ServerError:
            # 503/UNAVAILABLE: el modelo esta saturado. Espera y reintenta.
            if intento < reintentos - 1:
                time.sleep(2 ** intento)   # 1 s, luego 2 s, luego 4 s
                continue
            raise