import os
import time
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / "repositorio" / ".env")

from google import genai
from google.genai import types
import respuesta

alerta = {
    "id": "alert-1ba542ea4ffd",
    "tipo_amenaza": "acceso_remoto",
    "nivel_severidad": "alto",
    "descripcion": "Fuerza bruta — 180 autenticaciones fallidas contra SRV-CONTA",
    "equipo": "SRV-CONTA",
    "motivos": ["180 autenticaciones fallidas contra SRV-CONTA en 5 min (umbral 100)"],
    "mitre": [{"id": "T1110", "nombre": "Brute Force"}],
    "resultado_analisis": {"evento": {
        "equipo": "SRV-CONTA", "cuenta": "administrador",
        "origen": "192.168.1.80", "intentos_fallidos": 180,
        "tabla_origen": "DeviceLogonEvents",
    }},
}

cliente = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
prompt = "Genera las recomendaciones para la siguiente alerta:\n\n" + respuesta._contexto(alerta)


def config_con(**thinking):
    return types.GenerateContentConfig(
        system_instruction=respuesta.INSTRUCCION_SISTEMA,
        response_mime_type="application/json",
        response_schema=respuesta.Recomendaciones,
        temperature=0.3,
        **thinking,
    )


configs = {
    "thinking_level=low": config_con(thinking_config=types.ThinkingConfig(thinking_level="low")),
    "thinking_budget=0":  config_con(thinking_config=types.ThinkingConfig(thinking_budget=0)),
    "sin thinking_config (default)": config_con(),
}

for nombre, cfg in configs.items():
    print(f"\n== {nombre} ==")
    try:
        for i in range(3):
            t0 = time.perf_counter()
            r = cliente.models.generate_content(
                model=respuesta.MODELO, contents=prompt, config=cfg
            )
            t1 = time.perf_counter()
            n = len(respuesta.Recomendaciones.model_validate_json(r.text).lista)
            print(f"  llamada {i + 1}: {t1 - t0:5.2f} s  ({n} recomendaciones)")
    except Exception as e:
        print(f"  (falló: {type(e).__name__}: {str(e)[:90]})")