from pathlib import Path
from dotenv import load_dotenv

# El .env (con GEMINI_API_KEY y MONGODB_URI) vive en Sistema/repositorio/
load_dotenv(Path(__file__).resolve().parent.parent / "repositorio" / ".env")

from respuesta import generar_recomendaciones

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

res = generar_recomendaciones(alerta)
print("Recomendaciones generadas:\n")
for i, r in enumerate(res["lista"], 1):
    print(f"{i}. {r}")