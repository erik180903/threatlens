"""
Carga a MongoDB las alertas que hoy viven como archivos JSON estaticos en
public/datos/. Es un script de poblado: se corre una vez (o cada vez que se
regeneran los JSON) para que la base tenga las alertas que el dashboard
leera desde /api/alertas en lugar de los archivos.

Es idempotente: cada alerta se guarda por su 'id' con upsert, asi que
correrlo dos veces no duplica nada.
"""
import os
import json

from dotenv import load_dotenv
load_dotenv()

from repositorio import Repositorio

# Carpeta donde el frontend sirve los JSON. Desde Sistema/repositorio/ hay
# que subir un nivel y entrar a interfaz/public/datos/.
CARPETA = os.path.join("..", "interfaz", "public", "datos")

ARCHIVOS = [
    "alertas_phishing.json",
    "alertas_accesos.json",
    "alertas_malware.json",
]

repo = Repositorio()
repo.crear_indices()

total = 0
for nombre in ARCHIVOS:
    ruta = os.path.join(CARPETA, nombre)
    with open(ruta, encoding="utf-8") as f:
        alertas = json.load(f)

    for alerta in alertas:
        repo.guardar_alerta(alerta)
        total = total + 1

    print(f"{nombre}: {len(alertas)} alertas")

print(f"total procesadas: {total}")
print("alertas en la base:", repo.alertas.count_documents({}))
repo.cerrar()