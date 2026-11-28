"""
Prueba del repositorio con una base simulada (mongomock), sin tocar Atlas.

Verifica el contrato del repositorio contra la estructura real de alerta
(contrato_alerta.py): guardar por 'id', recuperar para el dashboard sin el
'_id' de Mongo y ordenadas por fecha, consultar por tipo/equipo/fecha, y que
reprocesar no duplique.

Se corre con:  python probar_repositorio.py
"""
import sys
from pathlib import Path

# repositorio.py vive en Sistema/repositorio/ (carpeta hermana)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "repositorio"))

import mongomock

from repositorio import Repositorio


# Tres alertas de ejemplo, una por vector, con la forma de nivel superior
# que define el contrato. Fechas distintas para probar el orden.
ALERTAS_EJEMPLO = [
    {
        "id": "alert-aaa111",
        "tipo_amenaza": "phishing",
        "nivel_severidad": "medio",
        "descripcion": "Phishing de prueba",
        "equipo": "PC-GERENCIA",
        "fecha": "2026-11-08T21:34:59",
        "estado": "nueva",
        "resultado_analisis": {"origen_deteccion": "modelo+regla", "es_malicioso": True},
    },
    {
        "id": "alert-bbb222",
        "tipo_amenaza": "acceso_remoto",
        "nivel_severidad": "alto",
        "descripcion": "Fuerza bruta de prueba",
        "equipo": "SRV-CONTA",
        "fecha": "2026-11-09T10:00:00",
        "estado": "nueva",
        "resultado_analisis": {"origen_deteccion": "regla", "es_malicioso": True},
    },
    {
        "id": "alert-ccc333",
        "tipo_amenaza": "malware",
        "nivel_severidad": "bajo",
        "descripcion": "Proceso sospechoso de prueba",
        "equipo": "PC-RECEPCION",
        "fecha": "2026-11-07T08:15:00",
        "estado": "nueva",
        "resultado_analisis": {"origen_deteccion": "modelo", "es_malicioso": True},
    },
]


def main():
    # cliente simulado: no se conecta a ninguna base real.
    repo = Repositorio(cliente=mongomock.MongoClient())
    repo.crear_indices()

    # 1. Guardar las tres alertas.
    for alerta in ALERTAS_EJEMPLO:
        repo.guardar_alerta(alerta)
    total = repo.alertas.count_documents({})
    print("guardadas:", total, "(esperado 3)")

    # 2. obtener_alertas: forma que consume el dashboard.
    para_dashboard = repo.obtener_alertas()
    sin_id = "_id" not in para_dashboard[0]
    ordenadas = all(
        para_dashboard[i]["fecha"] >= para_dashboard[i + 1]["fecha"]
        for i in range(len(para_dashboard) - 1)
    )
    print("obtener_alertas:", len(para_dashboard), "| sin _id:", sin_id, "| orden desc:", ordenadas)

    # 3. Consultas por criterio.
    print("por tipo phishing:", len(repo.consultar_alertas(tipo="phishing")), "(esperado 1)")
    print("por equipo SRV-CONTA:", len(repo.consultar_alertas(equipo="SRV-CONTA")), "(esperado 1)")
    print("desde 2026-11-08:", len(repo.consultar_alertas(desde="2026-11-08")), "(esperado 2)")

    # 4. Idempotencia: volver a guardar las mismas no duplica.
    for alerta in ALERTAS_EJEMPLO:
        repo.guardar_alerta(alerta)
    print("tras recargar:", repo.alertas.count_documents({}), "(esperado 3)")

    repo.cerrar()
    print("OK")


if __name__ == "__main__":
    main()