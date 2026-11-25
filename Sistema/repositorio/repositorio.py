"""
Repositorio de datos de ThreatLens (MongoDB).

El modelo de colecciones del protocolo (Figura 4 / Codigo 1) define que cada
registro es un EVENTO PROCESADO COMPLETO. Por eso el repositorio usa una sola
coleccion, 'eventos', donde cada documento guarda el crudo normalizado, las
features, el resultado del modelo y la alerta generada:

    {
      "event_id": "...",
      "timestamp": datetime,
      "device_info": { "device_id", "hostname", "ip_address", "user" },
      "log": { "event_type": "phishing|acceso_remoto|malware", ... },
      "analysis_result": { ... },
      "alert": { ... }
    }

Sirve de repositorio historico: permite consultar por rango de fechas, por
equipo y por tipo de amenaza (RF20, RF22).
"""
import os
from pymongo import MongoClient, DESCENDING

NOMBRE_BD = "threatlens"
NOMBRE_COLECCION = "alertas"
TIPOS = ("phishing", "acceso_remoto", "malware")


class Repositorio:
    def __init__(self, cadena=None, cliente=None):
        # La conexion a MongoDB. En produccion la cadena viene de la variable
        # de entorno MONGODB_URI (nunca se escribe en el codigo ni se sube al
        # repo). El parametro 'cliente' solo se usa en las pruebas, para
        # inyectar una base simulada.
        if cliente is not None:
            self.cliente = cliente
        else:
            if cadena is None:
                cadena = os.environ["MONGODB_URI"]
            self.cliente = MongoClient(cadena)

        self.bd = self.cliente[NOMBRE_BD]
        self.alertas = self.bd[NOMBRE_COLECCION]

    def crear_indices(self):
        # id unico evita duplicados: generar_id (contrato_alerta.py) es
        # determinista a proposito, para que reprocesar una deteccion no
        # guarde la alerta dos veces. Los otros tres aceleran las consultas
        # tipicas del historico: por fecha, por equipo y por tipo.
        self.alertas.create_index("id", unique=True)
        self.alertas.create_index([("fecha", DESCENDING)])
        self.alertas.create_index("equipo")
        self.alertas.create_index("tipo_amenaza")

    def guardar_alerta(self, alerta):
        # Inserta la alerta; si ya existe una con el mismo id, la reemplaza
        # (upsert). Asi reprocesar una ventana que se traslapa no duplica.
        clave = {"id": alerta["id"]}
        self.alertas.replace_one(clave, alerta, upsert=True)
        return alerta["id"]

    def consultar_alertas(self, desde=None, hasta=None, equipo=None, tipo=None, limite=200):
        # Construye el filtro con solo los criterios que vengan dados.
        filtro = {}

        # Rango de fechas sobre el campo 'fecha'. Como estan en ISO 8601,
        # comparar las cadenas da directamente el orden cronologico.
        if desde is not None or hasta is not None:
            rango = {}
            if desde is not None:
                rango["$gte"] = desde
            if hasta is not None:
                rango["$lte"] = hasta
            filtro["fecha"] = rango

        if equipo is not None:
            filtro["equipo"] = equipo

        if tipo is not None:
            filtro["tipo_amenaza"] = tipo

        cursor = (
            self.alertas.find(filtro, {"_id": 0})
            .sort("fecha", DESCENDING)
            .limit(limite)
        )
        return list(cursor)

    def obtener_alertas(self, limite=200):
        # Para el dashboard: todas las alertas, mas recientes primero, con la
        # forma exacta que el frontend ya consume. La proyeccion {"_id": 0}
        # quita el identificador interno de MongoDB para que el JSON quede
        # igual que los archivos estaticos de hoy.
        cursor = (
            self.alertas.find({}, {"_id": 0})
            .sort("fecha", DESCENDING)
            .limit(limite)
        )
        return list(cursor)

    def cerrar(self):
        self.cliente.close()