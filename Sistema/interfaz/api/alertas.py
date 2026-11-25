"""
Funcion serverless de Vercel: GET /api/alertas

Vercel convierte cada .py de la carpeta api/ en una funcion y lo sirve en su
ruta: este archivo responde /api/alertas.

Es autocontenida a proposito: en Vercel la funcion solo empaqueta archivos
dentro de la raiz del proyecto (Sistema/interfaz), y repositorio.py vive
fuera. Asi que aqui se repite la unica consulta que necesita, equivalente a
Repositorio.obtener_alertas(): todas las alertas, mas recientes primero, sin
el _id interno de Mongo.
"""
import os
import json
from http.server import BaseHTTPRequestHandler

from pymongo import MongoClient, DESCENDING

# Un solo cliente por instancia de la funcion. Mientras siga "caliente",
# Vercel reutiliza el proceso y con el esta conexion, en vez de abrir una
# nueva en cada peticion.
_cliente = None


def _coleccion():
    global _cliente
    if _cliente is None:
        _cliente = MongoClient(os.environ["MONGODB_URI"])
    return _cliente["threatlens"]["alertas"]


def leer_alertas(limite=500):
    cursor = (
        _coleccion()
        .find({}, {"_id": 0})
        .sort("fecha", DESCENDING)
        .limit(limite)
    )
    return list(cursor)


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            cuerpo = json.dumps(leer_alertas()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(cuerpo)
        except Exception as e:
            cuerpo = json.dumps({"error": str(e)}).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(cuerpo)