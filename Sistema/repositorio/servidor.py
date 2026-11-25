"""
Servidor HTTP minimo de ThreatLens.

Expone el historico de alertas que vive en MongoDB a traves de un unico
endpoint, /api/alertas, que el dashboard consume. Por dentro solo llama al
repositorio: toda la logica de datos esta en repositorio.py; aqui solo se
traduce el resultado a una respuesta HTTP en JSON.
"""
import os

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify
from repositorio import Repositorio

app = Flask(__name__)

# Un solo repositorio para todo el proceso. MongoClient es seguro de
# compartir entre peticiones, asi que no se abre una conexion por request.
repo = Repositorio()


@app.get("/api/alertas")
def api_alertas():
    # Devuelve el historico completo, mas recientes primero, con la misma
    # forma que hoy tienen los JSON estaticos. jsonify arma la respuesta
    # HTTP con el encabezado application/json correcto.
    alertas = repo.obtener_alertas(limite=500)
    return jsonify(alertas)


if __name__ == "__main__":
    # debug=True recarga al guardar y muestra los errores en el navegador.
    # Es solo para desarrollo local.
    app.run(port=5000, debug=True)