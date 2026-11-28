# Pruebas del sistema

Scripts para probar los modulos de `Sistema/` de forma aislada. Cada uno
agrega al `sys.path` la carpeta del modulo que prueba, asi que se corren
desde aqui con `python <archivo>`.

- `probarrepositorio.py` — prueba el repositorio con una base simulada
  (mongomock), sin tocar Atlas. No necesita credenciales.
- `probar_conexion.py` — verifica la conexion real a MongoDB Atlas
  (lee `MONGODB_URI` de `Sistema/repositorio/.env`).
- `probar_respuesta.py` — genera recomendaciones de una alerta de ejemplo
  con la API de Gemini (lee `GEMINI_API_KEY` de `Sistema/repositorio/.env`).
- `probar_con_csv.py` — prueba la normalizacion sobre un CSV exportado.

Las pruebas de cada modelo (phishing, accesos, malware) viven dentro de su
propia carpeta `Entrenamiento_*`, junto al codigo de entrenamiento.
