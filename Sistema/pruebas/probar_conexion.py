import sys
from pathlib import Path

# repositorio.py y el .env viven en Sistema/repositorio/ (carpeta hermana)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "repositorio"))

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / "repositorio" / ".env")

from repositorio import Repositorio

repo = Repositorio()
repo.crear_indices()
print("conectado; alertas en la base:", repo.alertas.count_documents({}))
repo.cerrar()