from dotenv import load_dotenv
load_dotenv()

from repositorio import Repositorio

repo = Repositorio()
repo.crear_indices()
print("conectado; alertas en la base:", repo.alertas.count_documents({}))
repo.cerrar()