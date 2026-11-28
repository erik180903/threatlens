import csv
import sys
from pathlib import Path

# normalizador.py vive en Sistema/normalizacion/ (carpeta hermana)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalizacion"))

from normalizador import normaliza, CAMPOS_FECHA

MESES = {
    "ene": "01", "feb": "02", "mar": "03", "abr": "04",
    "may": "05", "jun": "06", "jul": "07", "ago": "08",
    "sep": "09", "sept": "09", "oct": "10", "nov": "11", "dic": "12",
}


def fecha_es_a_iso(texto):
    if not texto:
        return texto
    try:
        limpio = texto.replace(".", "").replace(" de ", " ")
        partes = limpio.split()
        dia = partes[0].zfill(2)
        mes = MESES[partes[1].lower()]
        anio = partes[2]
        hora = partes[3]
        return anio + "-" + mes + "-" + dia + "T" + hora
    except (KeyError, IndexError):
        return texto


def cargar_csv(ruta):
    filas = []
    with open(ruta, encoding="utf-8-sig") as f:
        for fila in csv.DictReader(f):
            cruda = dict(fila)
            for campo in CAMPOS_FECHA:
                valor = cruda.get(campo)
                if valor:
                    cruda[campo] = fecha_es_a_iso(valor)
            filas.append(cruda)
    return filas


if __name__ == "__main__":
    ruta = "EventosEntraID.csv"   # <-- ajusta a tu ruta

    crudas = cargar_csv(ruta)
    limpias = normaliza(crudas)

    print("Filas:", len(crudas), "->", len(limpias))

    equipos_antes = set()
    for fila in crudas:
        nombre = fila.get("DeviceName")
        if nombre:
            equipos_antes.add(nombre)

    equipos_despues = set()
    for fila in limpias:
        nombre = fila.get("DeviceName")
        if nombre:
            equipos_despues.add(nombre)

    print("Equipos distintos:", len(equipos_antes), "->", len(equipos_despues))
    print("  antes: ", sorted(equipos_antes))
    print("  despues:", sorted(equipos_despues))

    for fila in limpias:
        if fila.get("DeviceName") == "srv-archivos":
            print("Ejemplo reconciliado -> cuenta:", fila.get("AccountName"),
                  "| fecha:", fila.get("Timestamp"))
            break