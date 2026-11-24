from datetime import datetime

# Campos de texto que se doblan a minúsculas porque participan
# en comparaciones o en la construcción de claves.
CAMPOS_MINUSCULAS = (
    "DeviceName",
    "FileName",
    "InitiatingProcessFileName",
    "AccountName",
    "AccountDomain",
    "InitiatingProcessAccountName",
    "InitiatingProcessAccountDomain",
    "RemoteDeviceName",
)

# Equipos que cambiaron de nombre. La llave es el nombre viejo
# (en minúsculas), el valor es el nombre definitivo.
EQUIVALENCIAS_EQUIPO = {
    "desktop-rqp6r8m": "srv-archivos",
}

# Campos de fecha que se normalizan a ISO 8601.
CAMPOS_FECHA = (
    "Timestamp",
    "ProcessCreationTime",
    "InitiatingProcessCreationTime",
    "InitiatingProcessParentCreationTime",
)

def normaliza_caso(fila):
    copia = dict(fila)
    for campo in CAMPOS_MINUSCULAS:
        valor = copia.get(campo)
        if valor is None:
            continue
        texto = str(valor)
        copia[campo] = texto.lower()
    return copia

def normaliza_identidad(fila):
    copia = dict(fila)
    cuenta = copia.get("AccountName")
    if cuenta is None:
        cuenta = copia.get("AccountUpn")
    if cuenta is None:
        return copia
    cuenta = str(cuenta).lower()
    if "@" in cuenta:
        partes = cuenta.split("@")
        cuenta = partes[0]
    copia["AccountName"] = cuenta
    return copia

def normaliza_equipo(fila):
    copia = dict(fila)
    for campo in ("DeviceName", "RemoteDeviceName"):
        valor = copia.get(campo)
        if valor is None:
            continue
        nombre = str(valor).lower()
        if nombre in EQUIVALENCIAS_EQUIPO:
            nombre = EQUIVALENCIAS_EQUIPO[nombre]
        copia[campo] = nombre
    return copia

def es_espurio(fila):
    tipo = fila.get("LogonType")
    if tipo != "RemoteInteractive":
        return False
    ip = fila.get("RemoteIP")
    if ip == "0.0.0.0":
        return True
    return False

def normaliza_fecha(valor):
    if valor is None:
        return None
    texto = str(valor).strip()
    texto = texto.replace("Z", "+00:00")
    momento = datetime.fromisoformat(texto)
    return momento.strftime("%Y-%m-%dT%H:%M:%S")

def normaliza_fechas(fila):
    copia = dict(fila)
    for campo in CAMPOS_FECHA:
        valor = copia.get(campo)
        if valor is None:
            continue
        copia[campo] = normaliza_fecha(valor)
    return copia

def normaliza(filas):
    salida = []
    for fila in filas:
        limpia = normaliza_caso(fila)
        limpia = normaliza_identidad(limpia)
        limpia = normaliza_equipo(limpia)
        limpia = normaliza_fechas(limpia)
        if es_espurio(limpia):
            continue
        salida.append(limpia)
    return salida

if __name__ == "__main__":
    crudas = [
        {"DeviceName": "SRV-ARCHIVOS", "AccountName": "Jorge.Rios",
         "LogonType": "RemoteInteractive", "RemoteIP": "172.29.75.52",
         "Timestamp": "2026-11-19T21:00:47Z"},
        {"DeviceName": "DESKTOP-RQP6R8M",
         "AccountUpn": "jorge.rios@threatlenspt2upiita.onmicrosoft.com",
         "LogonType": "RemoteInteractive", "RemoteIP": "172.29.75.52",
         "Timestamp": "2026-11-19T20:56:48.000Z"},
        {"DeviceName": "PC-CONTABILIDAD", "AccountName": "laura.mendez",
         "LogonType": "RemoteInteractive", "RemoteIP": "0.0.0.0",
         "Timestamp": "2026-11-19T18:30:00Z"},
    ]
    limpias = normaliza(crudas)
    print("Entraron:", len(crudas), "| Salieron:", len(limpias))
    for fila in limpias:
        print(fila["DeviceName"], "|", fila["AccountName"], "|", fila["Timestamp"])