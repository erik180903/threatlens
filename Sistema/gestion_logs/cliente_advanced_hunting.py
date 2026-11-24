import os
import requests
import msal
from dotenv import load_dotenv

load_dotenv()


class ClienteAdvancedHunting:
    def __init__(self):
        self.tenant_id = os.environ["TENANT_ID"]
        self.client_id = os.environ["CLIENT_ID"]
        self.client_secret = os.environ["CLIENT_SECRET"]
        self.token = None

    def autenticar(self):
        app = msal.PublicClientApplication(
            self.client_id,
            authority="https://login.microsoftonline.com/" + self.tenant_id,
        )
        ambitos = ["https://graph.microsoft.com/ThreatHunting.Read.All"]
        resultado = app.acquire_token_interactive(scopes=ambitos)
        if "access_token" not in resultado:
            print("Error de autenticación:")
            print(resultado)
            raise SystemExit(1)
        self.token = resultado["access_token"]
        return self.token

    def ejecutar_consulta(self, kql):
        if self.token is None:
            self.autenticar()
        url = "https://graph.microsoft.com/beta/security/runHuntingQuery"
        cabeceras = {
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json",
        }
        cuerpo = {"Query": kql}
        respuesta = requests.post(url, headers=cabeceras, json=cuerpo)
        if respuesta.status_code != 200:
            print("Código:", respuesta.status_code)
            print("Respuesta de la API:")
            print(respuesta.text)
        respuesta.raise_for_status()
        datos = respuesta.json()
        resultados = datos["results"]
        return resultados

if __name__ == "__main__":
    cliente = ClienteAdvancedHunting()
    cliente.autenticar()
    consulta = "DeviceProcessEvents | limit 5"
    filas = cliente.ejecutar_consulta(consulta)
    print("Filas recibidas:", len(filas))
    for fila in filas:
        print(fila)