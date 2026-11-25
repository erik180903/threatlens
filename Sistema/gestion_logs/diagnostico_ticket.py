# diagnostico_ticket.py
import os, requests, msal
from dotenv import load_dotenv
load_dotenv()

TENANT = os.environ["TENANT_ID"]
CLIENT = os.environ["CLIENT_ID"]
SECRET = os.environ["CLIENT_SECRET"]

# Token app-only (client credentials) para la API de Defender for Endpoint
app = msal.ConfidentialClientApplication(
    CLIENT,
    authority="https://login.microsoftonline.com/" + TENANT,
    client_credential=SECRET,
)
res = app.acquire_token_for_client(
    scopes=["https://api.securitycenter.microsoft.com/.default"]
)
if "access_token" not in res:
    print("ERROR token:", res.get("error"), "|", res.get("error_description"))
    raise SystemExit(1)
cab = {"Authorization": "Bearer " + res["access_token"],
       "Content-Type": "application/json"}

def request_id(r):
    for k in ("request-id", "client-request-id", "x-ms-correlation-request-id"):
        if k in r.headers:
            return k + "=" + r.headers[k]
    return "(sin request-id)"

print("===== PREGUNTA 1: tres consultas =====")
for q in ["print x=1", "AlertInfo | take 1", "DeviceInfo | take 1"]:
    r = requests.post(
        "https://api.securitycenter.microsoft.com/api/advancedqueries/run",
        headers=cab, json={"Query": q})
    print("\n--- Consulta:", q)
    print("HTTP:", r.status_code, "|", request_id(r))
    print("Cuerpo:", r.text[:800])

print("\n===== PREGUNTA 2: GET /api/machines =====")
r = requests.get("https://api.securitycenter.microsoft.com/api/machines", headers=cab)
print("HTTP:", r.status_code, "|", request_id(r))
try:
    print("Dispositivos devueltos:", len(r.json().get("value", [])))
except Exception:
    pass
print("Cuerpo:", r.text[:500])