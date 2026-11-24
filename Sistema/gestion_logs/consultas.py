# Consultas KQL de los vectores de amenaza de ThreatLens.
# Cada constante es la consulta que el conector del modulo de gestion de logs
# ejecuta periodicamente contra Advanced Hunting. No todas son del mismo tipo:
#   - ACCESO_REMOTO      : consolida las cuatro senales del vector con 'union'.
#   - ARCHIVOS_MALICIOSOS: calcula en AH el vector de 37 caracteristicas del modelo.
#   - PHISHING           : consulta de ALIMENTACION (no calcula caracteristicas;
#                          entrega campos crudos al extractor del backend).


# Consolida con 'union' las cuatro senales de accesos remotos: inicio remoto
# (RDP), conexion por puerto, uso de herramientas remotas y posible fuerza bruta.
ACCESO_REMOTO = r"""
let puertos_remotos = dynamic([22, 21, 23, 3389, 5900]);
let herramientas = dynamic(["mstsc.exe","ssh.exe","putty.exe","plink.exe",
                            "teamviewer.exe","anydesk.exe","psexec.exe",
                            "winrs.exe","vncviewer.exe","mobaxterm.exe"]);
union
(
    DeviceLogonEvents
    | where LogonType == "RemoteInteractive"
    | project Timestamp, DeviceName, AccountName, RemoteIP,
              Senal = "Inicio remoto (RDP)",
              Detalle = strcat(ActionType, " desde ", tostring(RemoteDeviceName))
),
(
    DeviceNetworkEvents
    | where RemotePort in (puertos_remotos) or LocalPort in (puertos_remotos)
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName, RemoteIP,
              Senal = "Conexion por puerto",
              Detalle = strcat(ActionType, " L:", tostring(LocalPort),
                               " R:", tostring(RemotePort), " via ", InitiatingProcessFileName)
),
(
    DeviceProcessEvents
    | where FileName in~ (herramientas)
    | project Timestamp, DeviceName, AccountName, RemoteIP = "",
              Senal = "Herramienta remota",
              Detalle = strcat(FileName, " (padre: ", InitiatingProcessFileName, ")")
),
(
    DeviceLogonEvents
    | where LogonType in ("RemoteInteractive", "Network")
    | summarize Intentos = count(), Fallos = countif(ActionType == "LogonFailed")
              by AccountName, DeviceName, RemoteIP, Ventana = bin(Timestamp, 5m)
    | where Fallos >= 5
    | project Timestamp = Ventana, DeviceName, AccountName, RemoteIP,
              Senal = "Posible fuerza bruta",
              Detalle = strcat(tostring(Intentos), " intentos, ", tostring(Fallos), " fallos en 5 min")
)
| order by Timestamp desc
"""

# Calcula en Advanced Hunting las 37 caracteristicas de features_proceso.py
# (extractor de referencia con el que se entreno el modelo de malware).
# Verificado 37/37 contra el extractor con validar_kql.py.
ARCHIVOS_MALICIOSOS = r"""
// ===========================================================================
// Vector de archivos maliciosos  -  extractor de 37 caracteristicas en KQL
// Reproduce features_proceso.py sobre DeviceProcessEvents de Advanced Hunting.
// Clave de instancia de proceso:  DeviceName|ProcessId|ProcessCreationTime
// Las caracteristicas del PADRE que usan su comando o su cuenta se calculan
// solo si el padre esta en la ventana (paridad con features_proceso.py).
// ===========================================================================
let VENTANA = 1d;
let procs =
    DeviceProcessEvents
    | where Timestamp > ago(VENTANA)
    | extend clave       = strcat(DeviceName, "|", tostring(ProcessId), "|", tostring(ProcessCreationTime)),
             clave_padre = strcat(DeviceName, "|", tostring(InitiatingProcessId), "|", tostring(InitiatingProcessCreationTime)),
             img  = tolower(tostring(FileName)),
             cmd  = tostring(ProcessCommandLine),
             pcmd = tostring(InitiatingProcessCommandLine),
             pimg = tolower(tostring(InitiatingProcessFileName)),
             ruta = tolower(replace_string(tostring(FolderPath), "/", "\\"));
// ---- quien tiene al padre dentro de la ventana ----
let claves = procs | distinct clave;
let presencia =
    procs
    | join kind=leftouter (claves | project clave_padre = clave, _pp = 1) on clave_padre
    | project clave, padre_presente = coalesce(_pp, 0);
// ---- entropia del comando propio ----
let ent_cmd =
    procs | project clave, cmd
    | mv-expand _c = extract_all(@"(?s)(.)", cmd) to typeof(string)
    | summarize _n = count() by clave, _c
    | summarize N = sum(_n), S = sum(_n * log2(todouble(_n))) by clave
    | project clave, cmd_entropia = log2(todouble(N)) - S / todouble(N);
// ---- entropia del comando del padre (SOLO si el padre esta en la ventana) ----
let ent_pcmd =
    procs
    | join kind=inner (claves | project clave_padre = clave) on clave_padre
    | project clave, pcmd
    | mv-expand _c = extract_all(@"(?s)(.)", pcmd) to typeof(string)
    | summarize _n = count() by clave, _c
    | summarize N = sum(_n), S = sum(_n * log2(todouble(_n))) by clave
    | project clave, padre_cmd_entropia = log2(todouble(N)) - S / todouble(N);
// ---- maximos del comando ----
let cmd_tmax =
    procs | project clave, cmd
    | mv-expand _t = extract_all(@"(\S+)", cmd) to typeof(string)
    | summarize cmd_token_max = max(strlen(_t)) by clave;
let cmd_b64 =
    procs | project clave, cmd
    | mv-expand _b = extract_all(@"([A-Za-z0-9+/]{50,}={0,2})", cmd) to typeof(string)
    | summarize cmd_b64_longitud = max(strlen(_b)) by clave;
// ---- rafaga: hermanos = otros hijos del mismo padre ----
let hermanos = procs | project clave_h = clave, clave_padre, t_h = Timestamp, img_h = img, cmd_h = cmd;
let raf_sib =
    procs
    | join kind=inner hermanos on clave_padre
    | summarize raf_hermanos_1s         = countif(clave_h != clave and t_h between (Timestamp - 1s .. Timestamp + 1s)),
                raf_hermanos_60s        = countif(clave_h != clave and t_h between (Timestamp - 60s .. Timestamp + 60s)),
                raf_n_imagenes_hermanos = dcountif(img_h, clave_h != clave and t_h between (Timestamp - 1s .. Timestamp + 1s)),
                _mismos_1s              = countif(clave_h != clave and img_h == img and t_h between (Timestamp - 1s .. Timestamp + 1s))
              by clave
    | project clave, raf_hermanos_1s, raf_hermanos_60s, raf_n_imagenes_hermanos,
              raf_prop_misma_imagen = iff(raf_hermanos_1s == 0, 0.0, todouble(_mismos_1s) / raf_hermanos_1s);
let raf_ips =
    procs
    | join kind=inner hermanos on clave_padre
    | where clave_h != clave and t_h between (Timestamp - 60s .. Timestamp + 60s)
    | mv-expand _ip = extract_all(@"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)", cmd_h) to typeof(string)
    | where isnotempty(_ip)
    | summarize raf_ips_hermanos = dcount(_ip) by clave;
let raf_dev =
    procs
    | join kind=inner (procs | project clave_e = clave, DeviceName, t_e = Timestamp) on DeviceName
    | summarize raf_eventos_equipo_60s = countif(t_e between (Timestamp - 60s .. Timestamp + 60s)) by clave;
// ---- linaje: hijos y nietos ----
let hijos_total = procs | summarize nietos_de_h = count() by clave_padre;
let hijos =
    procs
    | project clave_h = clave, cp_h = clave_padre, t_h = Timestamp, img_h = img
    | join kind=leftouter (hijos_total | project clave_h = clave_padre, nietos_de_h) on clave_h
    | project clave_h, cp_h, t_h, img_h, nietos_de_h = coalesce(nietos_de_h, 0);
let lin_child =
    procs
    | join kind=leftouter hijos on $left.clave == $right.cp_h
    | summarize lin_n_hijos          = countif(isnotempty(clave_h) and t_h between (Timestamp .. Timestamp + 60s)),
                lin_n_imagenes_hijos = dcountif(img_h, isnotempty(clave_h) and t_h between (Timestamp .. Timestamp + 60s)),
                lin_n_nietos         = sumif(nietos_de_h, isnotempty(clave_h) and t_h between (Timestamp .. Timestamp + 60s))
              by clave;
// ---- linaje: profundidad (climb iterativo, 10 niveles) ----
let ed = procs | project clave, clave_padre;
let lin_depth =
    procs
    | project clave, p1 = clave_padre
    | join kind=leftouter (ed | project p1 = clave, p2  = clave_padre, m1 = 1) on p1
    | join kind=leftouter (ed | project p2 = clave, p3  = clave_padre, m2 = 1) on p2
    | join kind=leftouter (ed | project p3 = clave, p4  = clave_padre, m3 = 1) on p3
    | join kind=leftouter (ed | project p4 = clave, p5  = clave_padre, m4 = 1) on p4
    | join kind=leftouter (ed | project p5 = clave, p6  = clave_padre, m5 = 1) on p5
    | join kind=leftouter (ed | project p6 = clave, p7  = clave_padre, m6 = 1) on p6
    | join kind=leftouter (ed | project p7 = clave, p8  = clave_padre, m7 = 1) on p7
    | join kind=leftouter (ed | project p8 = clave, p9  = clave_padre, m8 = 1) on p8
    | join kind=leftouter (ed | project p9 = clave, p10 = clave_padre, m9 = 1) on p9
    | join kind=leftouter (ed | project p10 = clave,                   m10 = 1) on p10
    | project clave, lin_profundidad = coalesce(m1,0)+coalesce(m2,0)+coalesce(m3,0)+coalesce(m4,0)+coalesce(m5,0)
                                      + coalesce(m6,0)+coalesce(m7,0)+coalesce(m8,0)+coalesce(m9,0)+coalesce(m10,0);
// ============================ ensamble final ============================
procs
| join kind=leftouter presencia on clave
| extend padre_presente = coalesce(padre_presente, 0)
| extend pcmd_ef = iff(padre_presente == 1, pcmd, ""),
         pcta_ef = iff(padre_presente == 1, tolower(tostring(InitiatingProcessAccountName)), ""),
         c_low   = tolower(tostring(AccountName))
| extend _n = max_of(strlen(cmd), 1)
| extend cmd_longitud      = strlen(cmd),
         cmd_n_tokens      = coalesce(array_length(extract_all(@"(\S+)", cmd)), 0),
         cmd_prop_no_alfa  = 1.0 - todouble(strlen(replace_regex(cmd, @"[^A-Za-z0-9\s]", ""))) / _n,
         cmd_prop_digitos  = todouble(strlen(replace_regex(cmd, @"[^0-9]", ""))) / _n,
         cmd_tiene_b64     = toint(cmd matches regex @"[A-Za-z0-9+/]{50,}={0,2}"),
         cmd_n_banderas    = coalesce(array_length(extract_all(@"((?:^|\s)[-/][A-Za-z][\w-]*)", cmd)), 0),
         cmd_n_ips         = array_length(set_union(extract_all(@"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)", cmd), dynamic([]))),
         cmd_tiene_url     = toint(cmd matches regex @"(?i)\b(?:https?://|ftp://|www\.)\S+"),
         cmd_tiene_unc     = toint(cmd matches regex @"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+"),
         cmd_n_comillas    = countof(cmd, '"') + countof(cmd, "'"),
         cmd_n_encadenados = countof(cmd, "|") + countof(cmd, "&&") + countof(cmd, ";") + countof(cmd, "&")
| extend ruta_profundidad    = countof(ruta, "\\"),
         ruta_longitud       = strlen(ruta),
         ruta_en_system32    = toint(ruta contains "\\system32\\"),
         ruta_en_sysnative   = toint(ruta contains "\\sysnative\\" or ruta contains "\\syswow64\\"),
         ruta_en_temporal    = toint(ruta contains "\\temp\\" or ruta contains "\\tmp\\" or ruta contains "\\appdata\\" or ruta contains "\\downloads\\" or ruta contains "\\users\\public\\" or ruta contains "\\programdata\\"),
         ruta_es_dispositivo = toint(ruta startswith "\\device\\" or ruta startswith "\\??\\")
| extend padre_es_interprete = toint(pimg in ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","msbuild.exe","installutil.exe","python.exe","bash.exe","cmstp.exe","forfiles.exe")),
         padre_es_ofimatica  = toint(pimg in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","firefox.exe","chrome.exe","iexplore.exe","msedge.exe")),
         padre_cmd_tiene_b64 = toint(pcmd_ef matches regex @"[A-Za-z0-9+/]{50,}={0,2}"),
         padre_cmd_longitud  = strlen(pcmd_ef)
| extend cta_es_sistema        = toint(c_low contains "system" or c_low contains "local service" or c_low contains "network service" or c_low contains "servicio"),
         cta_difiere_del_padre = toint(isnotempty(c_low) and isnotempty(pcta_ef) and c_low != pcta_ef)
| join kind=leftouter ent_cmd   on clave
| join kind=leftouter ent_pcmd  on clave
| join kind=leftouter cmd_tmax  on clave
| join kind=leftouter cmd_b64   on clave
| join kind=leftouter raf_sib   on clave
| join kind=leftouter raf_ips   on clave
| join kind=leftouter raf_dev   on clave
| join kind=leftouter lin_child on clave
| join kind=leftouter lin_depth on clave
| extend cmd_entropia            = coalesce(cmd_entropia, 0.0),
         padre_cmd_entropia      = coalesce(padre_cmd_entropia, 0.0),
         cmd_token_max           = coalesce(cmd_token_max, 0),
         cmd_b64_longitud        = coalesce(cmd_b64_longitud, 0),
         raf_hermanos_1s         = coalesce(raf_hermanos_1s, 0),
         raf_hermanos_60s        = coalesce(raf_hermanos_60s, 0),
         raf_n_imagenes_hermanos = coalesce(raf_n_imagenes_hermanos, 0),
         raf_prop_misma_imagen   = coalesce(raf_prop_misma_imagen, 0.0),
         raf_ips_hermanos        = coalesce(raf_ips_hermanos, 0),
         raf_eventos_equipo_60s  = coalesce(raf_eventos_equipo_60s, 0),
         lin_n_hijos             = coalesce(lin_n_hijos, 0),
         lin_n_imagenes_hijos    = coalesce(lin_n_imagenes_hijos, 0),
         lin_n_nietos            = coalesce(lin_n_nietos, 0),
         lin_profundidad         = coalesce(lin_profundidad, 0)
| project clave,
          cmd_longitud, cmd_entropia, cmd_n_tokens, cmd_token_max, cmd_prop_no_alfa, cmd_prop_digitos,
          cmd_tiene_b64, cmd_b64_longitud, cmd_n_banderas, cmd_n_ips, cmd_tiene_url, cmd_tiene_unc,
          cmd_n_comillas, cmd_n_encadenados,
          ruta_profundidad, ruta_longitud, ruta_en_system32, ruta_en_sysnative, ruta_en_temporal, ruta_es_dispositivo,
          padre_es_interprete, padre_es_ofimatica, padre_cmd_entropia, padre_cmd_tiene_b64, padre_cmd_longitud,
          lin_profundidad, lin_n_hijos, lin_n_imagenes_hijos, lin_n_nietos,
          raf_hermanos_1s, raf_hermanos_60s, raf_prop_misma_imagen, raf_n_imagenes_hermanos, raf_ips_hermanos, raf_eventos_equipo_60s,
          cta_es_sistema, cta_difiere_del_padre
"""

# Consulta de ALIMENTACION, no de calculo. Une EmailEvents + EmailUrlInfo +
# EmailAttachmentInfo por NetworkMessageId y entrega los campos crudos
# (remitente, asunto, urls, adjuntos, auth) que features_email.py consume
# en el backend. La paridad de las 37 caracteristicas es por construccion:
# es la misma libreria del entrenamiento. Dos caracteristicas de remitente
# (rem_distancia_marca, rem_es_lookalike) usan distancia de edicion, que
# Advanced Hunting no soporta; por eso su calculo vive en el backend.
PHISHING = r"""
let VENTANA = 1d;
let base =
    EmailEvents
    | where Timestamp > ago(VENTANA)
    | where EmailDirection == "Inbound"
    | extend _auth = parse_json(AuthenticationDetails)
    | project
        NetworkMessageId, Timestamp,
        remitente_correo  = SenderFromAddress,
        remitente_display = SenderDisplayName,
        asunto            = Subject,
        auth_spf          = tostring(_auth.SPF),
        auth_dkim         = tostring(_auth.DKIM),
        auth_dmarc        = tostring(_auth.DMARC);
let urls =
    EmailUrlInfo
    | where Timestamp > ago(VENTANA)
    | summarize urls = make_list(Url) by NetworkMessageId;
let adjuntos =
    EmailAttachmentInfo
    | where Timestamp > ago(VENTANA)
    | summarize adjuntos = make_list(FileName) by NetworkMessageId;
base
| join kind=leftouter (urls)     on NetworkMessageId
| join kind=leftouter (adjuntos) on NetworkMessageId
| project
    NetworkMessageId, Timestamp,
    remitente_correo, remitente_display, asunto,
    urls     = coalesce(urls, dynamic([])),
    adjuntos = coalesce(adjuntos, dynamic([])),
    auth_spf, auth_dkim, auth_dmarc
"""