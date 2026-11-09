# Detección de accesos remotos no autorizados — ThreatLens

Módulo del vector de accesos remotos del proyecto ThreatLens
(Trabajo Terminal, UPIITA-IPN).

El modelo se entrena **únicamente con corpus públicos**. El tenant de
Microsoft 365 del laboratorio es un entorno de **validación en operación**, no
de entrenamiento.

---

## 1. Este vector son tres detectores, no uno

Es la diferencia más importante respecto al módulo de phishing, y conviene
entenderla antes de tocar el código.

| | Qué detecta | Método | Por qué ese método |
|---|---|---|---|
| **A2** | Autenticación anómala: credenciales válidas, destino nuevo para la cuenta | **Modelo** (Random Forest, 28 características) | Patrón sutil, sin fallos, solo detectable contra el historial |
| **A1** | Fuerza bruta y password spraying | **Regla** con umbral calibrado | La definición es la detección; no hay nada que aprender |
| **B** | Herramientas de acceso remoto no autorizadas | **Inventario** configurable | Es una consulta a una lista, no una predicción |
| **Puertos** | RDP, SSH, Telnet, FTP entrantes | **Regla** | Un puerto es un hecho, no una inferencia |

Está verificado que **A1 y A2 no se solapan**: de los 702 eventos del red team
de LANL localizados en `auth.txt`, 701 fueron autenticaciones **exitosas**.
Ninguna ráfaga de fallos coincide con actividad del red team. Cada detector ve
lo que el otro no puede ver.

---

## 2. Preparación del entorno

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install pandas numpy scikit-learn xgboost joblib scipy
```

Usa siempre `python -m pip` en lugar de `pip`: invoca el módulo directamente y
funciona aunque el lanzador `pip.exe` esté roto, cosa que pasa si renombras la
carpeta del proyecto después de crear el entorno virtual.

**No copies ni renombres carpetas `.venv`.** En Windows los `.exe` de
`Scripts\` llevan la ruta absoluta grabada dentro y dejan de funcionar. Crear
uno nuevo toma diez segundos.

---

## 3. Obtener el corpus

LANL *Comprehensive, Multi-Source Cyber-Security Events*: 58 días consecutivos
de telemetría real de la red corporativa de Los Alamos National Laboratory,
licencia CC0, con etiquetas de un ejercicio real de red team.

La descarga es por formulario en <https://csr.lanl.gov/data/cyber1/>. Pide
correo y una descripción del uso. Son necesarios solo dos archivos:

```
Entrenamiento_AccesosRemotos\
├── datos\
│   ├── auth.txt.gz      (7.63 GB)
│   └── redteam.txt.gz   (pocos KB)
├── modelos_accesos\     <- lo crean los scripts
├── config_accesos.json
└── *.py
```

No hacen falta `dns.txt.gz`, `flows.txt.gz` ni `proc.txt.gz`.

### Esquemas

```
auth.txt     time, src_user@dom, dst_user@dom, src_computer, dst_computer,
             auth_type, logon_type, auth_orientation, success/failure
redteam.txt  time, user@dom, src_computer, dst_computer
```

---

## 4. Ejecución

En este orden. Los dos primeros recorren el archivo completo de mil millones
de líneas: déjalos corriendo.

```powershell
python inspeccionar_lanl.py datos\auth.txt.gz datos\redteam.txt.gz
python construir_ventanas.py datos\auth.txt.gz datos\redteam.txt.gz ventanas.csv
python entrenar_accesos.py ventanas.csv
python umbrales_accesos.py ventanas.csv --equipos 50
python calibrar_fuerza_bruta.py datos\auth.txt.gz datos\redteam.txt.gz --equipos 50
python detectar_accesos.py
```

Para ver que un script arranca bien sin esperar la pasada completa:

```powershell
python inspeccionar_lanl.py datos\auth.txt.gz datos\redteam.txt.gz --muestra 20000000
```

Esos números **no sirven para decidir nada**: el archivo está ordenado por
tiempo, así que una muestra solo cubre los primeros días y las proporciones
salen sesgadas.

Para probar otro tamaño de empresa **sin releer** `auth.txt` (los histogramas
no dependen del tamaño, solo la traducción):

```powershell
python calibrar_fuerza_bruta.py --desde-json --equipos 4
```

Si el entrenamiento tarda demasiado, se puede recortar a costa de peores
hiperparámetros e intervalos más anchos:

```powershell
python entrenar_accesos.py ventanas.csv --busqueda 10 --semillas 3
```

---

## 5. La unidad de análisis es una ventana, no un evento

En phishing la unidad era el correo: un mensaje aislado contiene toda la
evidencia. Aquí no. Un evento de autenticación por sí solo no dice nada —
alguien escribió mal su contraseña. Lo que delata el ataque es el patrón sobre
una ventana de tiempo.

**Clave de agrupación: `(cuenta, equipo origen, equipo destino, hora)`.**
Coincide exactamente con la granularidad de `redteam.txt`, que etiqueta
`(time, user, src_computer, dst_computer)`. Agrupar más grueso cargaría cada
ventana positiva de eventos benignos.

Las características salen de dos lugares distintos:

- **Dentro de la ventana:** conteos, tasa de fallo, tipos de logon, NTLM
  contra Kerberos, duración.
- **Historial previo a la ventana:** ¿esta cuenta había tocado este destino?
  ¿cuántos destinos toca normalmente? ¿este origen es suyo?

El segundo grupo es el que sostiene la detección, y trae una trampa.

---

## 6. Cómo se evita la fuga temporal

Si el historial de una ventana se calculara barriendo los 58 días completos,
una ventana del día 5 tendría una característica que ya sabe lo que pasó el
día 50. El modelo daría cifras excelentes e inservibles.

`construir_ventanas.py` procesa **hora por hora**:

1. Acumula los eventos de la hora en curso.
2. Al cambiar de hora, **emite** las ventanas usando el historial acumulado.
3. **Después** incorpora esa hora al historial.
4. Vacía el buffer.

El orden de 2 y 3 es lo que lo hace imposible: cuando se calculan las
características históricas, el historial **físicamente no contiene** ningún
evento de esa hora ni posterior. No es una regla que haya que recordar
respetar; es la estructura del bucle.

Verificado con datos sintéticos controlados: cero pares cuya primera ventana
ya traía historial, cero historiales que decrecen.

---

## 7. Las cuatro particiones

Temporales, con la misma disciplina de B1/B2 del módulo de phishing: **uno
decide, otro mide.**

| Bloque | Días | Ventanas | Positivas | Días con ataque | Función |
|---|---|---|---|---|---|
| Ajuste | 1–12 | 200,258 | 250 | 7 | Entrenar |
| Validación | 13–16 | 83,065 | 267 | 4 | **Decide**: hiperparámetros, ablación |
| Prueba | 17–30 | 243,087 | 46 | 7 | **Mide**, una sola vez |
| Benigno | 31–58 | 543,704 | 0 | 0 | FPR a escala real |

El bloque benigno se parte a su vez en dos: días 31–44 fijan el umbral, días
45–58 lo verifican. Sin esa división el FPR sería circular.

---

## 8. Resultados

Modelo desplegado: **Random Forest**, 28 características (grupo `concurrencia`
excluido por ablación).

Prevalencia de ventanas positivas: **1 de cada 94,988**.

| Nivel | Umbral | Recall en prueba | FPR verificado | Precisión | Falsas alarmas (PyME 50 eq.) |
|---|---|---|---|---|---|
| **alto** | 0.4825 | 0.587 [0.44–0.72] | 1.47e-5 | 0.296 | 1 cada 23 días |
| medio | 0.2425 | 0.652 [0.51–0.77] | 6.61e-5 | 0.094 | 1 cada 5 días |
| bajo | 0.0300 | 0.913 [0.80–0.97] | 1.39e-3 | 0.007 | 4.1 al día |

**Cobertura acumulada: 91.3 %** de los accesos no autorizados de los días
17–30 caen en algún nivel.

Solo **alto** notifica. Medio y bajo alimentan el panel: recuperan cobertura
sin gastar credibilidad, porque no afirman nada.

### Intervalos, que aquí importan más que las estimaciones

El nivel alto se apoya en **4 falsos positivos observados**. Con 4 eventos el
intervalo de Poisson al 95 % es enorme:

| | Estimación | Rango real al 95 % |
|---|---|---|
| FPR en alto | 1.47e-5 | 4.0e-6 — 3.8e-5 |
| Precisión en alto | 0.296 | **0.14 — 0.61** |
| Falsas alarmas | 1 cada 23 días | 1 cada **9 a 85** días |

Los números más sólidos están en los niveles que **no** notifican. Es el
límite de lo que 543 mil ventanas benignas permiten estimar, no un defecto del
modelo.

### Umbrales de la regla A1

| Patrón | 50 equipos | 4 equipos |
|---|---|---|
| Fuerza bruta (fallos contra un destino en 5 min) | ≥100 ⚠ | ≥30 |
| Spraying (cuentas distintas con fallo en 5 min) | ≥15 | ≥3 |

⚠ Ningún umbral candidato alcanza el presupuesto de 1 alerta cada 30 días a
escala de 50 equipos. El de 100 da 1 cada 13 días, y es el más exigente
disponible. El ruido que lo obliga viene de unos pocos orígenes mal
configurados, no de una tasa por equipo, así que la traducción lineal a una
PyME es un **límite superior pesimista**.

---

## 9. Lo que queda fuera del modelo

- **`AlertInfo` / `AlertEvidence`**: es el veredicto de Microsoft. Usarlo sería
  copiar la respuesta, y el sistema fallaría exactamente donde falla Defender.
- **Identificadores** (cuenta, origen, destino): son enteros arbitrarios. Si
  entraran como características, el modelo memorizaría las 104 cuentas del red
  team y daría métricas perfectas que no transfieren a nada. Se excluyen de
  forma explícita, no por omisión.
- **El grupo `concurrencia`** (6 características): eliminado por ablación. Ver
  sección 11.
- **Contenido de la sesión remota**: Advanced Hunting no lo expone.

---

## 10. Archivos

| Archivo | Qué hace |
|---|---|
| `inspeccionar_lanl.py` | Reconocimiento: mide el corpus antes de construir nada |
| `construir_ventanas.py` | Convierte `auth.txt.gz` en ventanas con 34 características |
| `entrenar_accesos.py` | Diagnóstico univariado, hiperparámetros, ablación, selección |
| `umbrales_accesos.py` | Tres niveles de severidad con intervalos; guarda el modelo |
| `calibrar_fuerza_bruta.py` | Calibra A1 sobre el fondo real de fallos |
| `detectar_accesos.py` | Detector de inferencia: junta A2, A1, B y puertos |
| `config_accesos.json` | Perfiles de entorno (laboratorio / producción) |

---

## 11. Tres predicciones que salieron mal

Se documentan porque forman parte del método: las tres se corrigieron con
medición, y la última cambió el diseño.

**1. `ven_logoff` como artefacto.** Las ventanas de red team contienen 100 %
eventos `LogOn`, cero `LogOff`, cuando en el tráfico general `LogOff` es el
41.5 %. Se temió que "ventana sin LogOff" resolviera el problema sola y fuera
un artefacto del corpus. El diagnóstico univariado lo descartó: `ven_logoff`
no aparece entre las 12 características con más separación, porque muchas
ventanas benignas tampoco tienen LogOff.

**2. `concurrencia` como la firma del movimiento lateral.** Se predijo que el
abanico de destinos en una hora sería la señal más fuerte. Es el grupo que
**estorba**: Random Forest pasa de 0.8946 a 0.9101 al quitarlo, y SVM de
0.2243 a 0.4268. La razón es un mecanismo que ya se había identificado en el
diseño: las características de concurrencia se comparten entre todas las
ventanas de una cuenta en una hora, así que las ventanas **benignas** de una
cuenta comprometida tienen valores idénticos a las malignas. Misma entrada,
etiqueta opuesta.

**3. El fondo de fallos como "silencioso".** Con 1,090,015 fallos en 58 días
sobre 292 millones de eventos se esperaba un fondo tranquilo. No lo es: las
16,704 ventanas de 5 minutos con fallos son exactamente 58 × 288, es decir,
**todos** los bins de los 58 días tienen al menos un fallo. Y a ≥100 fallos en
5 minutos contra un mismo destino todavía quedan 23.7 casos diarios.

La conclusión transferible: **en este tipo de problema la intuición sobre qué
característica va a funcionar no vale; solo vale la ablación.**

---

## 12. Hallazgo metodológico

Calibrar el umbral sobre **tráfico benigno puro** en lugar de sobre el bloque
de validación casi duplica el recall:

| Dónde se fijó el umbral | FPR logrado | Recall en prueba |
|---|---|---|
| Validación (días 13–16, contiene ataques) | 2.21e-6 | 0.313 |
| Benigno (días 31–44, sin ataques) | 1.47e-5 | **0.587** |

Pedirle al modelo un FPR objetivo sobre un bloque que contiene ataques
desplaza el corte: el umbral salió mucho más conservador de lo pedido y se
comió la mitad del recall. Calibrar sobre tráfico limpio es además lo que se
haría en producción de todos modos.

Es el mismo fenómeno que en el módulo de phishing se diagnosticó como "margen
perdido por umbral desfasado" y allá no se corrigió. **Es aplicable a ese
módulo.**

---

## 13. Integración

```python
from detectar_accesos import DetectorAccesosRemotos

detector = DetectorAccesosRemotos.desde_config()   # lee config_accesos.json

resultado = detector.evaluar(
    caracteristicas=caracts,          # las 28 del contrato
    fallos=0,
    cuentas_distintas=0,
    procesos=["mstsc.exe"],
    puerto=3389, ip_remota="201.141.22.9", entrante=True,
    cuenta="jlopez", destino="SRV-CONTA",
)

# resultado["nivel_severidad"]      -> alto | medio | bajo | ninguna
# resultado["notificar"]            -> True solo en alto
# resultado["motivos"]              -> por qué, en lenguaje del operador
# resultado["reglas_concluyentes"]  -> qué reglas dispararon por sí solas
# resultado["a2_fuera_de_rango"]    -> True si el entorno es muy pequeño
```

Para cambiar de escenario se edita **una palabra** en `config_accesos.json`:

```json
"activo": "laboratorio"     // 4 equipos, demostración
"activo": "produccion"      // 50 equipos, cifras del reporte
```

Las reglas **solo suben** la severidad, nunca la bajan. Las concluyentes
—herramienta fuera de inventario, RDP entrante desde IP pública, ráfaga de
fallos— disparan aunque el modelo no haya sospechado.

### Lo que falta para producción

El detector recibe las 28 características **ya calculadas**. En entrenamiento
las calcula `construir_ventanas.py`; en producción no las calcula nadie
todavía.

El lugar correcto para ese cálculo es **KQL**, no un almacén de historial en
Python: "¿esta cuenta había accedido antes a este equipo?" es un `join` contra
los últimos 30 días que Advanced Hunting resuelve del lado del servidor, sin
que el sistema mantenga estado.

```kql
let ventana   = 1h;
let historia  = 30d;
let remotos   = dynamic(["Network","RemoteInteractive","NetworkCleartext"]);
let base = DeviceLogonEvents
    | where Timestamp > ago(historia)
    | where LogonType in (remotos)
    | where AccountName !endswith "$";
let historico = base
    | where Timestamp < ago(ventana)          // estrictamente anterior: sin fuga
    | summarize his_par_visto = count() by AccountName, DeviceName;
base
| where Timestamp > ago(ventana)
| summarize ven_eventos = count(),
            ven_fallos  = countif(ActionType == "LogonFailed")
        by AccountName, RemoteIP, DeviceName, bin(Timestamp, ventana)
| join kind=leftouter historico on AccountName, DeviceName
| extend his_par_nuevo = iff(isempty(his_par_visto), 1, 0)
```

El `where Timestamp < ago(ventana)` replica en KQL la disciplina anti-fuga del
entrenamiento.

---

## 14. Limitaciones

1. **El red team de LANL no usa RDP.** Los 702 eventos son 100 % logon de red
   (`Network`); `RemoteInteractive` es el 0.01 % de todo el corpus. El modelo
   A2 detecta **movimiento lateral por logon de red**, no intrusiones por RDP.
   RDP queda cubierto por A1, por la regla de puerto y por el inventario, no
   por el modelo.

2. **46 ventanas positivas en el conjunto de prueba, de 7 episodios.** Los
   intervalos son anchos y además optimistas: las ventanas de un mismo
   episodio están correlacionadas, así que las 563 positivas no son 563
   muestras independientes sino **18 episodios de ataque**.

3. **La precisión supone la prevalencia de LANL**, que viene de un ejercicio
   de red team. La del tenant hay que medirla y volver a correr
   `umbrales_accesos.py`.

4. **La traducción a la PyME es lineal por número de equipos.** Es una
   aproximación, no una medición, y es la parte menos confiable del cálculo de
   A1: el ruido de fondo viene de unas pocas fuentes mal configuradas, no de
   una tasa por equipo.

5. **A2 se degrada en entornos pequeños.** Sus características son
   relacionales (`his_par_nuevo`, `his_usr_destinos`) y en 3 o 4 equipos se
   mueren solas: a los pocos días todas las cuentas tocaron todos los equipos.
   El detector no lo desactiva; lo marca con `a2_fuera_de_rango`. El
   laboratorio valida la **integración funcional** y las reglas A1 y B, que no
   dependen del tamaño; no valida el desempeño estadístico de A2.

6. **47 de los 749 eventos de `redteam.txt` no aparecen en `auth.txt`** (6.3 %),
   lo que deja 563 ventanas positivas de 572 posibles. Se trabaja con lo
   localizado.
