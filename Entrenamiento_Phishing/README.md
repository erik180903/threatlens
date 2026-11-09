# Entrenamiento del modelo de detección de phishing — ThreatLens

Módulo de detección de phishing por correo electrónico del proyecto ThreatLens
(Trabajo Terminal, UPIITA-IPN).

El modelo se entrena **únicamente con corpus públicos**. El tenant de
Microsoft 365 del laboratorio es un entorno de **validación en operación**, no
de entrenamiento.

---

## 1. Preparación del entorno

Desde la carpeta raíz del proyecto (donde están los `.py`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pandas numpy scikit-learn xgboost joblib
```

Si al ejecutar un script aparece `ModuleNotFoundError: No module named 'pandas'`,
el entorno virtual no está activo: vuelve a correr `.\.venv\Scripts\Activate.ps1`
y confirma que el prompt empieza con `(.venv)`.

Los scripts deben quedar en la **raíz** del proyecto, no dentro de `datos\`.

---

## 2. Obtener los corpus

Estructura esperada:

```
Entrenamiento_Phishing\
├── datos\
│   ├── CEAS_08.csv
│   ├── SpamAssasin.csv
│   ├── Nazario.csv
│   ├── Nigerian_Fraud.csv
│   └── PhishingPot.csv        <- se genera en el paso 2.2
├── modelos\                   <- lo crea el entrenamiento
└── *.py
```

### 2.1 Los cuatro CSV

Descargar de Kaggle el conjunto *Phishing Email Dataset* (Naser Abdullah Alam)
y colocar en `datos\` los archivos `CEAS_08.csv`, `SpamAssasin.csv`,
`Nazario.csv` y `Nigerian_Fraud.csv`. Todos traen las columnas
`sender, receiver, date, subject, body, label, urls`.

### 2.2 PhishingPot (phishing real 2022–2026)

```powershell
Invoke-WebRequest -Uri "https://github.com/rf-peixoto/phishing_pot/archive/refs/heads/main.zip" -OutFile "datos\phishing_pot.zip"
Expand-Archive -Path "datos\phishing_pot.zip" -DestinationPath "datos\" -Force
python parse_eml.py datos\phishing_pot-main\email 1 datos\PhishingPot.csv
```

`parse_eml.py` convierte los `.eml` al mismo esquema de columnas que los CSV.
Decodifica encabezados MIME (`=?utf-8?B?...?=`), separa adjuntos reales de
imágenes incrustadas y extrae SPF/DKIM/DMARC a columnas propias.

---

## 3. Ejecución

En este orden:

```powershell
python verificar_datos.py          # revisa formato y etiquetas antes de entrenar
python train_phishing_email.py     # ~12-15 min; escribe modelos\
python umbrales_severidad.py 0.01  # umbrales de severidad a la prevalencia dada
python predict_phishing_email.py   # prueba del detector con casos sintéticos
python prueba_manual.py            # prueba sobre correos reales de PhishingPot
```

`umbrales_severidad.py` acepta la prevalencia como argumento y, opcionalmente,
el modelo:

```powershell
python umbrales_severidad.py 0.005        # 0.5 % de phishing en el flujo
python umbrales_severidad.py 0.02 svm     # 2 %, forzando SVM
```

`prueba_manual.py` tiene dos modos:

```powershell
python prueba_manual.py            # muestra filtrada de PhishingPot
python prueba_manual.py --mios     # lee mis_correos.csv (correos propios)
```

Para el segundo modo, `mis_correos.csv` necesita las columnas
`sender,subject,body,adjuntos,etiqueta`.

---

## 4. Diseño experimental

Cuatro particiones. Ningún correo aparece en más de una.

| Partición | Phishing | Legítimo | Para qué sirve |
|---|---|---|---|
| Entrenamiento / validación | Nazario (1,565) | 7,134 | Ajustar el modelo |
| Externo A | Nigerian Fraud (3,332) | 7,134 | Generalización, misma época |
| Externo B1 | PhishingPot ½ (4,306) | 3,568 | **Decide** la selección de características |
| Externo B2 | PhishingPot ½ (4,306) | 3,567 | **Mide** el resultado final; no participa en ninguna decisión |

El legítimo (SpamAssassin `label=0` + CEAS-08 `label=0`) se reparte igual en las
cuatro particiones para que al comparar sólo varíe la fuente de phishing.

De CEAS-08 y SpamAssassin se descartan las 23,560 filas con `label=1`: son
*spam comercial*, no phishing, y etiquetarlas como phishing enseñaría al modelo
a detectar publicidad.

---

## 5. Resultados

Modelo desplegado: **SVM calibrado**, 37 características (grupo `url_magnitud`
excluido por ablación).

Cobertura con los tres niveles de severidad, según la prevalencia real de
phishing en el flujo de correo:

| Prevalencia | Cobertura total | Recall en severidad alta | Precisión en alta |
|---|---|---|---|
| 0.5 % | 35.2 % | 0.1238 | 1.0000 |
| 1 % | 55.0 % | 0.1282 | 1.0000 |
| 2 % | 68.7 % | 0.1282 | 0.99+ |

Severidad **alta** es la única que dispara notificación directa al usuario.
Media y baja quedan en el panel para revisión.

Pruebas manuales sobre correos reales de PhishingPot:

| Muestra | Severidad alta | Cobertura (alguna severidad) |
|---|---|---|
| Aleatoria (20 correos) | 0 % | 40 % |
| Filtrada por suplantación de marca (20 correos) | 15 % | 55 % |

Es decir: el sistema detecta **suplantación de instituciones y marcas**, que es
el vector relevante para una PyME mexicana, y no detecta fraude publicitario
genérico sin marca suplantada.

---

## 6. Lo que queda fuera del modelo

No son características del modelo, por decisión de diseño:

- **Cuerpo del correo.** Advanced Hunting no lo expone. Durante el entrenamiento
  sólo se usa para extraer las URLs y así simular `EmailUrlInfo`; el texto nunca
  entra como característica.
- **`ThreatTypes` / `DetectionMethods`** de `EmailEvents`: son el veredicto de
  Microsoft. Usarlos sería copiar la respuesta.
- **SPF/DKIM/DMARC**: se evalúan como regla determinista en inferencia, no como
  característica, porque en los corpus antiguos faltan o son inconsistentes.
- **Hash SHA256 de adjuntos**: Advanced Hunting entrega el hash, no el binario;
  no hay nada que caracterizar.
- **Adjuntos como características**: sólo 8 adjuntos de riesgo entre 2,279
  correos de Nazario (7 `.zip` + 1 `.bhx`); 299 de 304 "adjuntos" son imágenes
  incrustadas. Insuficiente para aprender. Se tratan con **reglas deterministas**
  en `predict_phishing_email.py`.

---

## 7. Archivos

| Archivo | Qué hace |
|---|---|
| `parse_eml.py` | Convierte un directorio de `.eml` al esquema CSV común |
| `verificar_datos.py` | Verifica formato, columnas y etiquetas antes de entrenar |
| `features_phishing.py` | 38 características léxicas de una URL (librería, no se ejecuta sola) |
| `features_email.py` | 47 características de correo en 4 grupos (librería) |
| `train_phishing_email.py` | Búsqueda de hiperparámetros, ablación, reajuste, selección |
| `umbrales_severidad.py` | Calcula los umbrales de los tres niveles para una prevalencia |
| `predict_phishing_email.py` | Detector de inferencia: modelo + reglas de adjuntos y autenticación |
| `prueba_manual.py` | Prueba el detector sobre correos reales |

`features_phishing.py` y `features_email.py` son **librerías**: al ejecutarlas
directamente no imprimen nada, y eso es correcto. Las importa tanto el
entrenamiento como la inferencia, lo que garantiza que ambos calculen
exactamente las mismas características en el mismo orden.

---

## 8. Integración con el sistema

```python
from predict_phishing_email import DetectorPhishingCorreo

detector = DetectorPhishingCorreo("modelos")

resultado = detector.evaluar(
    remitente="seguridad@bbva-mx-alertas.com",
    asunto="Su cuenta sera suspendida en 24 horas",
    urls=["http://bbva-mx-alertas.com/verificar"],
    adjuntos=["aviso.pdf.exe"],
    auth_spf="fail", auth_dkim="none", auth_dmarc="fail",
)

# resultado["nivel_severidad"]      -> "alto" | "medio" | "bajo" | "ninguna"
# resultado["notificar"]            -> True solo en "alto"
# resultado["probabilidad"]         -> salida calibrada del modelo
# resultado["motivos_escalamiento"] -> reglas que subieron la severidad
```

El detector se alimenta de `EmailEvents`, `EmailUrlInfo` y `EmailAttachmentInfo`
unidas por `NetworkMessageId`. Las reglas deterministas **sólo suben** la
severidad, nunca la bajan. Las reglas concluyentes (ejecutable, doble extensión)
disparan incluso cuando el modelo no marcó nada.

---

## 9. Limitaciones

1. **Brecha de época.** El entrenamiento usa phishing de 2002–2008; el escenario
   de operación es 2026. No existe corpus público moderno de correo legítimo con
   el que cerrarla. La medición en PhishingPot (2022–2026) cuantifica el costo:
   el recall cae respecto a la validación interna.
2. **Umbral desfasado.** La cota superior (umbral recalibrado sobre B2) muestra
   que SVM pierde +0.3805 de F1 por tener el umbral fijado en datos antiguos.
   Recalibrarlo con correo real del tenant recupera buena parte de ese margen.
3. **La prevalencia manda.** La precisión real depende de cuánto phishing llegue
   de verdad. Los números de la sección 5 asumen 0.5–2 %; hay que medir la
   prevalencia real del tenant y volver a correr `umbrales_severidad.py`.
4. **Marcas limitadas.** La lista `MARCAS` en `features_email.py` cubre 27
   marcas, incluidas las mexicanas principales (BBVA, Banorte, Santander,
   Citibanamex, Mercado Libre, Telmex, CFE, IMSS, SAT, Infonavit). Ampliarla
   requiere reentrenar.
5. **Sólo correo.** Los vectores de accesos remotos y malware son modelos
   independientes, aún no entrenados.
