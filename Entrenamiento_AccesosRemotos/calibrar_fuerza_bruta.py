"""
calibrar_fuerza_bruta.py
------------------------
Calibra la regla A1: fuerza bruta y password spraying.

POR QUE ESTO ES UNA REGLA Y NO UN MODELO
    "N fallos de autenticacion contra el mismo destino en T segundos" no
    necesita aprendizaje: la definicion ES la deteccion. Es una consulta
    de agregacion. Lo unico que hay que elegir con criterio son N y T.

    Ademas el modelo A2 no puede cubrirlo: de los 702 eventos del red
    team localizados en auth.txt, 701 fueron exitosos. A2 nunca vio una
    rafaga de fallos, asi que no puede haber aprendido a reconocerla.

COMO SE ELIGEN N Y T
    No se inventan. Se mide la distribucion de rafagas de fallos en los
    58 dias de trafico corporativo real y se elige el umbral que deja el
    volumen de alertas dentro del presupuesto. Calibracion empirica.

DOS PATRONES, DOS CLAVES
    fuerza bruta  (origen, destino, ventana)  -> muchos fallos contra una maquina
    spraying      (origen, ventana)           -> un intento en muchas cuentas

VENTANAS CONTIGUAS
    Con ventanas fijas, una rafaga de 10:58 a 11:02 se parte en dos y
    cada mitad puede quedar bajo el umbral. El script evalua tambien
    cada par de ventanas contiguas, que es como aproximar una ventana
    deslizante sin el costo de una.

Uso:
    python calibrar_fuerza_bruta.py datos\\auth.txt.gz datos\\redteam.txt.gz
    python calibrar_fuerza_bruta.py datos\\auth.txt.gz datos\\redteam.txt.gz --equipos 50
    python calibrar_fuerza_bruta.py datos\\auth.txt.gz datos\\redteam.txt.gz --muestra 30000000

    Para probar otro tamaño de empresa SIN volver a leer auth.txt
    (los histogramas no dependen del tamaño, solo la traduccion):

    python calibrar_fuerza_bruta.py --desde-json --equipos 4
"""

import gzip
import json
import os
import sys
from collections import Counter, defaultdict

VENTANA = 300                 # 5 minutos
SEGUNDOS_POR_DIA = 86400
DIAS = 58
AVANCE = 25_000_000
BASE = 1_000_000

EQUIPOS_LANL = 15744
EQUIPOS_PYME = 50

LOGON_REMOTOS = {b"Network", b"RemoteInteractive", b"NetworkCleartext"}

# Umbrales candidatos a evaluar.
CANDIDATOS_FB = [3, 5, 8, 10, 15, 20, 30, 50, 100]      # fallos contra un destino
CANDIDATOS_SP = [3, 5, 8, 10, 15, 20, 30, 50]           # cuentas distintas fallidas

DIR_SALIDA = "modelos_accesos"


def abrir(ruta):
    return gzip.open(ruta, "rb") if ruta.endswith(".gz") else open(ruta, "rb")


def cargar_redteam(ruta):
    """Ventanas de 5 min en las que hubo actividad de red team, para
    comprobar si la regla A1 las toca (no deberia: fueron exitosas)."""
    v = set()
    with abrir(ruta) as f:
        for linea in f:
            p = linea.strip().split(b",")
            if len(p) < 4:
                continue
            try:
                t = int(p[0])
            except ValueError:
                continue
            v.add((p[2], p[3], t // VENTANA))
    return v


def procesar(ruta_auth, rt_ventanas, limite=None):
    # Histogramas de la magnitud maxima observada por ventana.
    hist_fb = Counter()          # fallos por (origen, destino, ventana)
    hist_sp = Counter()          # cuentas distintas fallidas por (origen, ventana)
    hist_fb_par = Counter()      # idem sobre pares de ventanas contiguas
    hist_sp_par = Counter()

    rt_tocadas = 0
    total_leidos = 0
    total_filtrados = 0
    total_fallos = 0
    ventanas_vistas = 0
    t_min = t_max = None

    # Acumuladores de la ventana en curso
    actual = None
    fb = defaultdict(int)                 # (origen,destino) -> fallos
    sp = defaultdict(set)                 # origen -> {cuentas fallidas}
    fb_prev, sp_prev = {}, {}

    def cerrar(ventana):
        nonlocal fb_prev, sp_prev, rt_tocadas, ventanas_vistas
        ventanas_vistas += 1

        for clave, n in fb.items():
            hist_fb[n] += 1
            hist_fb_par[n + fb_prev.get(clave, 0)] += 1
        for origen, cuentas in sp.items():
            n = len(cuentas)
            hist_sp[n] += 1
            hist_sp_par[len(cuentas | sp_prev.get(origen, set()))] += 1

        # ¿alguna rafaga coincide con actividad de red team?
        for (o, d), n in fb.items():
            if n >= 3 and (o, d, ventana) in rt_ventanas:
                rt_tocadas += 1

        fb_prev = dict(fb)
        sp_prev = {k: set(v) for k, v in sp.items()}

    print("  recorriendo auth.txt...")
    with abrir(ruta_auth) as f:
        for linea in f:
            total_leidos += 1
            if limite and total_leidos > limite:
                total_leidos -= 1
                break
            if total_leidos % AVANCE == 0:
                print(f"    {total_leidos:,} lineas  |  "
                      f"{total_fallos:,} fallos  |  "
                      f"{ventanas_vistas:,} ventanas de {VENTANA}s")

            p = linea.rstrip(b"\n").split(b",")
            if len(p) < 9:
                continue
            try:
                t = int(p[0])
            except ValueError:
                continue

            if t_min is None or t < t_min:
                t_min = t
            if t_max is None or t > t_max:
                t_max = t

            if p[6] not in LOGON_REMOTOS:
                continue
            src_user = p[1]
            if src_user.endswith(b"$") or b"$@" in src_user:
                continue
            total_filtrados += 1

            if not p[8].startswith(b"Fail"):
                continue
            total_fallos += 1

            v = t // VENTANA
            if actual is None:
                actual = v
            elif v != actual:
                cerrar(actual)
                fb = defaultdict(int)
                sp = defaultdict(set)
                actual = v

            origen, destino = p[3], p[4]
            fb[(origen, destino)] += 1
            sp[origen].add(src_user)

    if actual is not None:
        cerrar(actual)

    return {
        "hist_fb": hist_fb, "hist_sp": hist_sp,
        "hist_fb_par": hist_fb_par, "hist_sp_par": hist_sp_par,
        "leidos": total_leidos, "filtrados": total_filtrados,
        "fallos": total_fallos, "ventanas": ventanas_vistas,
        "rt_tocadas": rt_tocadas, "t_min": t_min, "t_max": t_max,
    }


def excede(hist, n):
    """Cuantas ventanas alcanzan o superan n."""
    return sum(c for v, c in hist.items() if v >= n)


def tabla(titulo, hist, hist_par, candidatos, dias, equipos, factor_pyme):
    print("\n" + "-" * 78)
    print(f"  {titulo}")
    print("-" * 78)
    print(f"    {'umbral':>7} {'casos':>12} {'por dia':>10} "
          f"{'con pares':>11} {'escala PyME':>18}")
    filas = []
    for n in candidatos:
        e = excede(hist, n)
        ep = excede(hist_par, n)
        por_dia = e / dias
        pyme = por_dia * factor_pyme
        if pyme >= 1:
            leyenda = f"{pyme:.1f} al dia"
        elif pyme > 0:
            leyenda = f"1 cada {1/pyme:,.0f} dias"
        else:
            leyenda = "ninguna"
        print(f"    {n:>7} {e:>12,} {por_dia:>10.1f} {ep:>11,} {leyenda:>18}")
        filas.append({"umbral": n, "casos": e, "por_dia": por_dia,
                      "con_pares": ep, "pyme_por_dia": pyme})
    return filas


def recomendar(filas, objetivo_pyme):
    """El umbral mas bajo cuyo volumen en la PyME no pasa del objetivo.

    Devuelve (fila, cumple). Si ningun candidato alcanza el presupuesto
    devuelve el mas exigente con cumple=False: callarselo haria pasar un
    fallback por una recomendacion satisfecha.
    """
    for f in filas:
        if f["pyme_por_dia"] <= objetivo_pyme:
            return f, True
    return filas[-1], False


def rederivar(equipos):
    """Vuelve a calcular la recomendacion para otro tamaño de empresa
    usando el JSON ya guardado. No toca auth.txt: la pasada larga ya se
    hizo y los histogramas no dependen del tamaño, solo la traduccion."""
    ruta = os.path.join(DIR_SALIDA, "umbrales_fuerza_bruta.json")
    if not os.path.exists(ruta):
        print(f"[!] Falta {ruta}. Corre primero la pasada completa.")
        sys.exit(1)
    with open(ruta, encoding="utf-8") as f:
        d = json.load(f)

    factor = equipos / EQUIPOS_LANL
    objetivo = 1 / 30
    dias = d.get("dias_calibracion", 0)
    print(f"  Re-derivado para {equipos} equipos (factor {factor:.6f})")
    print(f"  Presupuesto: {objetivo:.4f} alertas/dia por patron")

    # El fondo de fallos y la tabla de candidatos ya estan en el JSON: la
    # pasada larga los midio y no dependen del tamaño de la empresa, solo
    # la ultima columna. Se reimprimen aqui porque son la evidencia de la
    # calibracion -- el umbral recomendado solo no dice de donde sale.
    fondo = d.get("fondo", {})
    if fondo:
        print("\n" + "=" * 78)
        print("FONDO DE FALLOS EN TRAFICO REAL  (medido en la pasada completa)")
        print("=" * 78)
        print(f"  eventos que pasan el filtro : {fondo['filtrados']:,}")
        print(f"  de esos, fallidos           : {fondo['fallos']:,}  "
              f"({100*fondo['fallos']/max(fondo['filtrados'],1):.2f} %)")
        print(f"  ventanas de {VENTANA//60} min con fallos: "
              f"{fondo['ventanas_con_fallos']:,}")
        if dias:
            # round y no int: el corpus abarca 57.99998 dias, no 58
            # exactos, y truncar daba 16,703 ventanas totales frente a
            # 16,704 medidas con fallos -- mas ventanas con fallos que
            # ventanas, que es imposible y delata el redondeo.
            tot = round(dias * 24 * 3600 / VENTANA)
            print(f"  ventanas totales del corpus: {tot:,}  "
                  f"({dias:.0f} dias)")
            if fondo["ventanas_con_fallos"] >= tot * 0.999:
                print("\n  [!] Practicamente TODAS las ventanas del corpus")
                print("      contienen fallos. No hay un fondo silencioso")
                print("      sobre el que recortar: el umbral tiene que")
                print("      competir contra ruido continuo.")

    salida = dict(d)
    salida["equipos_referencia"] = equipos
    titulos = {"fuerza_bruta": "FUERZA BRUTA  (fallos sobre una misma cuenta)",
               "spraying": "SPRAYING  (cuentas distintas desde un mismo origen)"}
    for patron in ("fuerza_bruta", "spraying"):
        filas = []
        for f0 in d[patron]["candidatos"]:
            casos = f0.get("casos", f0.get("ventanas"))
            f1 = dict(f0, casos=casos, pyme_por_dia=f0["por_dia"] * factor)
            f1.pop("ventanas", None)
            filas.append(f1)
        rec, cumple = recomendar(filas, objetivo)

        print("\n" + "-" * 78)
        print(f"  {titulos[patron]}")
        print("-" * 78)
        print(f"    {'umbral':>7} {'casos':>12} {'por dia':>10} "
              f"{'con pares':>11} {'escala PyME':>18}")
        for f1 in filas:
            p = f1["pyme_por_dia"]
            # Por debajo de 0.75 al dia se cuenta en dias. El corte no
            # esta en 1 porque "1 cada 1 dias" delata la plantilla y no
            # dice nada que "0.9 al dia" no diga mejor.
            entre = round(1 / p) if p > 0 else 0
            leyenda = (f"1 cada {entre:,} dias" if entre >= 2 else
                       f"{p:.1f} al dia" if p > 0 else "ninguna")
            marca = "  <-- elegido" if f1["umbral"] == rec["umbral"] else ""
            print(f"    {f1['umbral']:>7} {f1['casos']:>12,} "
                  f"{f1['por_dia']:>10.1f} {f1.get('con_pares', 0):>11,} "
                  f"{leyenda:>18}{marca}")
        if not cumple:
            print(f"\n    [!] NINGUN candidato alcanza el presupuesto de "
                  f"{objetivo:.4f} alertas/dia.")
            print("        El umbral elegido es el mas exigente de la lista,")
            print("        no una recomendacion que cumpla la meta.")
        salida[patron] = {"candidatos": filas, "recomendado": rec,
                          "cumple_presupuesto": cumple}

    print("\n" + "=" * 78)
    print("UMBRALES RECOMENDADOS")
    print("=" * 78)
    for patron in ("fuerza_bruta", "spraying"):
        rec = salida[patron]["recomendado"]
        print(f"  {patron:<13}: >= {rec['umbral']}   "
              f"{rec['casos']:,} casos   "
              f"{rec['pyme_por_dia']:.4f}/dia"
              + ("" if salida[patron]["cumple_presupuesto"]
                 else "   [!] no cumple el presupuesto"))
    rt = d.get("coincidencias_redteam")
    if rt is not None:
        print(f"\n  Rafagas de fallos que coinciden con el red team: {rt}")
        if rt == 0:
            print("  Cero: el red team entro con credenciales validas, asi")
            print("  que A1 no lo ve y A2 no ve fuerza bruta. Cada regla")
            print("  cubre lo que la otra no puede.")

    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(salida, f, indent=2, ensure_ascii=False)
    print(f"\n  Actualizado -> {ruta}")


def main():
    if "--desde-json" in sys.argv:
        eq = EQUIPOS_PYME
        if "--equipos" in sys.argv:
            eq = int(sys.argv[sys.argv.index("--equipos") + 1])
        rederivar(eq)
        return

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    ruta_auth, ruta_rt = args[0], args[1]

    equipos = EQUIPOS_PYME
    if "--equipos" in sys.argv:
        equipos = int(sys.argv[sys.argv.index("--equipos") + 1])
    limite = None
    if "--muestra" in sys.argv:
        limite = int(sys.argv[sys.argv.index("--muestra") + 1])

    for r in (ruta_auth, ruta_rt):
        if not os.path.exists(r):
            print(f"[!] No existe: {r}")
            sys.exit(1)

    print(f"  ventana: {VENTANA}s ({VENTANA//60} min)")
    print(f"  PyME de referencia: {equipos} equipos\n")

    rt = cargar_redteam(ruta_rt)
    print(f"  redteam: {len(rt):,} ventanas de {VENTANA}s con actividad\n")

    r = procesar(ruta_auth, rt, limite)

    if r["t_min"] is not None and r["t_max"] is not None:
        dias = max(1.0, (r["t_max"] - r["t_min"]) / SEGUNDOS_POR_DIA)
    else:
        dias = float(DIAS)
    factor = equipos / EQUIPOS_LANL

    print("\n" + "=" * 78)
    print("FONDO DE FALLOS EN TRAFICO REAL")
    print("=" * 78)
    print(f"  eventos leidos      : {r['leidos']:,}")
    print(f"  pasan el filtro     : {r['filtrados']:,}")
    print(f"  fallidos            : {r['fallos']:,}  "
          f"({100.0*r['fallos']/max(1,r['filtrados']):.3f}%)")
    print(f"  ventanas con fallos : {r['ventanas']:,}")
    print(f"\n  escala: PyME/{EQUIPOS_LANL:,} equipos = factor {factor:.5f}")

    f_fb = tabla("FUERZA BRUTA  -  fallos contra un mismo destino, por origen",
                 r["hist_fb"], r["hist_fb_par"], CANDIDATOS_FB,
                 dias, equipos, factor)
    f_sp = tabla("SPRAYING  -  cuentas distintas con fallo, por origen",
                 r["hist_sp"], r["hist_sp_par"], CANDIDATOS_SP,
                 dias, equipos, factor)

    # --- recomendacion ----------------------------------------------
    # Presupuesto: una alerta cada 30 dias en la PyME para cada patron.
    objetivo = 1 / 30
    rec_fb, cumple_fb = recomendar(f_fb, objetivo)
    rec_sp, cumple_sp = recomendar(f_sp, objetivo)

    print("\n" + "=" * 78)
    print("UMBRALES RECOMENDADOS")
    print("=" * 78)
    print(f"  Presupuesto: 1 alerta cada 30 dias por patron, "
          f"en una PyME de {equipos} equipos.\n")
    for nombre, rec, cumple in (("fuerza bruta", rec_fb, cumple_fb),
                                ("spraying", rec_sp, cumple_sp)):
        unidad = ("fallos contra un destino" if nombre == "fuerza bruta"
                  else "cuentas distintas con fallo desde un origen")
        print(f"  {nombre:<13}: >= {rec['umbral']} {unidad} en {VENTANA//60} min")
        print(f"                 {rec['casos']:,} casos en {dias:.0f} dias "
              f"a escala LANL ({rec['pyme_por_dia']:.4f}/dia en la PyME)")
        if not cumple:
            print(f"    [!] NINGUN candidato alcanza el presupuesto de "
                  f"{objetivo:.4f}/dia.")
            print("        Este es el umbral mas exigente de la lista, no una")
            print("        recomendacion que cumpla la meta. El ruido de fondo")
            print("        de LANL no permite bajar mas sin inundar de alertas.")
            print("        OJO: ese ruido viene de unos pocos origenes mal")
            print("        configurados, no de una tasa por equipo, asi que la")
            print("        traduccion lineal a la PyME es un limite superior")
            print("        pesimista. Ajusta sobre el trafico del propio tenant.")
        print()

    print("\n" + "=" * 78)
    print("A1 Y A2 SON COMPLEMENTARIOS, NO REDUNDANTES")
    print("=" * 78)
    print(f"  Rafagas de >=3 fallos que coinciden con una ventana de "
          f"red team: {r['rt_tocadas']}")
    if r["rt_tocadas"] == 0:
        print("  Cero, como se esperaba: el red team entro con credenciales")
        print("  validas (701 de 702 autenticaciones exitosas). A1 no lo ve,")
        print("  y A2 no ve fuerza bruta porque nunca la tuvo etiquetada.")
        print("  Cada regla cubre lo que la otra no puede.")
    else:
        print(f"  [!] {r['rt_tocadas']} coincidencias. Revisar: podria haber")
        print("      actividad de red team con fallos que A1 si detecta.")

    print("\n  NOTA sobre pares de ventanas contiguas:")
    print("  la columna 'con pares' cuenta tambien las rafagas repartidas")
    print("  entre dos ventanas consecutivas. La diferencia con la columna")
    print("  'ventanas' es cuanto se perderia usando bins fijos sin mirar")
    print("  el bin anterior, que es lo que pasaria en KQL con bin() a secas.")

    os.makedirs(DIR_SALIDA, exist_ok=True)
    salida = {
        "ventana_segundos": VENTANA,
        "equipos_referencia": equipos,
        "dias_calibracion": dias,
        "fondo": {"filtrados": r["filtrados"], "fallos": r["fallos"],
                  "ventanas_con_fallos": r["ventanas"]},
        "fuerza_bruta": {"candidatos": f_fb, "recomendado": rec_fb,
                         "cumple_presupuesto": cumple_fb},
        "spraying": {"candidatos": f_sp, "recomendado": rec_sp,
                     "cumple_presupuesto": cumple_sp},
        "presupuesto_por_dia": objetivo,
        "coincidencias_redteam": r["rt_tocadas"],
    }
    with open(os.path.join(DIR_SALIDA, "umbrales_fuerza_bruta.json"), "w",
              encoding="utf-8") as f:
        json.dump(salida, f, indent=2, ensure_ascii=False)
    print(f"\nUmbrales -> {DIR_SALIDA}/umbrales_fuerza_bruta.json")


if __name__ == "__main__":
    main()