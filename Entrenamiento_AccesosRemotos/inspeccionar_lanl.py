"""
inspeccionar_lanl.py
--------------------
Reconocimiento de los archivos de LANL antes de construir ventanas.

No genera nada todavia. Solo mide, y de esas mediciones dependen tres
decisiones que no se pueden tomar a ciegas:

  1. En que dias cae la actividad del red team  -> decide si la particion
     puede ser temporal o tiene que ser por equipo.
  2. Cuanto volumen queda al filtrar a logons remotos de cuentas humanas
     -> decide si el archivo cabe en memoria al agregar.
  3. Si los eventos del red team sobreviven a ese filtro -> si no
     sobreviven, nos quedariamos sin positivos y hay que rediseñar.

Esquemas (segun csr.lanl.gov/data/cyber1):

  auth.txt     time, src_user@dom, dst_user@dom, src_computer,
               dst_computer, auth_type, logon_type, auth_orientation,
               success/failure
  redteam.txt  time, user@dom, src_computer, dst_computer

Uso:
    python inspeccionar_lanl.py datos\\auth.txt.gz datos\\redteam.txt.gz
    python inspeccionar_lanl.py datos\\auth.txt.gz datos\\redteam.txt.gz --muestra 20000000

La opcion --muestra lee solo las primeras N lineas de auth.txt. Sirve para
una pasada rapida de prueba, pero OJO: el archivo esta ordenado por tiempo,
asi que una muestra solo cubre los primeros dias y sus proporciones estan
sesgadas. Los numeros definitivos salen de la pasada completa.
"""

import gzip
import os
import sys
from collections import Counter

# Tipos de logon de Windows que corresponden a acceso remoto.
# Son los mismos nombres que devuelve DeviceLogonEvents en Defender.
LOGON_REMOTOS = {b"Network", b"RemoteInteractive", b"NetworkCleartext"}

# Cada cuantas lineas se imprime avance.
AVANCE = 25_000_000

SEGUNDOS_POR_DIA = 86400


def dia(t):
    """LANL cuenta segundos desde 1. Devuelve el dia (1 = primer dia)."""
    return int(t) // SEGUNDOS_POR_DIA + 1


def abrir(ruta):
    """Abre .gz o texto plano, siempre en binario."""
    if ruta.endswith(".gz"):
        return gzip.open(ruta, "rb")
    return open(ruta, "rb")


# ----------------------------------------------------------------------
# redteam.txt  (archivo chico, se lee completo)
# ----------------------------------------------------------------------

def leer_redteam(ruta):
    eventos = []
    with abrir(ruta) as f:
        for linea in f:
            partes = linea.strip().split(b",")
            if len(partes) < 4:
                continue
            t, usuario, origen, destino = partes[0], partes[1], partes[2], partes[3]
            try:
                t = int(t)
            except ValueError:
                continue          # encabezado, si lo hubiera
            eventos.append((t, usuario, origen, destino))
    return eventos


def informe_redteam(eventos):
    print("=" * 70)
    print("REDTEAM.TXT")
    print("=" * 70)

    if not eventos:
        print("  [!] Vacio o ilegible. Revisa la ruta.")
        return set()

    tiempos = [e[0] for e in eventos]
    t_min, t_max = min(tiempos), max(tiempos)

    print(f"  eventos            : {len(eventos):,}")
    print(f"  usuarios distintos : {len({e[1] for e in eventos}):,}")
    print(f"  origenes distintos : {len({e[2] for e in eventos}):,}")
    print(f"  destinos distintos : {len({e[3] for e in eventos}):,}")
    print(f"  primer evento      : t={t_min:,}  (dia {dia(t_min)})")
    print(f"  ultimo evento      : t={t_max:,}  (dia {dia(t_max)})")
    print(f"  abarca             : {dia(t_max) - dia(t_min) + 1} dias")

    por_dia = Counter(dia(t) for t in tiempos)
    print(f"\n  distribucion por dia ({len(por_dia)} dias con actividad):")
    for d in sorted(por_dia):
        barra = "#" * min(50, por_dia[d])
        print(f"    dia {d:>3} | {por_dia[d]:>5}  {barra}")

    print("\n  -> Si la actividad se concentra en pocos dias, la particion")
    print("     temporal dejaria el conjunto de prueba sin positivos y hay")
    print("     que partir por equipo destino.")

    # Clave de cruce con auth.txt: (tiempo, usuario, origen, destino)
    return {(e[0], e[1], e[2], e[3]) for e in eventos}


# ----------------------------------------------------------------------
# auth.txt  (archivo grande, una sola pasada en streaming)
# ----------------------------------------------------------------------

def recorrer_auth(ruta, claves_rt, limite=None):
    total = 0
    t_min, t_max = None, None

    c_logon = Counter()
    c_auth = Counter()
    c_orient = Counter()
    c_exito = Counter()

    maquinas = 0          # cuentas de equipo (terminan en $)
    remotos = 0           # logon remoto
    remotos_humanos = 0   # logon remoto + cuenta no-maquina  <- el filtro real
    fallos_rh = 0

    rt_encontrados = 0
    rt_logon = Counter()
    rt_orient = Counter()
    rt_exito = Counter()
    rt_lado = Counter()   # la etiqueta casa con src_user o con dst_user?
    rt_pasa_filtro = 0

    print("=" * 70)
    print("AUTH.TXT")
    print("=" * 70)
    if limite:
        print(f"  [modo muestra: solo las primeras {limite:,} lineas]")
    print("  recorriendo...")

    with abrir(ruta) as f:
        for linea in f:
            total += 1
            if limite and total > limite:
                total -= 1
                break
            if total % AVANCE == 0:
                print(f"    {total:,} lineas")

            p = linea.rstrip(b"\n").split(b",")
            if len(p) < 9:
                continue
            try:
                t = int(p[0])
            except ValueError:
                continue      # encabezado

            src_user, dst_user = p[1], p[2]
            origen, destino = p[3], p[4]
            auth_type, logon_type, orient, exito = p[5], p[6], p[7], p[8]

            if t_min is None or t < t_min:
                t_min = t
            if t_max is None or t > t_max:
                t_max = t

            c_logon[logon_type] += 1
            c_auth[auth_type] += 1
            c_orient[orient] += 1
            c_exito[exito] += 1

            es_maquina = src_user.endswith(b"$") or b"$@" in src_user
            if es_maquina:
                maquinas += 1

            es_remoto = logon_type in LOGON_REMOTOS
            if es_remoto:
                remotos += 1
                if not es_maquina:
                    remotos_humanos += 1
                    if exito.startswith(b"Fail"):
                        fallos_rh += 1

            # Cruce con las etiquetas del red team
            if (t, src_user, origen, destino) in claves_rt:
                lado = "src_user"
            elif (t, dst_user, origen, destino) in claves_rt:
                lado = "dst_user"
            else:
                lado = None

            if lado:
                rt_encontrados += 1
                rt_lado[lado] += 1
                rt_logon[logon_type] += 1
                rt_orient[orient] += 1
                rt_exito[exito] += 1
                if es_remoto and not es_maquina:
                    rt_pasa_filtro += 1

    return {
        "total": total, "t_min": t_min, "t_max": t_max,
        "c_logon": c_logon, "c_auth": c_auth,
        "c_orient": c_orient, "c_exito": c_exito,
        "maquinas": maquinas, "remotos": remotos,
        "remotos_humanos": remotos_humanos, "fallos_rh": fallos_rh,
        "rt_encontrados": rt_encontrados, "rt_logon": rt_logon,
        "rt_orient": rt_orient, "rt_exito": rt_exito,
        "rt_lado": rt_lado, "rt_pasa_filtro": rt_pasa_filtro,
    }


def pct(parte, total):
    return f"{100.0 * parte / total:.2f}%" if total else "n/a"


def tabla(titulo, contador, total, tope=15):
    print(f"\n  {titulo}")
    for valor, n in contador.most_common(tope):
        etiqueta = valor.decode("utf-8", "replace") or "(vacio)"
        print(f"    {etiqueta:<24} {n:>15,}  {pct(n, total):>8}")
    if len(contador) > tope:
        print(f"    ... y {len(contador) - tope} valores mas")


def informe_auth(r, n_redteam):
    total = r["total"]

    print(f"\n  eventos leidos : {total:,}")
    if r["t_min"] is not None:
        print(f"  rango temporal : t={r['t_min']:,} a t={r['t_max']:,}"
              f"  (dia {dia(r['t_min'])} a dia {dia(r['t_max'])})")

    tabla("tipo de logon:", r["c_logon"], total)
    tabla("tipo de autenticacion:", r["c_auth"], total)
    tabla("orientacion:", r["c_orient"], total)
    tabla("resultado:", r["c_exito"], total)

    print("\n" + "-" * 70)
    print("  EFECTO DEL FILTRO  (logon remoto + cuenta no-maquina)")
    print("-" * 70)
    print(f"    cuentas de maquina ($)      {r['maquinas']:>15,}  {pct(r['maquinas'], total):>8}")
    print(f"    logon remoto                {r['remotos']:>15,}  {pct(r['remotos'], total):>8}")
    print(f"    remoto + humano  <= FILTRO  {r['remotos_humanos']:>15,}  {pct(r['remotos_humanos'], total):>8}")
    print(f"      de esos, fallidos         {r['fallos_rh']:>15,}  {pct(r['fallos_rh'], r['remotos_humanos']):>8}")
    print("\n    -> Este ultimo numero es el volumen real con el que vamos a")
    print("       trabajar al construir ventanas.")

    print("\n" + "-" * 70)
    print("  CRUCE CON LAS ETIQUETAS DEL RED TEAM")
    print("-" * 70)
    print(f"    eventos de redteam.txt            : {n_redteam:,}")
    print(f"    localizados en auth.txt           : {r['rt_encontrados']:,}")
    print(f"    que PASAN el filtro remoto+humano : {r['rt_pasa_filtro']:,}")

    if r["rt_lado"]:
        print("\n    la etiqueta casa con:")
        for lado, n in r["rt_lado"].most_common():
            print(f"      {lado:<12} {n:>8,}")

    if r["rt_logon"]:
        tabla("tipo de logon de los eventos del red team:",
              r["rt_logon"], r["rt_encontrados"])
        tabla("resultado de los eventos del red team:",
              r["rt_exito"], r["rt_encontrados"])

    print("\n" + "=" * 70)
    print("  LECTURA")
    print("=" * 70)

    if r["rt_encontrados"] == 0:
        print("  [!] No se localizo ningun evento del red team dentro de auth.txt.")
        print("      Casi seguro es desajuste de formato (separador, campo de")
        print("      usuario distinto). Hay que revisar antes de seguir.")
    elif r["rt_pasa_filtro"] == 0:
        print("  [!] Los eventos del red team NO sobreviven al filtro de logon")
        print("      remoto. Hay que ampliar LOGON_REMOTOS o quitar el filtro.")
    elif r["rt_pasa_filtro"] < r["rt_encontrados"]:
        perdidos = r["rt_encontrados"] - r["rt_pasa_filtro"]
        print(f"  [!] El filtro descarta {perdidos:,} positivos de "
              f"{r['rt_encontrados']:,}.")
        print("      Revisa arriba que tipos de logon usa el red team y decide")
        print("      si conviene ampliar LOGON_REMOTOS.")
    else:
        print("  [OK] Todos los eventos del red team sobreviven al filtro.")
        print("       Se puede proceder a construir ventanas.")

    if r["remotos_humanos"]:
        razon = r["rt_pasa_filtro"] / r["remotos_humanos"] if r["rt_pasa_filtro"] else 0
        if razon:
            print(f"\n  Desbalance a nivel evento: 1 positivo por cada "
                  f"{1 / razon:,.0f} eventos.")
            print("  Confirma que hay que submuestrear negativos para entrenar y")
            print("  evaluar sobre la proporcion real.")


# ----------------------------------------------------------------------

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)

    ruta_auth, ruta_rt = args[0], args[1]

    limite = None
    if "--muestra" in sys.argv:
        i = sys.argv.index("--muestra")
        if i + 1 < len(sys.argv):
            limite = int(sys.argv[i + 1])

    for ruta in (ruta_auth, ruta_rt):
        if not os.path.exists(ruta):
            print(f"[!] No existe: {ruta}")
            sys.exit(1)
        print(f"  {ruta}  ({os.path.getsize(ruta) / 1e9:.2f} GB)")
    print()

    eventos_rt = leer_redteam(ruta_rt)
    claves_rt = informe_redteam(eventos_rt)
    print()

    r = recorrer_auth(ruta_auth, claves_rt, limite)
    informe_auth(r, len(eventos_rt))


if __name__ == "__main__":
    main()
