"""
construir_ventanas.py
---------------------
Convierte auth.txt.gz en ventanas con caracteristicas, listas para entrenar.

UNIDAD DE ANALISIS
    (usuario, equipo origen, equipo destino, hora)

    Una fila de salida = toda la actividad de autenticacion de ese triple
    durante esa hora. Coincide con la granularidad de redteam.txt, que
    etiqueta justamente (time, user, src_computer, dst_computer).

COMO SE EVITA LA FUGA TEMPORAL
    El archivo viene ordenado por tiempo. El bucle procesa hora por hora:

        1. acumula los eventos de la hora en curso
        2. al cambiar de hora, EMITE las ventanas usando el historial
        3. DESPUES incorpora esa hora al historial
        4. vacia el buffer

    El orden de 2 y 3 es lo que importa: cuando se calculan las
    caracteristicas historicas de una ventana, el historial no contiene
    ningun evento de esa hora ni de ninguna posterior. No es una regla
    que haya que acordarse de respetar; es la estructura del bucle.

MEMORIA
    Nunca se guardan los 292 millones de eventos. Solo:
      - el buffer de una hora (~200 mil eventos en promedio)
      - diccionarios de historial con claves enteras

    Usuarios y equipos se codifican a enteros al vuelo para que los
    diccionarios no guarden cadenas repetidas.

DESBALANCE
    Se conservan TODAS las ventanas positivas y una fraccion aleatoria de
    las negativas (por omision 2%). El muestreo uniforme de negativos deja
    el recall y el FPR insesgados; la precision se reconstruye despues con
    la formula de prevalencia, igual que en phishing.

Uso:
    python construir_ventanas.py datos\\auth.txt.gz datos\\redteam.txt.gz ventanas.csv
    python construir_ventanas.py datos\\auth.txt.gz datos\\redteam.txt.gz ventanas.csv --tasa 0.05
    python construir_ventanas.py datos\\auth.txt.gz datos\\redteam.txt.gz prueba.csv --muestra 20000000
"""

import gzip
import os
import random
import sys
from collections import Counter, defaultdict

# --------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------

# Tipos de logon de Windows que corresponden a acceso remoto.
# Verificado sobre el archivo completo: los 702 eventos del red team
# localizados en auth.txt son de tipo Network, asi que ninguno se pierde.
LOGON_REMOTOS = {b"Network", b"RemoteInteractive", b"NetworkCleartext"}

SEGUNDOS_POR_HORA = 3600
SEGUNDOS_POR_DIA = 86400

TASA_NEGATIVOS = 0.02     # fraccion de ventanas negativas que se conserva
SEMILLA = 42
AVANCE = 25_000_000

# Multiplicador para empacar dos ids en una sola clave entera.
BASE = 1_000_000


# --------------------------------------------------------------------
# Nombres de las caracteristicas, en orden canonico.
# Este orden es el contrato: entrenamiento e inferencia lo comparten.
# --------------------------------------------------------------------

NOMBRES_VENTANA = [
    "ven_eventos",            # total de eventos del triple en la hora
    "ven_logon",              # orientacion LogOn
    "ven_logoff",             # orientacion LogOff
    "ven_tgs",                # ticket de servicio Kerberos
    "ven_tgt",                # ticket de concesion Kerberos
    "ven_fallos",             # resultado Fail
    "ven_tasa_fallo",         # fallos / eventos
    "ven_tipos_logon",        # tipos de logon distintos
    "ven_frac_network",       # proporcion de logons Network
    "ven_frac_remoteint",     # proporcion de RemoteInteractive
    "ven_frac_ntlm",          # NTLM en entorno Kerberos: indicio de pass-the-hash
    "ven_frac_kerberos",
    "ven_duracion",           # segundos entre el primer y ultimo evento
    "ven_hora_dia",           # 0-23
]

NOMBRES_HIST_USUARIO = [
    "his_usr_eventos",        # eventos previos de este usuario
    "his_usr_destinos",       # destinos distintos que ya habia tocado
    "his_usr_origenes",       # origenes distintos que ya habia usado
    "his_par_visto",          # veces que este usuario toco este destino antes
    "his_par_nuevo",          # 1 si nunca lo habia tocado
    "his_origen_visto",       # veces que uso este origen antes
    "his_origen_nuevo",       # 1 si nunca lo habia usado
    "his_frac_destino",       # his_par_visto / his_usr_eventos
    "his_usr_frac_hora",      # proporcion de su actividad previa en esta hora del dia
]

NOMBRES_HIST_DESTINO = [
    "his_dst_eventos",        # eventos previos contra este destino
    "his_dst_usuarios",       # usuarios distintos que ya lo habian tocado
    "his_dst_nuevo",          # 1 si el destino no tenia historial
    "his_frac_usr_en_dst",    # his_par_visto / his_dst_eventos
    "his_dst_por_usuario",    # his_dst_eventos / his_dst_usuarios
]

NOMBRES_CONCURRENCIA = [
    "con_destinos_usr",       # destinos distintos del usuario EN ESTA hora
    "con_origenes_usr",       # origenes distintos del usuario en esta hora
    "con_eventos_usr",        # eventos totales del usuario en esta hora
    "con_usuarios_dst",       # usuarios distintos contra el destino en esta hora
    "con_eventos_dst",        # eventos totales contra el destino en esta hora
    "con_destinos_nuevos_usr",  # de esos destinos, cuantos no tenian historial
]

NOMBRES = (NOMBRES_VENTANA + NOMBRES_HIST_USUARIO
           + NOMBRES_HIST_DESTINO + NOMBRES_CONCURRENCIA)

GRUPOS = {
    "ventana": NOMBRES_VENTANA,
    "historial_usuario": NOMBRES_HIST_USUARIO,
    "historial_destino": NOMBRES_HIST_DESTINO,
    "concurrencia": NOMBRES_CONCURRENCIA,
}


# --------------------------------------------------------------------
# Codificacion de nombres a enteros
# --------------------------------------------------------------------

class Catalogo:
    """Asigna un entero a cada cadena vista. Evita guardar cadenas
    repetidas en los diccionarios de historial."""

    def __init__(self):
        self.ids = {}
        self.nombres = []

    def id(self, s):
        v = self.ids.get(s)
        if v is None:
            v = len(self.nombres)
            self.ids[s] = v
            self.nombres.append(s)
        return v

    def __len__(self):
        return len(self.nombres)


# --------------------------------------------------------------------
# redteam.txt
# --------------------------------------------------------------------

def abrir(ruta):
    return gzip.open(ruta, "rb") if ruta.endswith(".gz") else open(ruta, "rb")


def cargar_redteam(ruta, cat_usr, cat_eq):
    """Devuelve el conjunto de ventanas positivas, ya en espacio de ids.

    Los ids se asignan aqui, antes de recorrer auth.txt, para que al
    comparar durante el recorrido ya existan.
    """
    ventanas = set()
    n = 0
    with abrir(ruta) as f:
        for linea in f:
            p = linea.strip().split(b",")
            if len(p) < 4:
                continue
            try:
                t = int(p[0])
            except ValueError:
                continue
            n += 1
            u = cat_usr.id(p[1])
            o = cat_eq.id(p[2])
            d = cat_eq.id(p[3])
            ventanas.add((u, o, d, t // SEGUNDOS_POR_HORA))
    return ventanas, n


# --------------------------------------------------------------------
# Historial
# --------------------------------------------------------------------

class Historial:
    """Estado acumulado de todas las horas ya procesadas.

    Los contadores de 'distintos' se mantienen incrementalmente: cuando
    aparece un par (usuario, destino) que no estaba, se suma 1 a los
    distintos del usuario y 1 a los del destino. Asi no hace falta
    guardar conjuntos."""

    def __init__(self):
        # dict normal, no defaultdict: con defaultdict una consulta fallida
        # crea la entrada, y estos dos son los diccionarios que crecen.
        self.par_usr_dst = {}                 # usuario*BASE+destino -> veces
        self.par_usr_org = {}                 # usuario*BASE+origen  -> veces
        self.usr_eventos = defaultdict(int)
        self.usr_destinos = defaultdict(int)
        self.usr_origenes = defaultdict(int)
        self.dst_eventos = defaultdict(int)
        self.dst_usuarios = defaultdict(int)
        self.usr_hora = defaultdict(int)      # usuario*100+hora_del_dia -> veces

    def incorporar(self, eventos):
        for (u, o, d, hd, _ori, _lt, _at, _fa, _t) in eventos:
            ku = u * BASE + d
            visto = self.par_usr_dst.get(ku)
            if visto is None:
                self.usr_destinos[u] += 1
                self.dst_usuarios[d] += 1
                self.par_usr_dst[ku] = 1
            else:
                self.par_usr_dst[ku] = visto + 1

            ko = u * BASE + o
            visto_o = self.par_usr_org.get(ko)
            if visto_o is None:
                self.usr_origenes[u] += 1
                self.par_usr_org[ko] = 1
            else:
                self.par_usr_org[ko] = visto_o + 1

            self.usr_eventos[u] += 1
            self.dst_eventos[d] += 1
            self.usr_hora[u * 100 + hd] += 1


# --------------------------------------------------------------------
# Construccion de las ventanas de una hora
# --------------------------------------------------------------------

def ventanas_de_la_hora(eventos, hist, hora):
    """Agrupa los eventos de una hora en ventanas y calcula sus
    caracteristicas. 'hist' contiene SOLO horas anteriores."""

    # --- agrupacion por triple -------------------------------------
    triples = defaultdict(list)
    for ev in eventos:
        triples[(ev[0], ev[1], ev[2])].append(ev)

    # --- contexto concurrente de la hora ----------------------------
    usr_destinos_h = defaultdict(set)
    usr_origenes_h = defaultdict(set)
    usr_eventos_h = Counter()
    dst_usuarios_h = defaultdict(set)
    dst_eventos_h = Counter()

    for (u, o, d) in triples:
        usr_destinos_h[u].add(d)
        usr_origenes_h[u].add(o)
        dst_usuarios_h[d].add(u)
    for (u, o, d), evs in triples.items():
        usr_eventos_h[u] += len(evs)
        dst_eventos_h[d] += len(evs)

    # destinos de esta hora que el usuario nunca habia tocado
    nuevos_por_usr = {}
    for u, destinos in usr_destinos_h.items():
        nuevos_por_usr[u] = sum(
            1 for d in destinos if hist.par_usr_dst.get(u * BASE + d, 0) == 0)

    filas = []
    hora_dia = hora % 24

    for (u, o, d), evs in triples.items():
        n = len(evs)

        logon = logoff = tgs = tgt = fallos = 0
        network = remoteint = ntlm = kerb = 0
        tipos = set()
        t_min = t_max = evs[0][8]

        for (_u, _o, _d, _hd, ori, lt, at, fa, t) in evs:
            if ori == b"LogOn":
                logon += 1
            elif ori == b"LogOff":
                logoff += 1
            elif ori == b"TGS":
                tgs += 1
            elif ori == b"TGT":
                tgt += 1
            if fa:
                fallos += 1
            tipos.add(lt)
            if lt == b"Network":
                network += 1
            elif lt == b"RemoteInteractive":
                remoteint += 1
            if at == b"NTLM":
                ntlm += 1
            elif at == b"Kerberos":
                kerb += 1
            if t < t_min:
                t_min = t
            if t > t_max:
                t_max = t

        # --- historial (solo horas anteriores) ----------------------
        par = hist.par_usr_dst.get(u * BASE + d, 0)
        org = hist.par_usr_org.get(u * BASE + o, 0)
        ue = hist.usr_eventos.get(u, 0)
        de = hist.dst_eventos.get(d, 0)
        du = hist.dst_usuarios.get(d, 0)
        uh = hist.usr_hora.get(u * 100 + hora_dia, 0)

        fila = [
            # ventana
            n, logon, logoff, tgs, tgt, fallos,
            fallos / n,
            len(tipos),
            network / n, remoteint / n, ntlm / n, kerb / n,
            t_max - t_min,
            hora_dia,
            # historial usuario
            ue,
            hist.usr_destinos.get(u, 0),
            hist.usr_origenes.get(u, 0),
            par,
            1 if par == 0 else 0,
            org,
            1 if org == 0 else 0,
            par / ue if ue else 0.0,
            uh / ue if ue else 0.0,
            # historial destino
            de,
            du,
            1 if de == 0 else 0,
            par / de if de else 0.0,
            de / du if du else 0.0,
            # concurrencia
            len(usr_destinos_h[u]),
            len(usr_origenes_h[u]),
            usr_eventos_h[u],
            len(dst_usuarios_h[d]),
            dst_eventos_h[d],
            nuevos_por_usr[u],
        ]
        filas.append(((u, o, d), fila))

    return filas


# --------------------------------------------------------------------
# Recorrido principal
# --------------------------------------------------------------------

def construir(ruta_auth, rt_ventanas, cat_usr, cat_eq, salida,
              tasa_neg, limite=None):

    rnd = random.Random(SEMILLA)
    hist = Historial()

    total_leidos = 0
    total_filtrados = 0
    n_ventanas = 0
    n_pos = 0
    n_neg_escritas = 0
    pos_por_dia = Counter()
    rt_orient = Counter()      # lo que falto medir en el reconocimiento
    rt_lt = Counter()

    buffer = []
    hora_actual = None

    f_sal = open(salida, "w", encoding="utf-8", newline="")
    f_sal.write("dia,hora,usuario,origen,destino," + ",".join(NOMBRES) + ",etiqueta\n")

    def volcar(hora):
        nonlocal n_ventanas, n_pos, n_neg_escritas
        if not buffer:
            return
        for (u, o, d), fila in ventanas_de_la_hora(buffer, hist, hora):
            n_ventanas += 1
            es_pos = (u, o, d, hora) in rt_ventanas
            if es_pos:
                n_pos += 1
                pos_por_dia[hora * SEGUNDOS_POR_HORA // SEGUNDOS_POR_DIA + 1] += 1
            elif rnd.random() >= tasa_neg:
                continue
            else:
                n_neg_escritas += 1
            dia = hora * SEGUNDOS_POR_HORA // SEGUNDOS_POR_DIA + 1
            f_sal.write(
                f"{dia},{hora},{u},{o},{d},"
                + ",".join(f"{v:.6g}" if isinstance(v, float) else str(v)
                           for v in fila)
                + f",{1 if es_pos else 0}\n")

    print("  recorriendo auth.txt...")
    with abrir(ruta_auth) as f:
        for linea in f:
            total_leidos += 1
            if limite and total_leidos > limite:
                total_leidos -= 1
                break
            if total_leidos % AVANCE == 0:
                # el tamaño de los diccionarios de historial es lo unico que
                # crece sin tope; si se dispara, se ve aqui
                print(f"    {total_leidos:,} lineas  |  "
                      f"{n_ventanas:,} ventanas  |  {n_pos} positivas  |  "
                      f"historial {len(hist.par_usr_dst):,} pares")

            p = linea.rstrip(b"\n").split(b",")
            if len(p) < 9:
                continue
            try:
                t = int(p[0])
            except ValueError:
                continue

            src_user = p[1]
            logon_type = p[6]

            # filtro: logon remoto + cuenta de persona
            if logon_type not in LOGON_REMOTOS:
                continue
            if src_user.endswith(b"$") or b"$@" in src_user:
                continue

            total_filtrados += 1

            u = cat_usr.id(src_user)
            o = cat_eq.id(p[3])
            d = cat_eq.id(p[4])
            hora = t // SEGUNDOS_POR_HORA

            if hora_actual is None:
                hora_actual = hora
            elif hora != hora_actual:
                volcar(hora_actual)           # 2. emite con el historial previo
                hist.incorporar(buffer)       # 3. recien ahora incorpora
                buffer = []
                hora_actual = hora

            # medicion que falto en el reconocimiento
            if (u, o, d, hora) in rt_ventanas:
                rt_orient[p[7]] += 1
                rt_lt[logon_type] += 1

            buffer.append((u, o, d, hora % 24, p[7], logon_type, p[5],
                           p[8].startswith(b"Fail"), t))

    if buffer:
        volcar(hora_actual)
        hist.incorporar(buffer)

    f_sal.close()

    return {
        "leidos": total_leidos, "filtrados": total_filtrados,
        "ventanas": n_ventanas, "positivas": n_pos,
        "negativas_escritas": n_neg_escritas,
        "pos_por_dia": pos_por_dia,
        "rt_orient": rt_orient, "rt_lt": rt_lt,
        "usuarios": len(cat_usr), "equipos": len(cat_eq),
    }


# --------------------------------------------------------------------

def informe(r, n_rt, salida, tasa_neg):
    print("\n" + "=" * 70)
    print("RESULTADO")
    print("=" * 70)
    print(f"  eventos leidos        : {r['leidos']:,}")
    print(f"  pasan el filtro       : {r['filtrados']:,}")
    print(f"  usuarios distintos    : {r['usuarios']:,}")
    print(f"  equipos distintos     : {r['equipos']:,}")

    print(f"\n  ventanas construidas  : {r['ventanas']:,}")
    print(f"    positivas           : {r['positivas']:,}")
    print(f"    negativas           : {r['ventanas'] - r['positivas']:,}")
    if r["ventanas"]:
        prev = r["positivas"] / r["ventanas"]
        print(f"    prevalencia real    : {prev:.8f}"
              + (f"   (1 de cada {1/prev:,.0f})" if prev else ""))

    print(f"\n  escritas en {salida}:")
    print(f"    positivas           : {r['positivas']:,}   (todas)")
    print(f"    negativas           : {r['negativas_escritas']:,}   "
          f"(muestreo {tasa_neg:.1%})")
    print(f"    TASA_NEGATIVOS      : {tasa_neg}")
    print("\n    -> Guarda esta tasa. El recall y el FPR medidos sobre este")
    print("       archivo son insesgados, pero la precision hay que")
    print("       reconstruirla con la formula de prevalencia.")

    print("\n  ventanas positivas por dia:")
    for d in sorted(r["pos_por_dia"]):
        print(f"    dia {d:>3} | {r['pos_por_dia'][d]:>5}")

    ent = sum(n for d, n in r["pos_por_dia"].items() if d <= 16)
    pru = sum(n for d, n in r["pos_por_dia"].items() if 17 <= d <= 30)
    ben = sum(n for d, n in r["pos_por_dia"].items() if d >= 31)
    print(f"\n    dias  1-16 (entrenamiento) : {ent:>5} positivas")
    print(f"    dias 17-30 (prueba)        : {pru:>5} positivas")
    print(f"    dias 31-58 (benigno puro)  : {ben:>5} positivas"
          + ("   <- correcto, debe ser 0" if ben == 0 else "   <- [!] revisar"))

    print("\n" + "-" * 70)
    print("  ORIENTACION DE LOS EVENTOS DEL RED TEAM")
    print("  (la medicion que falto en el reconocimiento)")
    print("-" * 70)
    tot = sum(r["rt_orient"].values())
    if tot:
        for v, n in r["rt_orient"].most_common():
            print(f"    {v.decode('utf-8','replace'):<16} {n:>6}  "
                  f"{100.0*n/tot:>6.2f}%")
    else:
        print("    [!] No se localizo ningun evento del red team.")

    if r["positivas"] == 0:
        print("\n  [!] Cero ventanas positivas. No se puede entrenar.")
    elif pru < 20:
        print(f"\n  [!] Solo {pru} positivas en el conjunto de prueba.")
        print("      El recall tendra un intervalo de confianza amplio;")
        print("      hay que reportarlo con intervalo, no como numero seco.")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 3:
        print(__doc__)
        sys.exit(1)

    ruta_auth, ruta_rt, salida = args[0], args[1], args[2]

    tasa = TASA_NEGATIVOS
    if "--tasa" in sys.argv:
        tasa = float(sys.argv[sys.argv.index("--tasa") + 1])
    limite = None
    if "--muestra" in sys.argv:
        limite = int(sys.argv[sys.argv.index("--muestra") + 1])

    for ruta in (ruta_auth, ruta_rt):
        if not os.path.exists(ruta):
            print(f"[!] No existe: {ruta}")
            sys.exit(1)

    print(f"  caracteristicas : {len(NOMBRES)}")
    for g, cols in GRUPOS.items():
        print(f"    {g:<20} {len(cols):>3}")
    if limite:
        print(f"  [modo muestra: {limite:,} lineas]")
    print()

    cat_usr, cat_eq = Catalogo(), Catalogo()
    rt_ventanas, n_rt = cargar_redteam(ruta_rt, cat_usr, cat_eq)
    print(f"  redteam.txt: {n_rt:,} eventos -> "
          f"{len(rt_ventanas):,} ventanas positivas posibles\n")

    r = construir(ruta_auth, rt_ventanas, cat_usr, cat_eq,
                  salida, tasa, limite)
    informe(r, n_rt, salida, tasa)


if __name__ == "__main__":
    main()