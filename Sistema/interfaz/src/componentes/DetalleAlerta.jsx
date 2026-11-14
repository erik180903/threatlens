import "./DetalleAlerta.css";
import { CabeceraAlerta } from "./CabeceraAlerta";
import { BloqueDatos } from "./BloqueDatos";
import { CampoDato } from "./CampoDato";
import { TecnicasMitre } from "./TecnicasMitre";
import { ListaMotivos } from "./ListaMotivos";
import { formatearFecha } from "../utiles/fecha";
import { Recomendaciones } from "./Recomendaciones";

// Protocolo deducido del puerto, solo para mostrarlo en la cabecera.
// No participa en ninguna deteccion: es comodidad de lectura.
const PROTOCOLO_POR_PUERTO = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  3389: "RDP",
  5900: "VNC",
};

const ORIGEN_TEXTO = {
  modelo: "Modelo supervisado",
  regla: "Regla determinista",
  "modelo+regla": "Modelo y regla",
};

// Los campos de cada vector, repartidos en las dos tarjetas. 'destacar'
// marca los datos que son la evidencia del ataque; se pintan del color
// del nivel. El resto es contexto.
const BLOQUES = {
  acceso_remoto: {
    izquierda: {
      titulo: "Datos del evento",
      campos: [
        { etiqueta: "Equipo", clave: "equipo" },
        { etiqueta: "IP local", clave: "ip_local" },
        { etiqueta: "IP remota", clave: "ip_remota", destacar: true },
        { etiqueta: "Origen", clave: "origen" },
        { etiqueta: "Protocolo", clave: "protocolo" },
        { etiqueta: "Puerto", clave: "puerto", destacar: true },
        { etiqueta: "Usuario objetivo", clave: "cuenta" },
        { etiqueta: "Intentos fallidos", clave: "intentos_fallidos", destacar: true, ocultarCero: true },
        { etiqueta: "Cuentas distintas", clave: "cuentas_distintas", destacar: true, ocultarCero: true },
        { etiqueta: "Tipo de logon", clave: "tipo_logon" },
      ],
    },
    derecha: {
      titulo: "Análisis",
      campos: [
        { etiqueta: "Proceso", clave: "proceso", mono: true },
        { etiqueta: "Detección", clave: "origen_deteccion", mapa: ORIGEN_TEXTO },
        { etiqueta: "Modelo", clave: "modelo" },
        { etiqueta: "Tabla origen", clave: "tabla_origen" },
      ],
    },
  },

  malware: {
    izquierda: {
      titulo: "Datos del evento",
      campos: [
        { etiqueta: "Equipo", clave: "equipo" },
        { etiqueta: "Cuenta", clave: "cuenta" },
        { etiqueta: "Procesos", clave: "n_procesos", destacar: true },
        { etiqueta: "Desde", clave: "desde", fecha: true },
        { etiqueta: "Hasta", clave: "hasta", fecha: true },
        { etiqueta: "Detección", clave: "origen_deteccion", mapa: ORIGEN_TEXTO },
        { etiqueta: "Tabla origen", clave: "tabla_origen" },
      ],
    },
    derecha: {
      titulo: "Proceso involucrado",
      campos: [
        { etiqueta: "Proceso", clave: "proceso" },
        { etiqueta: "Línea de comando", clave: "linea_comando", mono: true, destacar: true },
        { etiqueta: "Ruta", clave: "ruta", mono: true },
        { etiqueta: "Proceso padre", clave: "proceso_padre" },
        { etiqueta: "SHA256", clave: "sha256", mono: true },
        { etiqueta: "Id. de instancia", clave: "actor_id", mono: true },
        { etiqueta: "Modelo", clave: "modelo" },
      ],
    },
  },

  phishing: {
    izquierda: {
      titulo: "Datos del correo",
      campos: [
        { etiqueta: "Remitente", clave: "remitente", destacar: true },
        { etiqueta: "Asunto", clave: "asunto" },
        { etiqueta: "Destinatario", clave: "destinatario" },
        { etiqueta: "Enlaces", clave: "urls", mono: true, destacar: true },
        { etiqueta: "Adjuntos", clave: "adjuntos", mono: true, destacar: true },
        { etiqueta: "Autenticación fallida", clave: "mecanismos_no_superados", destacar: true },
      ],
    },
    derecha: {
      titulo: "Análisis",
      campos: [
        { etiqueta: "Detección", clave: "origen_deteccion", mapa: ORIGEN_TEXTO },
        { etiqueta: "Severidad del modelo", clave: "severidad_modelo" },
        { etiqueta: "Modelo", clave: "modelo" },
        { etiqueta: "Prevalencia de calibración", clave: "prevalencia_calibracion" },
        { etiqueta: "Tabla origen", clave: "tabla_origen" },
      ],
    },
  },
};

// El dato que acompaña al equipo en la linea de la fecha.
function contextoDe(vector, evento) {
  if (vector === "acceso_remoto") {
    return evento.ip_remota || evento.origen || "";
  }
  if (vector === "malware") {
    return evento.cuenta || "";
  }
  if (vector === "phishing") {
    return evento.destinatario || "";
  }
  return "";
}

// El tercer chip de la cabecera.
function tecnicoDe(vector, evento) {
  if (vector === "acceso_remoto") {
    const protocolo =
      evento.protocolo || PROTOCOLO_POR_PUERTO[evento.puerto] || "";
    const partes = [];
    if (protocolo) {
      partes.push(protocolo);
    }
    if (evento.puerto) {
      partes.push("Puerto " + evento.puerto);
    }
    return partes.join(" · ");
  }
  if (vector === "malware") {
    return evento.proceso || "";
  }
  if (vector === "phishing") {
    return evento.remitente || "";
  }
  return "";
}

// Convierte el valor crudo del evento en algo que se pueda pintar.
// Devolver cadena vacia hace que CampoDato no dibuje la fila.
function valorDeCampo(fuente, campo) {
  const bruto = fuente[campo.clave];

  if (campo.ocultarCero && (bruto === 0 || bruto === "0")) {
    return "";
  }
  if (campo.mapa) {
    return campo.mapa[bruto] || bruto;
  }
  if (campo.fecha) {
    return formatearFecha(bruto);
  }
  if (Array.isArray(bruto)) {
    return bruto.join(", ");
  }
  return bruto;
}

export function DetalleAlerta(props) {
  const alerta = props.alerta;
  const resultado = alerta.resultado_analisis;
  const evento = resultado.evento;
  const vector = alerta.tipo_amenaza;
    const bloques = BLOQUES[vector];

  // La tarjeta derecha necesita el modelo y el origen de la deteccion,
  // que viven en resultado_analisis y no en evento. En lugar de que
  // cada campo declare de donde sale, se arma una sola fuente con los
  // dos juntos.
  const fuente = {
    ...evento,
    modelo: resultado.modelo,
    origen_deteccion: resultado.origen_deteccion,
  };

  function dibujarCampo(campo) {
    return (
      <CampoDato
        key={campo.clave}
        etiqueta={campo.etiqueta}
        valor={valorDeCampo(fuente, campo)}
        mono={campo.mono}
        destacar={campo.destacar}
      />
    );
  }

  // Un vector sin tabla no se dibuja a medias: se dice que falta.
  if (!bloques) {
    return (
      <p className="detalle-alerta__aviso">
        No hay una vista definida para el vector «{vector}».
      </p>
    );
  }

    return (
    <article
      className={"detalle-alerta detalle-alerta--" + alerta.nivel_severidad}
    >
      <CabeceraAlerta
        alerta={alerta}
        contexto={contextoDe(vector, evento)}
        tecnico={tecnicoDe(vector, evento)}
      />

      {evento.a2_fuera_de_rango ? (
        <p className="detalle-alerta__aviso">
          El modelo opera fuera de su rango de ajuste: este entorno declara
          menos equipos que los 17,684 sobre los que se entrenó. Su puntaje no
          es comparable con el reportado.
        </p>
      ) : null}

      <div className="detalle-alerta__columnas">
        <BloqueDatos titulo={bloques.izquierda.titulo}>
          {bloques.izquierda.campos.map(dibujarCampo)}
        </BloqueDatos>

        <BloqueDatos
          titulo={bloques.derecha.titulo}
          pie={
            <div>
              <h4 className="detalle-alerta__rotulo">MITRE ATT&CK</h4>
              <TecnicasMitre tecnicas={alerta.mitre} />
            </div>
          }
        >
          {bloques.derecha.campos.map(dibujarCampo)}
        </BloqueDatos>
      </div>

      <BloqueDatos titulo="Por qué se disparó">
        <ListaMotivos
          motivos={alerta.motivos}
          origen={resultado.origen_deteccion}
        />
      </BloqueDatos>

      <Recomendaciones recomendaciones={alerta.recomendaciones} />
    </article>
  );
}