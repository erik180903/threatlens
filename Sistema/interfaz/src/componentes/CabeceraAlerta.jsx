import "./CabeceraAlerta.css";
import { NivelBadge } from "./NivelBadge";
import { EtiquetaVector } from "./EtiquetaVector";
import { formatearFecha } from "../utiles/fecha";

// Lo que va en el recuadro de la derecha. Una alerta del modelo lleva
// su probabilidad. Una de regla no tiene ninguna, y poner un numero
// ahi seria presentar como medicion algo que nadie midio: la regla de
// fuerza bruta cuenta intentos, no estima probabilidades.
function Veredicto(props) {
  const probabilidad = props.probabilidad;
  const reglas = props.reglas || [];

  if (probabilidad === null || probabilidad === undefined) {
    return (
      <div className="veredicto">
        <span className="veredicto__rotulo">Detección</span>
        <span className="veredicto__texto">
          {reglas.length > 0 ? "Regla determinista" : "Sin modelo"}
        </span>
      </div>
    );
  }

  return (
    <div className="veredicto">
      <span className="veredicto__rotulo">Probabilidad</span>
      <span className="veredicto__numero">{probabilidad.toFixed(2)}</span>
    </div>
  );
}

export function CabeceraAlerta(props) {
  const alerta = props.alerta;
  const resultado = alerta.resultado_analisis;
  const contexto = props.contexto;
  const tecnico = props.tecnico;

  return (
    <header className="cabecera-alerta">
      <div className="cabecera-alerta__principal">
        <span className="cabecera-alerta__id">{alerta.id}</span>
        <h1 className="cabecera-alerta__titulo">{alerta.descripcion}</h1>

        <p className="cabecera-alerta__meta">
          <span>{alerta.equipo}</span>
                    {contexto ? (
            <>
              <span className="cabecera-alerta__punto">·</span>
              <span>{contexto}</span>
            </>
          ) : null}
          <span className="cabecera-alerta__punto">·</span>
          <span>{formatearFecha(alerta.fecha)}</span>

          {alerta.n_eventos > 1 ? (
            <>
              <span className="cabecera-alerta__punto">·</span>
              <span>{alerta.n_eventos} eventos agrupados</span>
            </>
          ) : null}
        </p>
        <div className="cabecera-alerta__etiquetas">
          <NivelBadge nivel={alerta.nivel_severidad} />
          <EtiquetaVector vector={alerta.tipo_amenaza} />
          {tecnico ? (
            <span className="cabecera-alerta__tecnico">{tecnico}</span>
          ) : null}
        </div>
      </div>

      <div className="cabecera-alerta__lateral">
        <Veredicto
          probabilidad={resultado.probabilidad}
          reglas={resultado.reglas}
        />
      </div>
    </header>
  );
}