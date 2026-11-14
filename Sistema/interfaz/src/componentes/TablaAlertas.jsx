import "./TablaAlertas.css";
import { NivelBadge } from "./NivelBadge";
import { EtiquetaVector } from "./EtiquetaVector";
import { formatearFecha } from "../utiles/fecha";

export function TablaAlertas(props) {
  const alertas = props.alertas;
  const seleccionada = props.seleccionada;
  const alSeleccionar = props.alSeleccionar;

  if (alertas.length === 0) {
    return <p className="tabla-alertas__vacio">No hay alertas que mostrar.</p>;
  }

  return (
    <div className="tabla-alertas__marco">
      <table className="tabla-alertas">
        <thead>
          <tr>
            <th>Fecha</th>
            <th>Descripción</th>
            <th>Vector</th>
            <th>Equipo</th>
            <th>Riesgo</th>
            <th className="tabla-alertas__num">Prob.</th>
          </tr>
        </thead>
        <tbody>
          {alertas.map(function (a) {
            const resultado = a.resultado_analisis;
            const probabilidad = resultado.probabilidad;
            const esActual = a.id === seleccionada;

            return (
              <tr
                key={a.id}
                className={esActual ? "fila fila--actual" : "fila"}
                tabIndex={0}
                onClick={function () {
                  alSeleccionar(a.id);
                }}
                onKeyDown={function (e) {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    alSeleccionar(a.id);
                  }
                }}
              >
                <td className="fila__fecha">{formatearFecha(a.fecha)}</td>
                <td className="fila__descripcion">{a.descripcion}</td>
                <td>
                  <EtiquetaVector vector={a.tipo_amenaza} />
                </td>
                <td className="fila__equipo">{a.equipo}</td>
                <td>
                  <NivelBadge nivel={a.nivel_severidad} />
                </td>
                <td className="tabla-alertas__num">
                  {probabilidad === null || probabilidad === undefined
                    ? "—"
                    : probabilidad.toFixed(2)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}