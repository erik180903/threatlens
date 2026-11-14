import "./ListaMotivos.css";

export function ListaMotivos(props) {
  const motivos = props.motivos || [];
  const origen = props.origen;

  if (motivos.length === 0) {
    return null;
  }

  return (
    <div className="lista-motivos">
      <ul className="lista-motivos__items">
        {motivos.map(function (m, i) {
          return <li key={m + i}>{m}</li>;
        })}
      </ul>

      {origen !== "regla" ? (
        <p className="lista-motivos__nota">
          Las razones son la contribución de cada característica al puntaje,
          no una explicación causal del comportamiento.
        </p>
      ) : null}
    </div>
  );
}