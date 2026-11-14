import "./FiltrosAlertas.css";

const VECTORES = [
  { valor: "todos", texto: "Todos los vectores" },
  { valor: "phishing", texto: "Phishing" },
  { valor: "acceso_remoto", texto: "Acceso remoto" },
  { valor: "malware", texto: "Archivo malicioso" },
];

const NIVELES = [
  { valor: "todos", texto: "Todas las severidades" },
  { valor: "alto", texto: "Alto riesgo" },
  { valor: "medio", texto: "Riesgo medio" },
  { valor: "bajo", texto: "Riesgo bajo" },
];

export const FILTROS_VACIOS = { vector: "todos", nivel: "todos", texto: "" };

export function FiltrosAlertas(props) {
  const filtros = props.filtros;
  const ponFiltros = props.ponFiltros;

  // Se construye un objeto NUEVO con los filtros anteriores y el campo
  // cambiado. Modificar el que ya existe no serviria: React compara
  // por identidad, y un objeto modificado sigue siendo el mismo objeto.
  function cambiar(campo, valor) {
    ponFiltros({ ...filtros, [campo]: valor });
  }

  const hayFiltro =
    filtros.vector !== "todos" ||
    filtros.nivel !== "todos" ||
    filtros.texto !== "";

  return (
    <div className="filtros">
      <input
        className="filtros__texto"
        type="search"
        placeholder="Buscar por descripción, equipo o identificador…"
        value={filtros.texto}
        onChange={function (e) {
          cambiar("texto", e.target.value);
        }}
      />

      <select
        className="filtros__select"
        value={filtros.vector}
        onChange={function (e) {
          cambiar("vector", e.target.value);
        }}
      >
        {VECTORES.map(function (v) {
          return (
            <option key={v.valor} value={v.valor}>
              {v.texto}
            </option>
          );
        })}
      </select>

      <select
        className="filtros__select"
        value={filtros.nivel}
        onChange={function (e) {
          cambiar("nivel", e.target.value);
        }}
      >
        {NIVELES.map(function (n) {
          return (
            <option key={n.valor} value={n.valor}>
              {n.texto}
            </option>
          );
        })}
      </select>

      {hayFiltro ? (
        <button
          className="filtros__limpiar"
          type="button"
          onClick={function () {
            ponFiltros(FILTROS_VACIOS);
          }}
        >
          Limpiar
        </button>
      ) : null}
    </div>
  );
}