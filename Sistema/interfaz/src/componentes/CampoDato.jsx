import "./CampoDato.css";

export function CampoDato(props) {
  const etiqueta = props.etiqueta;
  const valor = props.valor;
  const mono = props.mono;
  const destacar = props.destacar;

  // Un campo sin valor no se dibuja. La telemetria no siempre trae
  // todos los campos --el corpus OpTC no da SHA256, por ejemplo-- y
  // una etiqueta con nada al lado solo ocupa espacio y hace dudar al
  // analista de si fallo la pantalla o si de verdad no hay dato.
  if (valor === null || valor === undefined || valor === "") {
    return null;
  }

  // Las clases se arman sumando en vez de con ternarios anidados: asi
  // agregar otra variante despues es agregar un if, no rehacer la
  // expresion completa.
  let clases = "campo-dato__valor";
  if (mono) {
    clases = clases + " campo-dato__valor--mono";
  }
  if (destacar) {
    clases = clases + " campo-dato__valor--destacado";
  }

  return (
    <div className="campo-dato">
      <span className="campo-dato__etiqueta">{etiqueta}</span>
      <span className={clases}>{valor}</span>
    </div>
  );
}