import "./NivelBadge.css";

// El texto que ve el usuario para cada nivel. Se pone en una tabla y
// no en una cadena de if/else porque asi agregar o cambiar un nivel
// es editar una linea, no tocar logica.
const ETIQUETAS = {
  alto: "Alto riesgo",
  medio: "Riesgo medio",
  bajo: "Riesgo bajo",
};

export function NivelBadge(props) {
  const nivel = props.nivel;

  // Si llegara un nivel que no conocemos, se muestra tal cual en vez
  // de dejar el hueco vacio. Un valor raro visible es mas facil de
  // diagnosticar que uno invisible.
  const texto = ETIQUETAS[nivel] || nivel;

  return (
    <span className={`nivel-badge nivel-badge--${nivel}`}>
      {texto}
    </span>
  );
}