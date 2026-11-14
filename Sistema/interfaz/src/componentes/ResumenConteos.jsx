import "./ResumenConteos.css";

const TARJETAS = [
  { clave: "todos", texto: "Total de alertas", color: "neutro" },
  { clave: "phishing", texto: "Phishing", color: "primario" },
  { clave: "acceso_remoto", texto: "Accesos remotos", color: "admin" },
  { clave: "malware", texto: "Archivos maliciosos", color: "activo" },
];

// Iconos dibujados aqui mismo, con trazo y sin relleno, para que
// hereden el color de la tarjeta. Son formas genericas: un triangulo
// de aviso, un sobre, un escudo y un documento.
const ICONOS = {
  todos: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3.5 21 20H3Z" />
      <path d="M12 10v4" />
      <path d="M12 16.9v.1" />
    </svg>
  ),
  phishing: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 6h18v12H3Z" />
      <path d="m3 7 9 6 9-6" />
    </svg>
  ),
  acceso_remoto: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3.2 19 6v5c0 4.2-2.9 7.3-7 8.4-4.1-1.1-7-4.2-7-8.4V6Z" />
      <path d="M9.3 12.2 11.3 14l3.6-3.8" />
    </svg>
  ),
  malware: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M6 3h8l4 4v14H6Z" />
      <path d="M14 3v4h4" />
      <path d="M9.5 12h5" />
      <path d="M9.5 15.5h3" />
    </svg>
  ),
};

export function ResumenConteos(props) {
  const alertas = props.alertas;
  const vectorActivo = props.vectorActivo;
  const alElegir = props.alElegir;

  // Se parte de cero en los tres vectores para que una categoria sin
  // alertas muestre 0 y no desaparezca. Un cero visible informa; una
  // tarjeta ausente hace dudar de si fallo la pantalla.
  const conteos = {
    todos: alertas.length,
    phishing: 0,
    acceso_remoto: 0,
    malware: 0,
  };

  for (const a of alertas) {
    if (conteos[a.tipo_amenaza] !== undefined) {
      conteos[a.tipo_amenaza] = conteos[a.tipo_amenaza] + 1;
    }
  }

  return (
    <div className="resumen">
      {TARJETAS.map(function (t) {
        const activa = t.clave === vectorActivo;

        return (
          <button
            key={t.clave}
            type="button"
            className={
              activa ? "resumen__tarjeta resumen__tarjeta--activa" : "resumen__tarjeta"
            }
            onClick={function () {
              alElegir(t.clave);
            }}
          >
            <span className={"resumen__icono resumen__icono--" + t.color}>
              {ICONOS[t.clave]}
            </span>
            <span className="resumen__datos">
              <span className={"resumen__cifra resumen__cifra--" + t.color}>
                {conteos[t.clave]}
              </span>
              <span className="resumen__texto">{t.texto}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}