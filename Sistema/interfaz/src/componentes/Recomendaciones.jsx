import "./Recomendaciones.css";

const ICONO_INFO = (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11.5v4.5" />
    <path d="M12 8v.1" />
  </svg>
);

export function Recomendaciones(props) {
  const recomendaciones = props.recomendaciones;

  // El contrato declara el campo como null hasta que exista la
  // integracion con Gemini. Se aceptan dos formas --un arreglo de
  // textos, o un objeto con la lista adentro-- para no tener que
  // volver aqui cuando se decida cual entrega la API.
  let lista = [];
  if (Array.isArray(recomendaciones)) {
    lista = recomendaciones;
  } else if (recomendaciones && Array.isArray(recomendaciones.lista)) {
    lista = recomendaciones.lista;
  }

  return (
    <section className="recomendaciones">
      <header className="recomendaciones__cabecera">
        <span className="recomendaciones__icono">{ICONO_INFO}</span>
        <h3 className="recomendaciones__titulo">
          Recomendaciones generadas por Gemini
        </h3>
        <span className="recomendaciones__distintivo">IA generativa</span>
      </header>

      {lista.length === 0 ? (
        <p className="recomendaciones__pendiente">
          Se generan con la API de Gemini en la tercera iteración. El campo ya
          está declarado en el contrato de alerta y llega vacío.
        </p>
      ) : (
        <ol className="recomendaciones__lista">
          {lista.map(function (texto, i) {
            return (
              <li key={i} className="recomendaciones__item">
                <span className="recomendaciones__numero">{i + 1}</span>
                <span className="recomendaciones__texto">{texto}</span>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}