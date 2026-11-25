import { useEffect } from "react";
import { createPortal } from "react-dom";
import "./Modal.css";

// Ventana emergente que se pinta encima de todo. Se cierra con la ✕, con la
// tecla Escape o con un clic en el fondo (fuera de la caja).
export function Modal(props) {
  const alCerrar = props.alCerrar;

  // Escuchar la tecla Escape mientras el modal este abierto.
  useEffect(function () {
    function alTecla(evento) {
      if (evento.key === "Escape") {
        alCerrar();
      }
    }
    document.addEventListener("keydown", alTecla);
    return function () {
      document.removeEventListener("keydown", alTecla);
    };
  }, [alCerrar]);

  // Clic en el fondo cierra; clic dentro de la caja no (se detiene ahi).
  function alClicFondo(evento) {
    if (evento.target === evento.currentTarget) {
      alCerrar();
    }
  }

  const contenido = (
    <div className="modal__fondo" onClick={alClicFondo}>
      <div className="modal__caja" role="dialog" aria-modal="true">
        <button className="modal__cerrar" onClick={alCerrar} aria-label="Cerrar">
          ×
        </button>
        <div className="modal__contenido">{props.children}</div>
      </div>
    </div>
  );

  // createPortal saca el modal del arbol del cascaron y lo monta en <body>,
  // asi ningun contenedor con overflow lo recorta y queda encima de todo.
  return createPortal(contenido, document.body);
}