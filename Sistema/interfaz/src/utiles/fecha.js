// El formateador se construye UNA vez y se reutiliza. Crear un
// Intl.DateTimeFormat es caro, y en el historial esta funcion se va a
// llamar una vez por fila.
const FORMATO = new Intl.DateTimeFormat("es-MX", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

export function formatearFecha(iso) {
  if (!iso) {
    return "";
  }

  const d = new Date(iso);

  // Si la cadena no se pudo interpretar, se muestra cruda en lugar de
  // "Invalid Date". Ver el valor original dice de donde viene el
  // problema; "Invalid Date" no dice nada.
  if (Number.isNaN(d.getTime())) {
    return iso;
  }

  return FORMATO.format(d);
}