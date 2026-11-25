import { createContext, useContext, useState } from "react";

// Contexto que guarda quien inicio sesion y lo comparte con toda la app,
// para que el cascaron (menu, rutas protegidas) sepa si hay sesion o no.
const ContextoSesion = createContext(null);

const CLAVE = "tl_sesion";

// Lee la sesion guardada en el navegador (si la hay). Asi, al recargar,
// la sesion se conserva en vez de pedir login otra vez.
function leerSesion() {
  const crudo = localStorage.getItem(CLAVE);
  if (!crudo) {
    return null;
  }
  try {
    return JSON.parse(crudo);
  } catch {
    return null;
  }
}

export function ProveedorSesion(props) {
  const estado = useState(leerSesion);
  const usuario = estado[0];
  const ponUsuario = estado[1];

  // Guarda la sesion en el navegador y en memoria.
  function iniciar(datos) {
    localStorage.setItem(CLAVE, JSON.stringify(datos));
    ponUsuario(datos);
  }

  // Borra la sesion.
  function cerrar() {
    localStorage.removeItem(CLAVE);
    ponUsuario(null);
  }

  const valor = { usuario: usuario, iniciar: iniciar, cerrar: cerrar };

  return (
    <ContextoSesion.Provider value={valor}>
      {props.children}
    </ContextoSesion.Provider>
  );
}

// Hook para leer la sesion desde cualquier componente.
export function useSesion() {
  return useContext(ContextoSesion);
}
