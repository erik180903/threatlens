import { useEffect, useState } from "react";

// Mientras no exista el repositorio ni la API, las alertas se leen
// como archivos estaticos desde public/datos/. Cuando el backend este
// en linea esta lista se reemplaza por una sola llamada a
// /api/alertas, y ningun componente que use este hook se entera.

export function useAlertas() {
  const estadoAlertas = useState([]);
  const alertas = estadoAlertas[0];
  const ponAlertas = estadoAlertas[1];

  const estadoCargando = useState(true);
  const cargando = estadoCargando[0];
  const ponCargando = estadoCargando[1];

  const estadoError = useState(null);
  const error = estadoError[0];
  const ponError = estadoError[1];

  useEffect(function () {
    // Bandera para no tocar el estado si el componente desaparece
    // antes de que termine la descarga.
    let vigente = true;

        async function cargar() {
      try {
        const respuesta = await fetch("/api/alertas");

        if (!respuesta.ok) {
          throw new Error(`/api/alertas respondio ${respuesta.status}`);
        }

        const todas = await respuesta.json();

        if (vigente) {
          ponAlertas(todas);
          ponCargando(false);
        }
      } catch (e) {
        if (vigente) {
          ponError(e.message);
          ponCargando(false);
        }
      }
    }

    cargar();

    return function () {
      vigente = false;
    };
  }, []);

  return { alertas, cargando, error };
}