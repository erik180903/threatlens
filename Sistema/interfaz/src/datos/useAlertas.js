import { useEffect, useState } from "react";

// Mientras no exista el repositorio ni la API, las alertas se leen
// como archivos estaticos desde public/datos/. Cuando el backend este
// en linea esta lista se reemplaza por una sola llamada a
// /api/alertas, y ningun componente que use este hook se entera.
const ARCHIVOS = [
  "/datos/alertas_phishing.json",
  "/datos/alertas_accesos.json",
  "/datos/alertas_malware.json",
];

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
        const respuestas = await Promise.all(
          ARCHIVOS.map(function (ruta) {
            return fetch(ruta);
          })
        );

        for (const r of respuestas) {
          if (!r.ok) {
            throw new Error(`${r.url} respondio ${r.status}`);
          }
        }

        const listas = await Promise.all(
          respuestas.map(function (r) {
            return r.json();
          })
        );

        const todas = listas.flat();

        // Mas recientes primero. Las fechas estan en ISO 8601, asi que
        // comparar las cadenas alfabeticamente da el orden cronologico.
        // Por eso se normalizaron en el contrato.
        todas.sort(function (a, b) {
          if (a.fecha < b.fecha) return 1;
          if (a.fecha > b.fecha) return -1;
          return 0;
        });

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