import { useState } from "react";
import { useAlertas } from "./datos/useAlertas";
import { TablaAlertas } from "./componentes/TablaAlertas";
import { DetalleAlerta } from "./componentes/DetalleAlerta";
import { FiltrosAlertas, FILTROS_VACIOS } from "./componentes/FiltrosAlertas";
import { ResumenConteos } from "./componentes/ResumenConteos";

import "./App.css";

function App() {
  const datos = useAlertas();
  const alertas = datos.alertas;
  const cargando = datos.cargando;
  const error = datos.error;

  // Se guarda el ID, no la alerta. Ver la explicacion de abajo.
  const estadoSeleccion = useState(null);
  const seleccionada = estadoSeleccion[0];
  const ponSeleccionada = estadoSeleccion[1];

  const estadoFiltros = useState(FILTROS_VACIOS);
  const filtros = estadoFiltros[0];
  const ponFiltros = estadoFiltros[1];

  if (cargando) {
    return <p className="app__estado">Cargando alertas…</p>;
  }

  if (error) {
    return <p className="app__estado app__estado--error">Error: {error}</p>;
  }

  const alertaAbierta = alertas.find(function (a) {
    return a.id === seleccionada;
  });

    // Dato derivado: se recalcula en cada pintado a partir de las
  // alertas y los filtros. No es estado porque no es informacion
  // nueva; es una vista de informacion que ya existe.
  const visibles = alertas.filter(function (a) {
    if (filtros.vector !== "todos" && a.tipo_amenaza !== filtros.vector) {
      return false;
    }

    if (filtros.nivel !== "todos" && a.nivel_severidad !== filtros.nivel) {
      return false;
    }

    if (filtros.texto !== "") {
      const buscado = filtros.texto.toLowerCase();
      const coincide =
        a.descripcion.toLowerCase().includes(buscado) ||
        a.equipo.toLowerCase().includes(buscado) ||
        a.id.toLowerCase().includes(buscado);

      if (!coincide) {
        return false;
      }
    }

    return true;
  });

  return (
    <div className="app">
      <header className="app__barra">
        <span className="app__marca">ThreatLens</span>
        <span className="app__conteo">{alertas.length} alertas</span>
      </header>

      <main className="app__cuerpo">
                <section className="app__panel">
          <h2 className="app__titulo">
            Historial de alertas
            <span className="app__sufijo">
              {visibles.length === alertas.length
                ? `${alertas.length} alertas`
                : `${visibles.length} de ${alertas.length}`}
            </span>
          </h2>
          
          <FiltrosAlertas filtros={filtros} ponFiltros={ponFiltros} />

          <ResumenConteos
            alertas={alertas}
            vectorActivo={filtros.vector}
            alElegir={function (clave) {
              ponFiltros({ ...filtros, vector: clave });
            }}
          />

          <TablaAlertas
            alertas={visibles}
            seleccionada={seleccionada}
            alSeleccionar={ponSeleccionada}
          />
        </section>

        <section className="app__panel">
          {alertaAbierta ? (
            <DetalleAlerta alerta={alertaAbierta} />
          ) : (
            <p className="app__pista">
              Selecciona una fila para ver el detalle de la alerta.
            </p>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;