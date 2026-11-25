import { useState } from "react";
import { useAlertas } from "../datos/useAlertas";
import { TablaAlertas } from "../componentes/TablaAlertas";
import { DetalleAlerta } from "../componentes/DetalleAlerta";
import { FiltrosAlertas, FILTROS_VACIOS } from "../componentes/FiltrosAlertas";
import { ResumenConteos } from "../componentes/ResumenConteos";
import { Modal } from "../componentes/Modal";

export function PaginaAlertas() {
  const datos = useAlertas();
  const alertas = datos.alertas;
  const cargando = datos.cargando;
  const error = datos.error;

  // Se guarda el ID, no la alerta.
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

  // Dato derivado: se recalcula en cada pintado a partir de las alertas
  // y los filtros. No es estado porque no es informacion nueva.
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
    <div className="alertas">
      <section className="alertas__lista">
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

      {alertaAbierta ? (
        <Modal alCerrar={function () { ponSeleccionada(null); }}>
          <DetalleAlerta alerta={alertaAbierta} />
        </Modal>
      ) : null}
    </div>
  );
}