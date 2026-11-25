import { Routes, Route, Navigate } from "react-router-dom";
import { Layout } from "./componentes/Layout";
import { PaginaAlertas } from "./paginas/PaginaAlertas";
import { PaginaUsuarios } from "./paginas/PaginaUsuarios";
import { PaginaLogin } from "./paginas/PaginaLogin";
import { RutaProtegida } from "./sesion/RutaProtegida";

import "./App.css";

function App() {
  return (
    <Routes>
      {/* El login vive fuera del cascaron: no lleva barra de navegacion. */}
      <Route path="/login" element={<PaginaLogin />} />

      {/* Todo lo demas vive dentro del cascaron (Layout con su menu). */}
      <Route
        path="/"
        element={
          <RutaProtegida>
            <Layout />
          </RutaProtegida>
        }
      >
        <Route index element={<Navigate to="/alertas" replace />} />
        <Route path="alertas" element={<PaginaAlertas />} />
        <Route
          path="usuarios"
          element={
            <RutaProtegida soloAdmin>
              <PaginaUsuarios />
            </RutaProtegida>
          }
        />
      </Route>

      {/* Cualquier ruta desconocida regresa a las alertas. */}
      <Route path="*" element={<Navigate to="/alertas" replace />} />
    </Routes>
  );
}

export default App;