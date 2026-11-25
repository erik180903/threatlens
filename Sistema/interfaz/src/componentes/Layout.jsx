import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useSesion } from "../sesion/ProveedorSesion";
import "./Layout.css";

// Decide la clase del enlace segun si la ruta esta activa. Se escribe
// como funcion (no desestructurada) para leer estado.isActive en dos pasos.
function claseEnlace(estado) {
  const activo = estado.isActive;
  return activo ? "shell__enlace shell__enlace--activo" : "shell__enlace";
}

export function Layout() {
  const sesion = useSesion();
  const usuario = sesion.usuario;
  const navegar = useNavigate();

  // En movil el menu se abre/cierra con el boton hamburguesa.
  const estadoMenu = useState(false);
  const menuAbierto = estadoMenu[0];
  const ponMenuAbierto = estadoMenu[1];

  function alCerrarSesion() {
    sesion.cerrar();
    navegar("/login", { replace: true });
  }

  function alAlternarMenu() {
    ponMenuAbierto(!menuAbierto);
  }

  // Al tocar un enlace en movil, cerrar el menu.
  function alNavegar() {
    ponMenuAbierto(false);
  }

  const claseNav = menuAbierto ? "shell__nav shell__nav--abierto" : "shell__nav";

  return (
    <div className="shell">
      <aside className={claseNav}>
        <div className="shell__cabecera">
          <div className="shell__marca">ThreatLens</div>
          <button
            className="shell__hamburguesa"
            onClick={alAlternarMenu}
            aria-label="Menú"
          >
            ☰
          </button>
        </div>

        <div className="shell__panel">
          <nav className="shell__menu">
            <NavLink to="/alertas" className={claseEnlace} onClick={alNavegar}>
              Alertas
            </NavLink>
            {/* Solo los administradores ven la gestion de usuarios y equipos. */}
            {usuario && usuario.rol === "administrador" ? (
              <NavLink to="/usuarios" className={claseEnlace} onClick={alNavegar}>
                Usuarios y equipos
              </NavLink>
            ) : null}
          </nav>

          <div className="shell__pie">
            <div className="shell__usuario">
              <span className="shell__nombre">{usuario ? usuario.nombre : ""}</span>
              {usuario ? (
                <span className={"shell__rol shell__rol--" + usuario.rol}>
                  {usuario.rol}
                </span>
              ) : null}
            </div>
            <button className="shell__salir" onClick={alCerrarSesion}>
              Cerrar sesión
            </button>
          </div>
        </div>
      </aside>

      <main className="shell__contenido">
        <Outlet />
      </main>
    </div>
  );
}