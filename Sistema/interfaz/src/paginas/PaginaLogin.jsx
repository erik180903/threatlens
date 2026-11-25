import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSesion } from "../sesion/ProveedorSesion";
import "./PaginaLogin.css";

export function PaginaLogin() {
  const sesion = useSesion();
  const navegar = useNavigate();

  const estadoUsuario = useState("");
  const usuario = estadoUsuario[0];
  const ponUsuario = estadoUsuario[1];

  const estadoClave = useState("");
  const clave = estadoClave[0];
  const ponClave = estadoClave[1];

  const estadoError = useState("");
  const error = estadoError[0];
  const ponError = estadoError[1];

  // Rol con el que se entra. Mientras no haya backend, se elige aqui para
  // poder ver las dos vistas (personal y administrador).
  const estadoRol = useState("administrador");
  const rol = estadoRol[0];
  const ponRol = estadoRol[1];

  function alEnviar(evento) {
    evento.preventDefault();

    if (usuario.trim() === "" || clave.trim() === "") {
      ponError("Escribe usuario y contraseña.");
      return;
    }

    // Cascaron: todavia no hay autenticacion real. Se crea una sesion
    // local (con su rol) y se entra. La validacion contra un backend se
    // integra despues; el rol vendra de la cuenta, no de este selector.
    sesion.iniciar({ nombre: usuario.trim(), rol: rol });
    navegar("/alertas", { replace: true });
  }

  return (
    <div className="login">
      <form className="login__tarjeta" onSubmit={alEnviar}>
        <div className="login__marca">ThreatLens</div>
        <p className="login__subtitulo">Acceso al panel de monitoreo</p>

        <label className="login__campo">
          <span>Usuario</span>
          <input
            type="text"
            value={usuario}
            onChange={function (e) {
              ponUsuario(e.target.value);
            }}
            autoFocus
          />
        </label>

        <label className="login__campo">
          <span>Contraseña</span>
          <input
            type="password"
            value={clave}
            onChange={function (e) {
              ponClave(e.target.value);
            }}
          />
        </label>

        <label className="login__campo">
          <span>Rol</span>
          <select
            value={rol}
            onChange={function (e) {
              ponRol(e.target.value);
            }}
          >
            <option value="administrador">Administrador</option>
            <option value="personal">Personal</option>
          </select>
        </label>

        {error ? <p className="login__error">{error}</p> : null}

        <button type="submit" className="login__boton">
          Entrar
        </button>

        <p className="login__nota">
          Acceso de demostración: cualquier usuario y contraseña. La
          autenticación real se integra más adelante.
        </p>
      </form>
    </div>
  );
}