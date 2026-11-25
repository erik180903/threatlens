import { useState } from "react";
import { Modal } from "../componentes/Modal";
import "./PaginaUsuarios.css";

// Datos de ejemplo. Cuando exista el backend, estas listas se llenan desde
// la API (equipos monitoreados y cuentas de usuario); la pantalla no cambia.
const EQUIPOS_INICIALES = [
  { id: 1, host: "srv-archivos", ip: "172.29.65.165", sistema: "Windows 11", estado: "Activo" },
  { id: 2, host: "PC-GERENCIA", ip: "172.29.65.40", sistema: "Windows 11", estado: "Activo" },
  { id: 3, host: "SRV-CONTA", ip: "172.29.65.12", sistema: "Windows Server 2022", estado: "Activo" },
];

const USUARIOS_INICIALES = [
  { id: 1, nombre: "Erik Bravo", correo: "erik.bravo@empresa.com", rol: "administrador", estado: "Activo" },
  { id: 2, nombre: "Ana Soto", correo: "ana.soto@empresa.com", rol: "personal", estado: "Activo" },
  { id: 3, nombre: "Luis Mora", correo: "luis.mora@empresa.com", rol: "personal", estado: "Inactivo" },
];

// Etiqueta de estado (Activo / Inactivo) con su color.
function Estado(props) {
  const valor = props.valor;
  const clase = valor === "Activo" ? "estado estado--activo" : "estado estado--inactivo";
  return <span className={clase}>{valor}</span>;
}

// Formulario de alta de equipo (dentro del modal).
function FormularioEquipo(props) {
  const alGuardar = props.alGuardar;

  const estadoHost = useState("");
  const host = estadoHost[0];
  const ponHost = estadoHost[1];

  const estadoIp = useState("");
  const ip = estadoIp[0];
  const ponIp = estadoIp[1];

  function alEnviar(evento) {
    evento.preventDefault();
    if (host.trim() === "" || ip.trim() === "") {
      return;
    }
    alGuardar({ host: host.trim(), ip: ip.trim(), sistema: "Por detectar" });
  }

  return (
    <form className="formulario" onSubmit={alEnviar}>
      <h3 className="formulario__titulo">Alta de equipo</h3>
      <label className="formulario__campo">
        <span>Nombre de host</span>
        <input type="text" value={host} onChange={function (e) { ponHost(e.target.value); }} autoFocus />
      </label>
      <label className="formulario__campo">
        <span>Dirección IP</span>
        <input type="text" value={ip} onChange={function (e) { ponIp(e.target.value); }} />
      </label>
      <button type="submit" className="formulario__boton">Dar de alta</button>
    </form>
  );
}

// Formulario de alta de usuario (dentro del modal).
function FormularioUsuario(props) {
  const alGuardar = props.alGuardar;

  const estadoNombre = useState("");
  const nombre = estadoNombre[0];
  const ponNombre = estadoNombre[1];

  const estadoCorreo = useState("");
  const correo = estadoCorreo[0];
  const ponCorreo = estadoCorreo[1];

  const estadoRol = useState("personal");
  const rol = estadoRol[0];
  const ponRol = estadoRol[1];

  function alEnviar(evento) {
    evento.preventDefault();
    if (nombre.trim() === "" || correo.trim() === "") {
      return;
    }
    alGuardar({ nombre: nombre.trim(), correo: correo.trim(), rol: rol });
  }

  return (
    <form className="formulario" onSubmit={alEnviar}>
      <h3 className="formulario__titulo">Alta de usuario</h3>
      <label className="formulario__campo">
        <span>Nombre</span>
        <input type="text" value={nombre} onChange={function (e) { ponNombre(e.target.value); }} autoFocus />
      </label>
      <label className="formulario__campo">
        <span>Correo</span>
        <input type="email" value={correo} onChange={function (e) { ponCorreo(e.target.value); }} />
      </label>
      <label className="formulario__campo">
        <span>Rol</span>
        <select value={rol} onChange={function (e) { ponRol(e.target.value); }}>
          <option value="personal">Personal</option>
          <option value="administrador">Administrador</option>
        </select>
      </label>
      <button type="submit" className="formulario__boton">Crear usuario</button>
    </form>
  );
}

export function PaginaUsuarios() {
  const estadoEquipos = useState(EQUIPOS_INICIALES);
  const equipos = estadoEquipos[0];
  const ponEquipos = estadoEquipos[1];

  const estadoUsuarios = useState(USUARIOS_INICIALES);
  const usuarios = estadoUsuarios[0];
  const ponUsuarios = estadoUsuarios[1];

  const estadoModalEquipo = useState(false);
  const modalEquipo = estadoModalEquipo[0];
  const ponModalEquipo = estadoModalEquipo[1];

  const estadoModalUsuario = useState(false);
  const modalUsuario = estadoModalUsuario[0];
  const ponModalUsuario = estadoModalUsuario[1];

  function agregarEquipo(datos) {
    const nuevo = { id: Date.now(), host: datos.host, ip: datos.ip, sistema: datos.sistema, estado: "Activo" };
    ponEquipos(equipos.concat(nuevo));
    ponModalEquipo(false);
  }

  function darDeBajaEquipo(id) {
    ponEquipos(equipos.filter(function (eq) { return eq.id !== id; }));
  }

  function agregarUsuario(datos) {
    const nuevo = { id: Date.now(), nombre: datos.nombre, correo: datos.correo, rol: datos.rol, estado: "Activo" };
    ponUsuarios(usuarios.concat(nuevo));
    ponModalUsuario(false);
  }

  function eliminarUsuario(id) {
    ponUsuarios(usuarios.filter(function (us) { return us.id !== id; }));
  }

  return (
    <div className="admin">
      <h2 className="pagina__titulo">Usuarios y equipos</h2>
      <p className="pagina__nota">
        Inventario tecnológico y humano: alta y baja de equipos monitoreados y
        administración de cuentas de usuario.
      </p>

      <section className="admin__seccion">
        <div className="admin__cabecera">
          <h3 className="admin__titulo">Equipos monitoreados</h3>
          <button className="admin__agregar" onClick={function () { ponModalEquipo(true); }}>
            + Agregar equipo
          </button>
        </div>
        <div className="admin__marco">
          <table className="admin__tabla">
            <thead>
              <tr>
                <th>Nombre de host</th>
                <th>Dirección IP</th>
                <th>Sistema</th>
                <th>Estado</th>
                <th aria-label="Acciones"></th>
              </tr>
            </thead>
            <tbody>
              {equipos.map(function (eq) {
                return (
                  <tr key={eq.id}>
                    <td>{eq.host}</td>
                    <td className="admin__mono">{eq.ip}</td>
                    <td>{eq.sistema}</td>
                    <td><Estado valor={eq.estado} /></td>
                    <td className="admin__acciones">
                      <button className="admin__baja" onClick={function () { darDeBajaEquipo(eq.id); }}>
                        Baja
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="admin__seccion">
        <div className="admin__cabecera">
          <h3 className="admin__titulo">Cuentas de usuario</h3>
          <button className="admin__agregar" onClick={function () { ponModalUsuario(true); }}>
            + Agregar usuario
          </button>
        </div>
        <div className="admin__marco">
          <table className="admin__tabla">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Correo</th>
                <th>Rol</th>
                <th>Estado</th>
                <th aria-label="Acciones"></th>
              </tr>
            </thead>
            <tbody>
              {usuarios.map(function (us) {
                return (
                  <tr key={us.id}>
                    <td>{us.nombre}</td>
                    <td className="admin__mono">{us.correo}</td>
                    <td className="admin__rol">{us.rol}</td>
                    <td><Estado valor={us.estado} /></td>
                    <td className="admin__acciones">
                      <button className="admin__baja" onClick={function () { eliminarUsuario(us.id); }}>
                        Eliminar
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {modalEquipo ? (
        <Modal alCerrar={function () { ponModalEquipo(false); }}>
          <FormularioEquipo alGuardar={agregarEquipo} />
        </Modal>
      ) : null}

      {modalUsuario ? (
        <Modal alCerrar={function () { ponModalUsuario(false); }}>
          <FormularioUsuario alGuardar={agregarUsuario} />
        </Modal>
      ) : null}
    </div>
  );
}