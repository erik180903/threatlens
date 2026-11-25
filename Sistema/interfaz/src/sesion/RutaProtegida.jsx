import { Navigate } from "react-router-dom";
import { useSesion } from "./ProveedorSesion";

// Envuelve a las pantallas que exigen sesion. Si no hay sesion, redirige al
// login. Con la propiedad soloAdmin, ademas exige rol de administrador: si
// no lo es, lo manda a las alertas.
export function RutaProtegida(props) {
  const sesion = useSesion();
  const usuario = sesion.usuario;

  if (!usuario) {
    return <Navigate to="/login" replace />;
  }

  if (props.soloAdmin && usuario.rol !== "administrador") {
    return <Navigate to="/alertas" replace />;
  }

  return props.children;
}