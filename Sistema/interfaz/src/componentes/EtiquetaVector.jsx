import "./EtiquetaVector.css";

const NOMBRES = {
  phishing: "Phishing",
  acceso_remoto: "Acceso remoto",
  malware: "Archivo malicioso",
};

export function EtiquetaVector(props) {
  const vector = props.vector;
  const texto = NOMBRES[vector] || vector;

  return <span className="etiqueta-vector">{texto}</span>;
}