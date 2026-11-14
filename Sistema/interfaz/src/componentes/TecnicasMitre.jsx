import "./TecnicasMitre.css";

// T1021 vive en /techniques/T1021/ y la subtecnica T1021.001 vive en
// /techniques/T1021/001/, de ahi el reemplazo del punto por diagonal.
function enlaceDe(id) {
  return "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";
}

export function TecnicasMitre(props) {
  const tecnicas = props.tecnicas || [];

  if (tecnicas.length === 0) {
    return null;
  }

  return (
    <div className="tecnicas-mitre">
      {tecnicas.map(function (t) {
        return (
          <a
            key={t.id}
            className="tecnica"
            href={enlaceDe(t.id)}
            target="_blank"
            rel="noreferrer"
          >
            <span className="tecnica__id">{t.id}</span>
            <span className="tecnica__nombre">{t.nombre}</span>
          </a>
        );
      })}
    </div>
  );
}