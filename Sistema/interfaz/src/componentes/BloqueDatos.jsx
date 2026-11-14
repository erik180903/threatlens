import "./BloqueDatos.css";

export function BloqueDatos(props) {
  const titulo = props.titulo;
  const children = props.children;
  const pie = props.pie;

  return (
    <section className="bloque-datos">
      <h3 className="bloque-datos__titulo">{titulo}</h3>
      <div className="bloque-datos__lista">{children}</div>
      {pie ? <div className="bloque-datos__pie">{pie}</div> : null}
    </section>
  );
}