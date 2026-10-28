import React from 'react';
export default class ErrorBoundary extends React.Component{
 state={failed:false};
 static getDerivedStateFromError(){return {failed:true}}
 componentDidCatch(){console.error('HyperLogs: se recuperó un error de presentación.');}
 render(){return this.state.failed?<main className="recovery-screen"><h1>No pudimos mostrar esta vista.</h1><p>Recarga la aplicación para recuperar la sesión y los datos guardados.</p><button className="button primary" onClick={()=>location.reload()}>Volver a cargar</button></main>:this.props.children;}
}
