import React,{useState} from 'react';
import {Layers3,ArrowRight,Eye,EyeOff,LockKeyhole,UserRound,ShieldCheck,Server,Monitor,Globe2,Sparkles,LoaderCircle} from 'lucide-react';
import './login.css';

export default function LoginScreen({onLogin,onDemo,onAccept,demoEnabled=false}){
 const [username,setUsername]=useState(''),[password,setPassword]=useState(''),[visible,setVisible]=useState(false),[busy,setBusy]=useState(''),[error,setError]=useState('');
 async function submit(event){event.preventDefault();if(busy)return;setError('');setBusy('login');try{onAccept(await onLogin({username,password}))}catch(e){setError(e.message)}finally{setBusy('')}}
 async function demo(){if(busy)return;setError('');setBusy('demo');try{onAccept(await onDemo())}catch{setError('La demostración solo está disponible en el entorno local habilitado. Usa tu cuenta para entrar.')}finally{setBusy('')}}
 return <main className="access-screen">
  <header className="access-header"><div className="access-wordmark"><span><Layers3 size={21}/></span><strong>hyper<span>logs</span></strong></div><span className="access-environment"><i/> Espacio de laboratorio</span></header>
  <div className="access-atmosphere" aria-hidden="true"><div className="access-orbit orbit-one"/><div className="access-orbit orbit-two"/><div className="access-orbit orbit-three"/><div className="access-satellite satellite-server"><Server size={31} strokeWidth={1}/></div><div className="access-satellite satellite-monitor"><Monitor size={29} strokeWidth={1}/></div><div className="access-satellite satellite-globe"><Globe2 size={30} strokeWidth={1}/></div><div className="access-satellite satellite-shield"><ShieldCheck size={29} strokeWidth={1}/></div></div>
  <section className="access-content"><div className="access-intro"><span>SEGURIDAD. CON OTRA PERSPECTIVA.</span><h1>Todo comienza<br/>con una mirada clara.</h1></div>
   <div className="access-card"><div className="access-emblem"><Layers3 size={29} strokeWidth={1.3}/></div><h2>Tu espacio. Bajo control.</h2><p>Inicia sesión en HyperLogs.</p>
    <form onSubmit={submit}><label htmlFor="access-user">Usuario</label><div className="access-field"><UserRound size={17}/><input id="access-user" autoComplete="username" placeholder="Tu nombre de usuario" value={username} onChange={e=>setUsername(e.target.value)} maxLength={80} required disabled={!!busy}/></div><label htmlFor="access-password">Contraseña</label><div className="access-field"><LockKeyhole size={17}/><input id="access-password" type={visible?'text':'password'} autoComplete="current-password" placeholder="Tu contraseña" value={password} onChange={e=>setPassword(e.target.value)} maxLength={256} required disabled={!!busy}/><button type="button" aria-label={visible?'Ocultar contraseña':'Mostrar contraseña'} aria-pressed={visible} onClick={()=>setVisible(!visible)}>{visible?<EyeOff size={17}/>:<Eye size={17}/>}</button></div>
    {error&&<div className="access-error" role="alert">{error}</div>}<button className="access-submit" type="submit" disabled={!!busy}>{busy==='login'?<><LoaderCircle size={17} className="access-spinner"/> Conectando…</>:<>Entrar a mi espacio <ArrowRight size={17}/></>}</button></form>
    <div className="access-card-footer"><ShieldCheck size={13}/><span>Acceso por roles · Sesiones de 8 horas</span></div>
   </div>{demoEnabled&&<div className="access-demo"><span>Conoce el laboratorio antes de entrar.</span><button onClick={demo} disabled={!!busy}>{busy==='demo'?<LoaderCircle size={14} className="access-spinner"/>:<Sparkles size={14}/>} Explorar demostración <ArrowRight size={13}/></button></div>}
  </section><footer className="access-footer"><span>HyperLogs <i/> Security, in perspective.</span><span>Observa. Comprende. Responde.</span></footer>
 </main>
}
