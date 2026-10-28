import React,{useEffect,useState} from 'react';
import {Radar,RefreshCw,Plus,Check,Wifi} from 'lucide-react';
import {api} from './api';
import './discovery.css';

export default function DiscoveryPanel({user,onRegister}){
 const [data,setData]=useState(null),[network,setNetwork]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{let active=true,timer;async function load(){try{const value=await api('/discovery');if(active){setData(value);setNetwork(previous=>previous||value.networks.find(n=>Number(n.split('/')[1])>=24)||'');setError('')}}catch(e){if(active)setError(e.message)}finally{if(active)timer=setTimeout(load,2000)}}load();return()=>{active=false;clearTimeout(timer)}},[]);
 async function scan(e){e.preventDefault();setBusy(true);setError('');try{const job=await api('/discovery/scan',{method:'POST',body:{network}});setData(previous=>({...previous,job}))}catch(e){setError(e.message)}finally{setBusy(false)}}
 const running=data?.job.status==='running',progress=data?.job.total?Math.round(data.job.checked/data.job.total*100):0;
 return <div className="discovery-panel">
  <div className="discovery-intro"><span className="discovery-symbol"><Radar size={30}/></span><div><h3>Conoce tu red.</h3><p>Busca equipos desde el servidor de HyperLogs y convierte los detectados en fuentes de monitoreo.</p></div></div>
  {error&&<p className="discovery-error" role="alert">{error}</p>}
  {!data?<p role="status">Cargando inventario…</p>:<>
   {!data.networks.length?<div className="discovery-note"><strong>Primero autoriza la red del centro.</strong><p>Configura HYPERLOGS_DISCOVERY_NETWORKS en el servidor con tu subred real, por ejemplo 192.168.1.0/24, y reinicia HyperLogs. El escaneo quedará limitado a esas redes.</p></div>:<form className="discovery-form" onSubmit={scan}><label>Subred a explorar<input required aria-label="Subred a explorar" placeholder="192.168.1.0/24" value={network} onChange={e=>setNetwork(e.target.value)} list="allowed-lans" disabled={running}/><datalist id="allowed-lans">{data.networks.map(n=><option key={n} value={n}/>)}</datalist><small>Redes autorizadas: {data.networks.join(', ')} · máximo 254 direcciones por escaneo.</small></label><button className="button primary" disabled={user.role!=='admin'||busy||running}><RefreshCw size={15} className={running?'spin':''}/>{running?'Explorando…':'Escanear red'}</button></form>}
   {user.role!=='admin'&&<p className="muted">Tu rol permite consultar el inventario. El administrador inicia los escaneos.</p>}
   {data.job.status!=='idle'&&<div className="discovery-progress" role="status"><div><strong>{running?'Buscando equipos':data.job.status==='completed'?'Escaneo completado':'Escaneo interrumpido'}</strong><span>{data.job.checked} / {data.job.total} direcciones · {data.job.found} detectados</span></div><progress max="100" value={progress}/>{data.job.error&&<p>{data.job.error}</p>}</div>}
   <div className="discovery-table-wrap"><table><thead><tr><th>Activo detectado</th><th>Puertos accesibles</th><th>Última detección</th><th>Monitoreo</th></tr></thead><tbody>{data.assets.map((asset,i)=><tr key={asset.ip+'-'+i}><td><strong><Wifi size={14}/> {asset.ip}</strong><small>{asset.method==='icmp'?'Respuesta ICMP':asset.method==='tcp'?'Respuesta TCP':'Respuesta ICMP y TCP'}</small></td><td>{asset.ports.length?asset.ports.join(' · '):'No detectados'}</td><td>{new Date(asset.last_seen).toLocaleString('es-MX')}</td><td>{asset.source_id?<span className="discovery-linked"><Check size={14}/> {asset.source_name}</span>:user.role==='admin'?<button className="button subtle" onClick={()=>onRegister(asset)}><Plus size={14}/> Registrar</button>:<span>Pendiente de agente</span>}</td></tr>)}</tbody></table>{!data.assets.length&&<div className="discovery-empty"><Radar size={30}/><p>Los equipos detectados aparecerán aquí.</p></div>}</div>
   <p className="discovery-note">Detectado significa que respondió durante el escaneo. La lista conserva la última detección y no garantiza presencia actual. Los equipos con firewall, apagados, en otra VLAN o que no responden pueden no aparecer. Registrar un activo permite configurar su agente; las métricas y eventos llegan cuando el agente se conecta. El tipo sugerido por sus puertos se puede corregir.</p>
  </>}
 </div>
}
