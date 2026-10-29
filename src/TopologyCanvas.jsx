import React,{useEffect,useMemo,useRef,useState} from 'react';
import {Globe2,Monitor,Network,RotateCcw,Server,ShieldAlert} from 'lucide-react';
const icons={windows:Monitor,linux:Server,application:Globe2,syslog:Network};
const clamp=(value,min,max)=>Math.max(min,Math.min(max,value));

function automatic(sources){
 const count=Math.max(sources.length,1),columns=Math.ceil(Math.sqrt(count*1.55)),rows=Math.ceil(count/columns),result={};
 sources.forEach((source,index)=>{const col=index%columns,row=Math.floor(index/columns);result[source.id]={x:18+(columns===1?0:col/(columns-1))*64,y:22+(rows===1?0.5:row/(rows-1))*58}});return result;
}

export default function TopologyCanvas({sources,selected,onSelect}){
 const stage=useRef(null),drag=useRef(null),storage='hyperlogs.topology.v1';
 const defaults=useMemo(()=>automatic(sources),[sources]);
 const [positions,setPositions]=useState(()=>{try{return {...defaults,...JSON.parse(localStorage.getItem(storage)||'{}')}}catch{return defaults}});
 useEffect(()=>setPositions(previous=>{const next={};sources.forEach(source=>next[source.id]=previous[source.id]||defaults[source.id]);return next}),[sources,defaults]);
 useEffect(()=>{try{localStorage.setItem(storage,JSON.stringify(positions))}catch{}},[positions]);
 function start(event,id){event.currentTarget.setPointerCapture(event.pointerId);drag.current={id};onSelect(id)}
 function move(event){if(!drag.current||!stage.current)return;const box=stage.current.getBoundingClientRect();setPositions(previous=>({...previous,[drag.current.id]:{x:clamp((event.clientX-box.left)/box.width*100,7,93),y:clamp((event.clientY-box.top)/box.height*100,12,88)}}))}
 function stop(){drag.current=null}
 function reset(){setPositions(defaults)}
 return <div ref={stage} className="topology-canvas" onPointerMove={move} onPointerUp={stop} onPointerCancel={stop}>
  <div className="topology-glow one"/><div className="topology-glow two"/>
  <svg className="topology-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">{sources.map(source=>{const point=positions[source.id]||defaults[source.id]||{x:50,y:50};return <line key={source.id} x1="50" y1="50" x2={point.x} y2={point.y} className={source.alerts?'risk':''}/>})}</svg>
  <div className="topology-core"><span/><strong>HyperLogs</strong><small>Security bus</small></div>
  {sources.map(source=>{const Icon=icons[source.kind]||Server,point=positions[source.id]||defaults[source.id]||{x:50,y:50};return <button key={source.id} style={{left:point.x+'%',top:point.y+'%'}} className={'topology-node '+(selected===source.id?'selected ':'')+(source.alerts?'risk':'')} onPointerDown={event=>start(event,source.id)} onDoubleClick={()=>onSelect(source.id)} aria-label={`${source.name}, ${source.alerts?'con alertas':'sin alertas'}`}><span className="topology-node-icon"><Icon size={22}/>{source.alerts>0&&<i><ShieldAlert size={9}/></i>}</span><span><strong>{source.name}</strong><small>{source.ip||source.kind}</small></span></button>})}
  {!sources.length&&<div className="topology-empty"><Network size={28}/><strong>La red aparecerá aquí.</strong><small>Conecta o descubre tu primer activo.</small></div>}
  <button className="topology-reset" onClick={reset}><RotateCcw size={13}/> Reorganizar</button>
  <span className="topology-hint">Arrastra los equipos · doble clic para seleccionar</span>
 </div>
}
