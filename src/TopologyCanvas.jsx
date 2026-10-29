import React,{useEffect,useMemo,useRef,useState} from 'react';
import {Globe2,Monitor,Network,RotateCcw,Server,ShieldAlert} from 'lucide-react';
const icons={windows:Monitor,linux:Server,application:Globe2,syslog:Network};
const clamp=(value,min,max)=>Math.max(min,Math.min(max,value));

function automatic(sources,size){
 const width=Math.max(size.width,320),height=Math.max(size.height,330),nodeWidth=width<520?126:156,gap=24;
 const columns=Math.max(1,Math.min(sources.length,Math.floor((width-36)/(nodeWidth+gap)))),rows=Math.max(1,Math.ceil(sources.length/columns)),result={};
 const xPadding=nodeWidth/2+18,yPadding=54,usableX=Math.max(0,width-xPadding*2),usableY=Math.max(0,height-yPadding*2);
 sources.forEach((source,index)=>{const row=Math.floor(index/columns),items=Math.min(columns,sources.length-row*columns),col=index-row*columns;
  const rowInset=(columns-items)*(nodeWidth+gap)/2,x=items===1?width/2:xPadding+rowInset+col*(usableX-rowInset*2)/(items-1),y=rows===1?height*.28:yPadding+row*usableY/(rows-1);
  result[source.id]={x:x/width*100,y:y/height*100};});return result;
}

export default function TopologyCanvas({sources,selected,onSelect}){
 const stage=useRef(null),drag=useRef(null),storage='hyperlogs.topology.v2',custom=useRef(false);
 const [size,setSize]=useState({width:800,height:380}),defaults=useMemo(()=>automatic(sources,size),[sources,size]);
 const [positions,setPositions]=useState(()=>{try{const saved=JSON.parse(localStorage.getItem(storage)||'null');custom.current=!!saved;return saved||{}}catch{return {}}});
 useEffect(()=>{if(!stage.current)return;const observer=new ResizeObserver(([entry])=>setSize({width:entry.contentRect.width,height:entry.contentRect.height}));observer.observe(stage.current);return()=>observer.disconnect()},[]);
 useEffect(()=>setPositions(previous=>{const next={};sources.forEach(source=>next[source.id]=custom.current&&previous[source.id]?previous[source.id]:defaults[source.id]);return next}),[sources,defaults]);
 useEffect(()=>{try{localStorage.setItem(storage,JSON.stringify(positions))}catch{}},[positions]);
 function start(event,id){event.currentTarget.setPointerCapture(event.pointerId);drag.current={id};onSelect(id)}
 function move(event){if(!drag.current||!stage.current)return;custom.current=true;const box=stage.current.getBoundingClientRect();setPositions(previous=>({...previous,[drag.current.id]:{x:clamp((event.clientX-box.left)/box.width*100,9,91),y:clamp((event.clientY-box.top)/box.height*100,13,87)}}))}
 function stop(){drag.current=null}
 function reset(){custom.current=false;setPositions(defaults);try{localStorage.removeItem(storage)}catch{}}
 return <div ref={stage} className="topology-canvas" onPointerMove={move} onPointerUp={stop} onPointerCancel={stop}>
  <div className="topology-glow one"/><div className="topology-glow two"/>
  <svg className="topology-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">{sources.map(source=>{const point=positions[source.id]||defaults[source.id]||{x:50,y:50};return <line key={source.id} x1="50" y1="50" x2={point.x} y2={point.y} className={source.alerts?'risk':''}/>})}</svg>
  <div className="topology-core"><span/><strong>HyperLogs</strong><small>Security bus</small></div>
  {sources.map(source=>{const Icon=icons[source.kind]||Server,point=positions[source.id]||defaults[source.id]||{x:50,y:50};return <button key={source.id} style={{left:point.x+'%',top:point.y+'%'}} className={'topology-node '+(selected===source.id?'selected ':'')+(source.alerts?'risk':'')} onPointerDown={event=>start(event,source.id)} onClick={()=>onSelect(source.id)} aria-label={`${source.name}, ${source.alerts?'con alertas':'sin alertas'}`}><span className="topology-node-icon"><Icon size={22}/>{source.alerts>0&&<i><ShieldAlert size={9}/></i>}</span><span><strong>{source.name}</strong><small>{source.ip||source.kind}</small></span></button>})}
  {!sources.length&&<div className="topology-empty"><Network size={28}/><strong>La red aparecerá aquí.</strong><small>Conecta o descubre tu primer activo.</small></div>}
  <button className="topology-reset" onClick={reset}><RotateCcw size={13}/> Reorganizar</button>
  <span className="topology-hint">Selecciona o arrastra cualquier equipo</span>
 </div>
}
