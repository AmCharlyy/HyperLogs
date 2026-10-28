import React,{useEffect,useRef,useState} from 'react';
import * as THREE from 'three';
import {OrbitControls} from 'three/addons/controls/OrbitControls.js';
import {Maximize2,Minus,Plus,RotateCcw,Layers3} from 'lucide-react';

export default function NetworkScene({sources,selected,onSelect,live,onlyAlerts=false,showLabels=true,flat=false}){
 const mount=useRef(null),api=useRef(null),latest=useRef({selected,onSelect,live,onlyAlerts,showLabels}),[failed,setFailed]=useState(false),[labels,setLabels]=useState([]),[hover,setHover]=useState(null);
 latest.current={selected,onSelect,live,onlyAlerts,showLabels,flat};
 useEffect(()=>{
  const container=mount.current;if(!container)return;
  let renderer;try{renderer=new THREE.WebGLRenderer({antialias:true,alpha:true,powerPreference:'low-power'});}catch{setFailed(true);return;}
  renderer.setPixelRatio(Math.min(window.devicePixelRatio,1.6));renderer.shadowMap.enabled=true;renderer.shadowMap.autoUpdate=false;renderer.shadowMap.needsUpdate=true;renderer.shadowMap.type=THREE.PCFShadowMap;renderer.outputColorSpace=THREE.SRGBColorSpace;renderer.toneMapping=THREE.ACESFilmicToneMapping;renderer.toneMappingExposure=1.2;container.appendChild(renderer.domElement);
  const scene=new THREE.Scene(),camera=new THREE.PerspectiveCamera(30,1,.1,120);camera.position.set(...(latest.current.flat?[0,23,.61]:[3.1,11.5,16.4]));camera.lookAt(0,0,.6);
  const controls=new OrbitControls(camera,renderer.domElement);controls.target.set(0,0,.6);controls.enableDamping=true;controls.dampingFactor=.08;controls.enablePan=false;controls.enableZoom=false;renderer.domElement.style.touchAction="pan-y";controls.minDistance=12;controls.maxDistance=34;controls.minPolarAngle=.2;controls.maxPolarAngle=1.25;controls.minAzimuthAngle=-.7;controls.maxAzimuthAngle=.7;controls.update();
  const ambient=new THREE.HemisphereLight(0xffffff,0x9ca9c8,3);scene.add(ambient);
  const key=new THREE.DirectionalLight(0xffffff,4.5);key.position.set(-6,12,5);key.castShadow=true;key.shadow.mapSize.set(2048,2048);Object.assign(key.shadow.camera,{left:-12,right:12,top:12,bottom:-12,near:1,far:40});key.shadow.bias=-.0008;key.shadow.normalBias=.03;key.shadow.radius=5;scene.add(key);
  const rim=new THREE.DirectionalLight(0xffffff,2);rim.position.set(4,6,-8);scene.add(rim);const warm=new THREE.PointLight(0x9bc5ff,16,15);warm.position.set(-5,2,1);scene.add(warm);
  const materials={gold:new THREE.MeshStandardMaterial({color:0xb7c3d5,metalness:.78,roughness:.28}),lightGold:new THREE.MeshStandardMaterial({color:0xe6ecf4,metalness:.68,roughness:.21}),darkGold:new THREE.MeshStandardMaterial({color:0x8e9bb2,metalness:.8,roughness:.3}),chrome:new THREE.MeshStandardMaterial({color:0xdce5f3,metalness:.85,roughness:.2}),body:new THREE.MeshStandardMaterial({color:0x485770,metalness:.52,roughness:.33}),black:new THREE.MeshStandardMaterial({color:0x202e46,metalness:.4,roughness:.5}),cream:new THREE.MeshStandardMaterial({color:0xf0f4fc,metalness:.37,roughness:.32}),copper:new THREE.MeshStandardMaterial({color:0x9eacc6,metalness:.8,roughness:.3}),board:new THREE.MeshStandardMaterial({color:0xc7d2e5,metalness:.45,roughness:.36}),green:new THREE.MeshStandardMaterial({color:0x5cd2aa,emissive:0x3ab990,emissiveIntensity:1.2}),red:new THREE.MeshStandardMaterial({color:0xff7f91,emissive:0xf15f7a,emissiveIntensity:1.5}),yellow:new THREE.MeshStandardMaterial({color:0xe9c46d,emissive:0xd5a84c,emissiveIntensity:.6}),blue:new THREE.MeshStandardMaterial({color:0x9cbae6,emissive:0x6489c2,emissiveIntensity:.7})};
  function box(parent,w,h,d,x,y,z,mat=materials.gold,bevel=0){let geo;if(bevel){const shape=new THREE.Shape(),r=bevel;shape.moveTo(-w/2+r,-d/2);shape.lineTo(w/2-r,-d/2);shape.quadraticCurveTo(w/2,-d/2,w/2,-d/2+r);shape.lineTo(w/2,d/2-r);shape.quadraticCurveTo(w/2,d/2,w/2-r,d/2);shape.lineTo(-w/2+r,d/2);shape.quadraticCurveTo(-w/2,d/2,-w/2,d/2-r);shape.lineTo(-w/2,-d/2+r);shape.quadraticCurveTo(-w/2,-d/2,-w/2+r,-d/2);geo=new THREE.ExtrudeGeometry(shape,{depth:h,bevelEnabled:true,bevelSegments:2,steps:1,bevelSize:.025,bevelThickness:.025,curveSegments:4});geo.rotateX(-Math.PI/2);geo.translate(0,-h/2,0);}else geo=new THREE.BoxGeometry(w,h,d);const m=new THREE.Mesh(geo,mat);m.position.set(x,y,z);m.castShadow=true;m.receiveShadow=true;parent.add(m);return m;}
  function cyl(parent,r,h,x,y,z,mat=materials.chrome,r2=r){const m=new THREE.Mesh(new THREE.CylinderGeometry(r,r2,h,24),mat);m.position.set(x,y,z);m.castShadow=true;parent.add(m);return m;}
  function pipe(points,material,r=.026){const curve=new THREE.CatmullRomCurve3(points.map(p=>new THREE.Vector3(...p)),false,'centripetal');const m=new THREE.Mesh(new THREE.TubeGeometry(curve,70,r,7,false),material);scene.add(m);return curve;}
  function screw(g,x,y,z){cyl(g,.045,.028,x,y,z,materials.chrome);box(g,.05,.008,.009,x,y+.016,z,materials.black);}
  const floor=new THREE.Mesh(new THREE.PlaneGeometry(200,200),new THREE.ShadowMaterial({opacity:.12}));floor.rotation.x=-Math.PI/2;floor.position.y=-.23;floor.receiveShadow=true;scene.add(floor);
  const main=new THREE.Group();main.position.set(0,0,-2);scene.add(main);
  box(main,8.4,.22,3.5,0,0,0,materials.darkGold,.14);box(main,8.25,.09,3.38,0,.16,0,materials.lightGold,.12);box(main,8,.045,3.12,0,.22,0,materials.cream,.08);
  for(const x of [-3.8,3.8])for(const z of [-1.4,1.4])screw(main,x,.275,z);
  // Rounded aluminium collector, with graphite ventilation and an understated light strip.
  box(main,7.65,.59,2.48,0,.52,-.2,materials.chrome,.19);
  box(main,7.54,.045,2.35,0,.85,-.2,materials.cream,.16);
  box(main,7.3,.08,.035,0,.39,1.075,materials.body,.015);
  for(let x=-3.35;x<=3.35;x+=.115)box(main,.025,.14,.025,x,.57,1.065,materials.body);
  for(const x of [-2.85,2.85])for(let z=-.95;z<.55;z+=.13)box(main,.65,.008,.028,x,.884,z,materials.body);
  const emblem=new THREE.Group();emblem.position.set(0,.9,-.2);emblem.rotation.y=Math.PI/4;main.add(emblem);
  for(let i=0;i<3;i++)box(emblem,.44,.035,.44,0,i*.042,0,materials.body,.025);
  box(main,.45,.035,.025,2.78,.73,1.075,materials.green);
  const nodeGroups=[],paths=[],positions=[[-4,0,1.8],[-2.65,0,4.1],[-.3,0,5.25],[2.5,0,4],[4.25,0,1.9],[.7,0,2.15],[-5.1,0,-1],[5.1,0,-1]],portXs=[-3,-1.8,-.6,.6,1.8,3,-3.8,3.8];
  sources.slice(0,8).forEach((source,i)=>{
   const group=new THREE.Group(),[x,y,z]=positions[i];group.position.set(x,y,z);scene.add(group);group.userData.source=source.id;
   box(group,1.55,.16,1.16,0,0,0,materials.darkGold,.08);box(group,1.48,.07,1.1,0,.12,0,materials.lightGold,.08);box(group,1.28,.04,.91,0,.18,0,materials.cream,.035);
   for(const sx of [-.62,.62])for(const sz of [-.4,.4])screw(group,sx,.24,sz);
   if(source.kind==='linux'){
    box(group,.88,.65,.63,0,.52,-.08,materials.body,.03);box(group,.8,.035,.58,0,.87,-.08,materials.gold);
    for(let r=0;r<3;r++){box(group,.73,.135,.035,0,.33+r*.18,.255,materials.black);box(group,.03,.035,.045,.26,.33+r*.18,.28,materials.green);for(let v=0;v<5;v++)box(group,.055,.02,.045,-.25+v*.08,.33+r*.18,.28,materials.chrome);}
   }else if(source.kind==='windows'){
    box(group,.67,.55,.1,-.1,.64,-.15,materials.gold,.035);box(group,.56,.42,.015,-.1,.66,-.087,materials.black,.02);box(group,.47,.26,.015,-.1,.68,-.073,materials.body);box(group,.08,.26,.09,-.1,.3,-.15,materials.chrome);box(group,.4,.035,.26,-.1,.225,-.04,materials.darkGold);box(group,.53,.045,.19,.05,.235,.32,materials.body,.02);for(let k=0;k<6;k++)box(group,.05,.015,.13,-.16+k*.08,.265,.32,materials.gold);
   }else if(source.kind==='application'){
    box(group,.65,.63,.57,0,.53,-.08,materials.gold,.04);box(group,.53,.49,.03,0,.55,.22,materials.body);for(let r=0;r<4;r++)box(group,.36,.025,.035,0,.39+r*.09,.245,materials.chrome);box(group,.04,.04,.045,.17,.78,.25,materials.green);
   }else{
    box(group,1,.22,.58,0,.34,-.1,materials.body,.04);for(let k=0;k<6;k++){box(group,.1,.07,.025,-.36+k*.14,.34,.205,materials.gold);box(group,.027,.018,.03,-.36+k*.14,.41,.21,materials.green)}for(const sx of [-.43,.43]){cyl(group,.025,.5,sx,.69,-.23,materials.chrome);cyl(group,.055,.15,sx,.97,-.23,materials.black);}
   }
   const critical=source.alerts>0,accent=critical?materials.red:i===2?materials.blue:i===3?materials.yellow:materials.green;
   box(group,.23,.04,.075,.42,.25,.33,accent);const ring=new THREE.Mesh(new THREE.RingGeometry(.98,1.01,60),new THREE.MeshBasicMaterial({color:0x8cb9ff,transparent:true,opacity:.8,side:THREE.DoubleSide}));ring.rotation.x=-Math.PI/2;ring.position.y=-.065;group.add(ring);
   const port=portXs[i];box(main,.25,.23,.43,port,.34,1.21,materials.chrome,.025);box(main,.17,.15,.1,port,.35,1.46,accent);
   const start=[port,.33,-.5],end=[x,.24,z-.58],middleZ=.2+i*.13;
   const curve=pipe([start,[port,.23,middleZ],[x,.23,middleZ],[x,.24,z-.7],end],new THREE.MeshStandardMaterial({color:critical?0xe5a4b6:i===2?0x89aaf4:0xb2bfe0,emissive:critical?0xd67f9b:0x7d9cca,emissiveIntensity:.27,metalness:.45,roughness:.3}),.023);
   const pulse=new THREE.Mesh(new THREE.SphereGeometry(.043,8,8),new THREE.MeshBasicMaterial({color:critical?0xff92ad:0x9bbfff}));scene.add(pulse);paths.push({curve,pulse,group,critical});
   nodeGroups.push({group,ring,source,position:new THREE.Vector3(x,.5,z),label:new THREE.Vector3(x,.1,z+.9)});
  });
  const raycaster=new THREE.Raycaster(),pointer=new THREE.Vector2();let pointerDown;
  function hit(event){const rect=renderer.domElement.getBoundingClientRect();pointer.set((event.clientX-rect.left)/rect.width*2-1,-(event.clientY-rect.top)/rect.height*2+1);raycaster.setFromCamera(pointer,camera);const hits=raycaster.intersectObjects(nodeGroups.map(n=>n.group),true);if(!hits.length)return null;let obj=hits[0].object;while(obj&&!obj.userData.source)obj=obj.parent;return obj?.userData.source;}
  const move=e=>{const id=hit(e);renderer.domElement.style.cursor=id?'pointer':'grab';setHover(id||null)},down=e=>{pointerDown=[e.clientX,e.clientY]},up=e=>{if(pointerDown&&Math.hypot(e.clientX-pointerDown[0],e.clientY-pointerDown[1])<5){const id=hit(e);if(id)latest.current.onSelect(id)}};
  renderer.domElement.addEventListener('pointermove',move);renderer.domElement.addEventListener('pointerdown',down);renderer.domElement.addEventListener('pointerup',up);
  function fitScene(){camera.zoom=1;camera.updateProjectionMatrix();camera.updateMatrixWorld();let maxX=0,maxY=0;for(const x of [-5.45,5.45])for(const y of [-.2,1.4])for(const z of [-4,6]){const v=new THREE.Vector3(x,y,z).project(camera);maxX=Math.max(maxX,Math.abs(v.x));maxY=Math.max(maxY,Math.abs(v.y));}camera.zoom=Math.min(.89/maxX,.86/maxY);camera.updateProjectionMatrix();}
  function resize(){const w=container.clientWidth,h=container.clientHeight;if(!w||!h)return;renderer.setSize(w,h);camera.aspect=w/h;fitScene();queueMicrotask(()=>{dirty=true});}const observer=new ResizeObserver(resize);observer.observe(container);resize();
  api.current={zoom:amount=>{camera.position.sub(controls.target).multiplyScalar(amount).add(controls.target);controls.update()},reset:()=>{camera.position.set(3.1,11.5,16.4);controls.target.set(0,0,.6);controls.update();fitScene()},camera,controls,fitScene};
  let frame,last=0,labelTime=0,elapsed=0,labelSignature='',selectionSignature='',dirty=true,visible=true;
  const reducedMotion=window.matchMedia('(prefers-reduced-motion: reduce)');
  const intersection=new IntersectionObserver(entries=>{visible=entries[0]?.isIntersecting??true;dirty=true});intersection.observe(container);
  const changed=()=>{dirty=true};controls.addEventListener('change',changed);
  function animate(ms){
   frame=requestAnimationFrame(animate);if(document.hidden||!visible||ms-last<32)return;
   const dt=(ms-last)/1000;last=ms;controls.update();
   const moving=latest.current.live&&!reducedMotion.matches&&paths.length>0;
   if(moving){elapsed+=Math.min(dt,.1);dirty=true;}
   const nextSelection=latest.current.selected+':'+latest.current.onlyAlerts;
   if(nextSelection!==selectionSignature){selectionSignature=nextSelection;dirty=true;renderer.shadowMap.needsUpdate=true;}
   if(!dirty)return;dirty=false;
   for(let i=0;i<paths.length;i++){const p=paths[i];p.pulse.position.copy(p.curve.getPointAt((elapsed*.16+i*.17)%1));p.pulse.visible=!latest.current.onlyAlerts||p.critical;}
   nodeGroups.forEach(n=>{n.ring.visible=latest.current.selected===n.source.id;n.group.visible=!latest.current.onlyAlerts||n.source.alerts>0});
   renderer.render(scene,camera);
   if(ms-labelTime>90){labelTime=ms;const w=container.clientWidth,h=container.clientHeight;const projected=nodeGroups.map(n=>{const v=n.label.clone().project(camera);return {id:n.source.id,name:n.source.name,ip:n.source.ip,simulated:n.source.simulated,alert:n.source.alerts,x:Math.round((v.x+1)/2*w),y:Math.round((-v.y+1)/2*h),visible:n.group.visible}});const signature=projected.map(p=>p.id+':'+p.x+':'+p.y+':'+p.visible).join('|');if(signature!==labelSignature){labelSignature=signature;setLabels(projected)}}
  }
  frame=requestAnimationFrame(animate);
  return()=>{cancelAnimationFrame(frame);observer.disconnect();intersection.disconnect();controls.removeEventListener('change',changed);controls.dispose();renderer.domElement.removeEventListener('pointermove',move);renderer.domElement.removeEventListener('pointerdown',down);renderer.domElement.removeEventListener('pointerup',up);scene.traverse(o=>{o.geometry?.dispose();if(o.material&&!Object.values(materials).includes(o.material))o.material.dispose?.()});Object.values(materials).forEach(m=>m.dispose());renderer.dispose();renderer.domElement.remove();api.current=null};
 },[sources.map(s=>[s.id,s.alerts,s.name,s.ip,s.simulated].join(':')).join('|')]);
 useEffect(()=>{if(!api.current)return;const {camera,controls,fitScene}=api.current;camera.position.set(...(flat?[0,23,.61]:[3.1,11.5,16.4]));controls.update();fitScene()},[flat]);
 return <div className="physical-network"><div className="webgl-stage" ref={mount}/>{failed?<div className="scene-fallback"><Layers3/><p>La vista 3D necesita WebGL. Consulta los equipos en la colección inferior.</p></div>:<><div className="scene-haze"/><div className="scene-labels">{labels.map(l=>l.id==='core'?<div key={l.id} className="core-annotation" style={{left:l.x,top:l.y}}><span>SECTOR 01</span><strong>HyperLogs Core</strong><i/></div>:showLabels&&l.visible?<button key={l.id} style={{left:l.x,top:l.y}} className={'physical-label '+(selected===l.id?'selected':'')+(hover===l.id?' hovered':'')} onClick={()=>onSelect(l.id)}><span className="physical-id"><i className={l.alert?'critical':''}/>{l.name}</span><small>{l.ip} {l.simulated?'· SIM':'· REAL'}</small></button>:null)}</div><div className="scene-navigation"><span><i/> Arrastra para explorar · usa + y − para acercar</span><div><button aria-label="Alejar" onClick={()=>api.current?.zoom(1.15)}><Minus size={13}/></button><button aria-label="Acercar" onClick={()=>api.current?.zoom(.87)}><Plus size={13}/></button><button aria-label="Restablecer cámara" onClick={()=>api.current?.reset()}><RotateCcw size={12}/></button></div></div></>}</div>
}
