import React,{lazy,Suspense} from 'react';
import {Layers3} from 'lucide-react';
const Scene=lazy(()=>import('./NetworkScene'));
export default function SceneLoader(props){return <Suspense fallback={<div className="scene-loading"><Layers3 size={28}/><span>Preparando la vista de red…</span></div>}><Scene {...props}/></Suspense>}
