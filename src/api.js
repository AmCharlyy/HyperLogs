// Sessions live in an HttpOnly cookie. Only the per-session CSRF proof is in memory.
let csrf='',sessionEpoch=0;
const pending=new Map();
sessionStorage.removeItem('hyperlogs.token');
export function acceptSession(value){const next=value?.csrf||'';if(next!==csrf){csrf=next;sessionEpoch++;}}
export function clearSession(){csrf='';sessionEpoch++;}
export function reportError(error){if(error?.name!=='AbortError')window.dispatchEvent(new CustomEvent('hyperlogs:error',{detail:error?.message||'No se pudo cargar la información'}));}
export async function rawApi(path,options={}){
 const method=options.method||'GET';
 const headers={...(options.body?{'Content-Type':'application/json'}:{}),...(csrf?{'X-HyperLogs-CSRF':csrf}:{}),...options.headers};
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
 const abort=()=>controller.abort();options.signal?.addEventListener('abort',abort,{once:true});
 try{
  const response=await fetch('/api'+path,{...options,method,credentials:'same-origin',headers,signal:controller.signal,body:options.body?JSON.stringify(options.body):undefined});
  if(!response.ok){let value;try{value=await response.json()}catch{};
   if(response.status===401&&!path.startsWith('/auth/login')){clearSession();window.dispatchEvent(new Event('hyperlogs:expired'));}
   throw new Error(typeof value?.detail==='string'?value.detail:response.status===422?'Revisa los campos y filtros enviados.':'No se pudo completar la operación ('+response.status+')');
  }
  return response;
 }catch(error){if(error.name==='AbortError'&&!options.signal?.aborted)throw new Error('La solicitud tardó demasiado. Intenta de nuevo.');throw error;}
 finally{clearTimeout(timer);options.signal?.removeEventListener('abort',abort);}
}
export function api(path,options={}){
 // Coalesce identical requests, including accidental double-clicks on creation buttons.
 const key=sessionEpoch+':'+(options.method||'GET')+path+JSON.stringify(options.body||null);
 if(!options.signal&&pending.has(key))return pending.get(key);
 const promise=rawApi(path,options).then(r=>r.json());
 if(!options.signal){pending.set(key,promise);promise.finally(()=>pending.delete(key)).catch(()=>{});}
 return promise;
}
