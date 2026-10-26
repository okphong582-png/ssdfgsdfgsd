'use strict';
// In-memory RTDB adapter for deterministic unit/HTTP tests. Transactions are
// serialized and callbacks may see the same authoritative tree as production.
function createDatabase(initial={}){
 let tree=structuredClone(initial),serial=Promise.resolve();
 const parts=path=>(path||'').split('/').filter(Boolean);
 const read=path=>parts(path).reduce((node,key)=>node?.[key],tree)??null;
 const write=(path,value)=>{const keys=parts(path);if(!keys.length){tree=structuredClone(value);return;}let node=tree;for(const key of keys.slice(0,-1))node=node[key]??={};if(value===null)delete node[keys.at(-1)];else node[keys.at(-1)]=structuredClone(value);};
 const snap=value=>({val:()=>structuredClone(value),exists:()=>value!==null,forEach(fn){for(const [key,val]of Object.entries(value||{}))fn({key,val:()=>structuredClone(val)});}});
 function ref(path='',query={}){return {
  async get(){let value=read(path);if(query.order){const sorted=Object.entries(value||{}).filter(([,v])=>{const n=parts(query.order).reduce((o,k)=>o?.[k],v);return query.equal===undefined||n===query.equal;}).sort(([,a],[,b])=>{const val=v=>parts(query.order).reduce((o,k)=>o?.[k],v);return val(a)<val(b)?-1:1;});value=Object.fromEntries(sorted.slice(0,query.limit||Infinity));}return snap(value);},
  transaction(update){const task=serial.then(()=>{const next=update(structuredClone(read(path)));if(next===undefined)return {committed:false,snapshot:snap(read(path))};write(path,next);return {committed:true,snapshot:snap(read(path))};});serial=task.catch(()=>{});return task;},
  orderByChild(order){return ref(path,{...query,order});},equalTo(equal){return ref(path,{...query,equal});},limitToFirst(limit){return ref(path,{...query,limit});},
  async set(value){write(path,value);},async update(value){for(const [key,val]of Object.entries(value))write(path+'/'+key,val);}
 };}
 return {ref,read:path=>structuredClone(read(path))};
}
module.exports={createDatabase};
