'use strict';
const lease=require('./lease-v9.cjs');
async function ensureKey(primary,getLegacy,id,now=Date.now()){
 if(!/^[a-f0-9]{64}$/.test(id))throw Error('invalid_request');
 const ref=primary.ref('licensesV9/'+id),current=(await ref.get()).val();
 if(current!==null)return current;
 const legacy=await getLegacy();if(!legacy)return null;
 const source=(await legacy.ref('licensesV9/'+id).get()).val();
 if(!lease.validRecord(source,now))return null;
 // The submitted Key/password pair produced this exact record ID. Copy the
 // original entitlement without restarting its clock or dropping its devices.
 // A concurrent import/activation always wins over this missing-only insert.
 const result=await ref.transaction(value=>value===null?structuredClone(source):value);
 return result.committed?result.snapshot.val():(await ref.get()).val();
}
module.exports={ensureKey};
