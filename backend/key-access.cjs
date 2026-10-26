'use strict';
const crypto=require('node:crypto'),lease=require('./lease-v9.cjs'),portal=require('./portal-policy.cjs');
class KeyError extends Error{constructor(code,status=400){super(code);this.code=code;this.status=status;}}
const fail=(code,status=400)=>{throw new KeyError(code,status);};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function credentials(key,password,deviceId){
 if(typeof key!=='string'||typeof password!=='string'||typeof deviceId!=='string')fail('invalid_request');
 key=key.trim().toUpperCase();deviceId=deviceId.trim().toLowerCase();
 if(!/^[!-~]{8,128}$/.test(key)||!/^[!-~]{16,128}$/.test(password)||key===password||!hex(deviceId))fail('invalid_request');
 return {licenseId:crypto.createHash('sha256').update('mizze-pair-v1\n'+key.length+':'+key+'\n'+password.length+':'+password).digest('hex'),deviceId};
}
function usable(record,now){if(!lease.validRecord(record,now))fail('license_denied',403);}
function managed(record,now){
 const next=structuredClone(record);
 if(!next.portal){
  next.portal={v:1,ownerUid:'key-access:'+crypto.randomBytes(16).toString('hex'),label:'MIZZE',bindingVersion:1,resetHistory:[],lastResetAt:0,operations:{}};
  next.devices=Object.fromEntries(Object.entries(next.devices||{}).map(([id,d])=>[id,{version:1,claimedAt:d.claimedAt,portalLoggedOut:false,portalApprovedAt:now,portalBindingVersion:1}]));
 }
 return next;
}
function activateForKey(record,deviceId,now){
 usable(record,now);if(!hex(deviceId))fail('invalid_request');
 if(!record.devices?.[deviceId]&&Object.keys(record.devices||{}).length>=record.maxDevices)return record;
 const next=managed(record,now);
 return portal.change(next,{ownerUid:next.portal.ownerUid,action:'activate',deviceId,operationId:crypto.randomUUID()},now);
}
function resetForKey(record,deviceId,operationId,now){
 usable(record,now);if(!hex(deviceId)||typeof operationId!=='string'||!/^[A-Za-z0-9_-]{16,128}$/.test(operationId))fail('invalid_request');
 const old=record.portal?.operations?.[operationId];
 if(old){if(old.type!=='reset'||old.deviceId!==deviceId)fail('idempotency_conflict',409);return record;}
 if(!Object.keys(record.devices||{}).length)fail('device_not_found',409);
 const next=managed(record,now),p=next.portal,quota=portal.resetInfo(next,now);
 if(quota.remaining<=0)fail('reset_limited',409);
 p.bindingVersion++;if(!Number.isSafeInteger(p.bindingVersion))fail('invalid_record',409);
 p.resetHistory=[...(p.resetHistory||[]).filter(t=>t>=portal.dayStart(now)&&t<=now),now];p.lastResetAt=now;
 p.operations=Object.fromEntries(Object.entries(p.operations||{}).sort((a,b)=>a[1].at-b[1].at).slice(-31));
 p.operations[operationId]={type:'reset',deviceId,at:now};
 next.devices={[deviceId]:{version:1,claimedAt:now,portalLoggedOut:false,portalApprovedAt:now,portalBindingVersion:p.bindingVersion}};
 if(!lease.validRecord(next,now))fail('invalid_record',409);
 return next;
}
function dto(record,deviceId,now){
 const reset=record.portal?portal.resetInfo(record,now):{used:0,limit:2,remaining:2,nextAllowedAt:0};
 const bound=!!record.devices?.[deviceId]&&(!record.portal||record.devices[deviceId].portalLoggedOut===false);
 return {status:!lease.validRecord(record,now)?'unavailable':bound?'active':'reset_required',deviceId,devices:Object.keys(record.devices||{}),maxDevices:record.maxDevices,
  activatedAt:record.activatedAt||0,expiresAt:record.expiresAt,durationMs:record.durationMs||0,reset};
}
module.exports={credentials,activateForKey,resetForKey,dto,KeyError};
