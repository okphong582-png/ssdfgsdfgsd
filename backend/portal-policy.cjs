'use strict';
const crypto=require('node:crypto');
const legacy=require('./lease-v9.cjs');
const s=require('./portal-state.cjs');
const DAY=86400000,COOLDOWN=0,WINDOW=30*DAY,RESET_LIMIT=2;
// One calendar day in Vietnam (UTC+07:00); client clocks never decide quota.
const dayStart=now=>Math.floor((now+7*3600000)/DAY)*DAY-7*3600000;
class PortalError extends Error{constructor(code,status=400){super(code);this.code=code;this.status=status;}}
const fail=(code,status=400)=>{throw new PortalError(code,status);};
function normalizeKey(value){if(typeof value!=='string')fail('invalid_request');const key=value.trim().toUpperCase();if(!/^[!-~]{8,128}$/.test(key))fail('invalid_request');return key;}
function keyAlias(key,lookupSecret){return crypto.createHmac('sha256',lookupSecret).update(normalizeKey(key)).digest('hex');}
function validateInput(action,body){
 if(!s.plain(body))fail('invalid_request');
 const allowed=action==='activate'?['key','deviceId','operationId']:action==='status'?['key']:['licenseId','deviceId','operationId'];
 if(Object.keys(body).some(k=>!allowed.includes(k))||allowed.some(k=>!s.own(body,k)))fail('invalid_request');
 if(action==='activate'||action==='status')normalizeKey(body.key);
 else if(!s.HEX.test(body.licenseId))fail('invalid_request');
 if(action!=='status'&&(!s.HEX.test(body.deviceId)||!s.operationId(body.operationId)))fail('invalid_request');
 return body;
}
function owned(record,ownerUid,now){
 if(!record||!s.hasPortal(record)||!legacy.validRecord(record,now,true)||record.portal.ownerUid!==ownerUid)fail('key_not_found',404);
 return record;
}
function resetInfo(record,now){
 const start=dayStart(now),history=(record.portal.resetHistory||[]).filter(t=>t>=start&&t<=now);
 return {used:history.length,limit:RESET_LIMIT,remaining:Math.max(0,RESET_LIMIT-history.length),
 nextAllowedAt:history.length>=RESET_LIMIT?start+DAY:0};
}
function dto(id,record,now){
 const devices=Object.entries(record.devices||{}).map(([id,d])=>({id,claimedAt:d.claimedAt,loggedOut:d.portalLoggedOut===true}));
 let status=record.enabled!==true||(record.lock&&(record.lock.until===0||record.lock.until>now))?'disabled':
 record.timeMode==='firstUse'&&record.activatedAt===0?'pending':record.expiresAt<=now?'expired':devices.length===0?'reset_required':devices.every(d=>d.loggedOut)?'logged_out':'active';
 return {id,label:record.portal.label||'Mizze',status,expiresAt:record.expiresAt,activatedAt:record.activatedAt||0,maxDevices:record.maxDevices,devices,
 reset:resetInfo(record,now),...(record.durationMs?{durationMs:record.durationMs}:{})};
}
function change(record,{ownerUid,action,deviceId,operationId},now){
 owned(record,ownerUid,now);
 if(!s.HEX.test(deviceId)||!s.operationId(operationId)||!['activate','reset','logout'].includes(action))fail('invalid_request');
 const old=record.portal.operations?.[operationId];
 if(old){if(old.type!==action||old.deviceId!==deviceId)fail('idempotency_conflict',409);return record;}
 let next=structuredClone(record),p=next.portal,devices=next.devices||{};
 if(action==='activate'){
  if(!legacy.validRecord(record,now))fail('license_unavailable',403);
  if(!devices[deviceId]&&Object.keys(devices).length>=record.maxDevices)fail('device_limit',409);
  if(next.timeMode==='firstUse'&&next.activatedAt===0){if(!Number.isSafeInteger(now+next.durationMs))fail('invalid_record',409);next.activatedAt=now;next.expiresAt=now+next.durationMs;}
  const existing=devices[deviceId];
  devices[deviceId]={version:1,claimedAt:existing?.claimedAt||now,portalLoggedOut:false,portalApprovedAt:now,portalBindingVersion:p.bindingVersion};next.devices=devices;
 }else if(action==='logout'){
  if(!devices[deviceId])fail('device_not_found',404);
  devices[deviceId].portalLoggedOut=true;next.devices=devices;p.bindingVersion++;
 }else{
  if(!devices[deviceId])fail('device_not_found',404);
  const limit=resetInfo(record,now);if(now<limit.nextAllowedAt)fail('reset_limited',409);
  delete devices[deviceId];next.devices=Object.keys(devices).length?devices:null;
  p.resetHistory=[...(p.resetHistory||[]).filter(t=>t>=dayStart(now)&&t<=now),now];p.lastResetAt=now;p.bindingVersion++;
 }
 if(!Number.isSafeInteger(p.bindingVersion))fail('invalid_record',409);
 const operations=Object.entries(p.operations||{}).filter(([,v])=>v.at>now-WINDOW).sort((a,b)=>a[1].at-b[1].at).slice(-31);
 p.operations=Object.fromEntries(operations);p.operations[operationId]={type:action,deviceId,at:now};
 if(!legacy.validRecord(next,now,true))fail('invalid_record',409);
 return next;
}
module.exports={PortalError,fail,normalizeKey,keyAlias,validateInput,owned,resetInfo,dto,change,DAY,COOLDOWN,WINDOW,RESET_LIMIT,dayStart};
