'use strict';
const crypto=require('node:crypto');
const {hasPortal,validPortal}=require('./portal-state.cjs');
const HEX=/^[a-f0-9]{64}$/,NONCE=/^[a-f0-9]{32}$/;
const AUDIENCE='mizze-th-license-v9',TTL=30000,SESSION_TTL=600000;
const MAX_DURATION=3650*86400000;
function validSchedule(record,now,allowInactive=false){
  if(record.timeMode===undefined)return record.durationMs===undefined&&record.activatedAt===undefined&&Number.isSafeInteger(record.expiresAt)&&record.expiresAt>0&&(allowInactive||record.expiresAt>now);
  if(record.timeMode!=='firstUse'||!Number.isSafeInteger(record.durationMs)||record.durationMs<1000||record.durationMs>MAX_DURATION||
    !Number.isSafeInteger(record.activatedAt)||!Number.isSafeInteger(record.expiresAt))return false;
  if(record.activatedAt===0)return record.expiresAt===0&&Object.keys(record.devices||{}).length===0;
  return record.activatedAt>0&&record.activatedAt<=now&&Number.isSafeInteger(record.activatedAt+record.durationMs)&&
    record.expiresAt===record.activatedAt+record.durationMs&&(allowInactive||record.expiresAt>now);
}
function validateRequest(body){
  if(!body||typeof body!=='object'||Array.isArray(body)||!HEX.test(body.keyHash||'')||
    !HEX.test(body.deviceHash||'')||!NONCE.test(body.nonce||'')||typeof body.claim!=='boolean'||
    Object.keys(body).some(k=>!['keyHash','deviceHash','nonce','claim','sessionSeconds'].includes(k))||
    (Object.hasOwn(body,'sessionSeconds')&&body.sessionSeconds!==600))throw Error('invalid_request');
  const value={keyHash:body.keyHash,deviceHash:body.deviceHash,nonce:body.nonce,claim:body.claim};
  if(Object.hasOwn(body,'sessionSeconds'))value.sessionSeconds=600;
  return value;
}
function validRecord(record,now,allowInactive=false){
  if(!Number.isSafeInteger(now)||!record||record.protocol!==9||![2,3].includes(record.credentialMode)||typeof record.enabled!=='boolean'||(!allowInactive&&record.enabled!==true)||
    now<=0||!Number.isInteger(record.maxDevices)||record.maxDevices<1||record.maxDevices>50)return false;
  if(record.lock!==undefined&&record.lock!==null){
    const lock=record.lock;if(typeof lock!=='object'||Array.isArray(lock)||!Number.isSafeInteger(lock.until)||lock.until<0||
      typeof lock.message!=='string'||lock.message.length>500||(!allowInactive&&(lock.until===0||lock.until>now)))return false;
  }
  const devices=record.devices;
  if(devices!==undefined&&devices!==null){
    if(typeof devices!=='object'||Array.isArray(devices)||Object.keys(devices).length>record.maxDevices)return false;
    for(const [id,value] of Object.entries(devices))if(!HEX.test(id)||!value||typeof value!=='object'||Array.isArray(value)||
      value.version!==1||!Number.isSafeInteger(value.claimedAt)||value.claimedAt<=0||value.claimedAt>now)return false;
  }
  return validSchedule(record,now,allowInactive)&&validPortal(record,now);
}
function bind(record,request,now){
  const req=validateRequest(request);if(!validRecord(record,now))return;
  // Managed licenses can only acquire or resume a device through authenticated
  // website activation. A legacy client's claim flag grants no enrollment.
  if(hasPortal(record))return record.devices&&Object.hasOwn(record.devices,req.deviceHash)&&record.devices[req.deviceHash].portalLoggedOut===false?record:undefined;
  if(record.devices&&Object.hasOwn(record.devices,req.deviceHash))return record;
  const devices=record.devices||{};
  if(!req.claim||Object.keys(devices).length>=record.maxDevices)return;
  if(record.timeMode==='firstUse'&&!Number.isSafeInteger(now+record.durationMs))return;
  const activation=record.timeMode==='firstUse'&&record.activatedAt===0?{activatedAt:now,expiresAt:now+record.durationMs}:{};
  return {...record,...activation,devices:{...devices,[req.deviceHash]:{version:1,claimedAt:now}}};
}
function issueLease(request,record,now,key){
  const req=validateRequest(request);
  if(!validRecord(record,now)||record.expiresAt<=now||!record.devices||!Object.hasOwn(record.devices,req.deviceHash)||
    (hasPortal(record)&&record.devices[req.deviceHash].portalLoggedOut!==false))throw Error('license_denied');
  if(typeof key==='string'||Buffer.isBuffer(key))key=crypto.createPrivateKey(key);
  if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072)throw Error('invalid_signing_key');
  const publicKey=crypto.createPublicKey(key),kid=crypto.createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
  const payload=Buffer.from(JSON.stringify({v:9,aud:AUDIENCE,keyHash:req.keyHash,deviceHash:req.deviceHash,
    nonce:req.nonce,issuedAt:now,expiresAt:Math.min(record.expiresAt,now+(!hasPortal(record)&&req.sessionSeconds===600?SESSION_TTL:TTL)),
    licenseExpiresAt:record.expiresAt,activatedAt:record.timeMode==='firstUse'?record.activatedAt:0,maxDevices:record.maxDevices,
    ...(hasPortal(record)?{bindingVersion:record.portal.bindingVersion}:{})}));
  const signature=crypto.sign('RSA-SHA256',payload,{key,padding:crypto.constants.RSA_PKCS1_PADDING});
  return {alg:'RS256',kid,payload:payload.toString('base64'),signature:signature.toString('base64')};
}
function verifyForTest(envelope,request,publicKey){
  const req=validateRequest(request),raw=Buffer.from(envelope.payload,'base64');
  if(envelope.alg!=='RS256'||!crypto.verify('RSA-SHA256',raw,{key:publicKey,padding:crypto.constants.RSA_PKCS1_PADDING},Buffer.from(envelope.signature,'base64')))return false;
  const value=JSON.parse(raw);return value.aud===AUDIENCE&&value.v===9&&value.keyHash===req.keyHash&&value.deviceHash===req.deviceHash&&value.nonce===req.nonce;
}
module.exports={validateRequest,validRecord,bind,issueLease,verifyForTest,AUDIENCE,TTL,SESSION_TTL};
