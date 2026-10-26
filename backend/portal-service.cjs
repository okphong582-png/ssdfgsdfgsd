'use strict';
const crypto=require('node:crypto');
const p=require('./portal-policy.cjs');
const s=require('./portal-state.cjs');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function decodeSecret(value){
 if(typeof value!=='string'||!/^[A-Za-z0-9+/]+={0,2}$/.test(value))throw Error('invalid_service_secret');
 const bytes=Buffer.from(value,'base64');if(bytes.length<32||bytes.toString('base64')!==value)throw Error('invalid_service_secret');return bytes;
}
function canonical(method,path,timestamp,nonce,body,token='',sessionId=''){return [method,path,timestamp,nonce,sha(body),sha(token),sessionId].join('\n');}
function sign(secret,method,path,timestamp,nonce,body,token='',sessionId=''){return crypto.createHmac('sha256',secret).update(canonical(method,path,timestamp,nonce,body,token,sessionId)).digest('hex');}
function createPortalService({database,verifyIdToken,serviceSecret,lookupSecret,now=Date.now}){
 const serviceKey=Buffer.isBuffer(serviceSecret)?serviceSecret:decodeSecret(serviceSecret);
 const lookupKey=Buffer.isBuffer(lookupSecret)?lookupSecret:decodeSecret(lookupSecret);
 if(serviceKey.length<32||lookupKey.length<32||serviceKey.equals(lookupKey))throw Error('independent_service_secrets_required');
 const bucket=(kind,value)=>kind+'-'+crypto.createHmac('sha256',serviceKey).update(value).digest('hex');
 async function rate(key,limit,clock){
  const window=Math.floor(clock/60000),result=await database.ref('_mizzePortalRate/'+key).transaction(current=>{
   if(current===null||current===undefined||current.window!==window)return {window,count:1,updatedAt:clock};
   if(!Number.isSafeInteger(current.count)||current.count<1||current.count>=limit)return;
   return {window,count:current.count+1,updatedAt:clock};
  });if(!result.committed)p.fail('rate_limited',429);
 }
 async function authenticate({method,path,headers,rawBody,ip},preauth=false){
  const clock=now(),stamp=headers['x-mizze-timestamp'],nonce=headers['x-mizze-nonce'],signature=headers['x-mizze-signature'];
  const auth=headers.authorization,token=typeof auth==='string'&&/^Bearer [^\s]{1,8192}$/.test(auth)?auth.slice(7):'';
  const creatingSession=path==='/portal/v1/sessions',sessionId=headers['x-mizze-session']||'';
  if(!/^\d{13}$/.test(stamp||'')||!/^[a-f0-9]{32}$/.test(nonce||'')||!/^[a-f0-9]{64}$/.test(signature||'')||
   (preauth?auth!==undefined:!token)||((preauth||creatingSession)?sessionId!=='':!s.HEX.test(sessionId)))p.fail('unauthorized',401);
  const timestamp=Number(stamp);if(!Number.isSafeInteger(timestamp)||clock-timestamp>30000||timestamp-clock>5000)p.fail('unauthorized',401);
  const expected=sign(serviceKey,method,path,stamp,nonce,rawBody,token,sessionId);
  if(!crypto.timingSafeEqual(Buffer.from(expected,'hex'),Buffer.from(signature,'hex')))p.fail('unauthorized',401);
  // The signed timestamp can be slightly ahead of this server. Retain the
  // nonce through the complete acceptance window, not only now + 30 seconds.
  const result=await database.ref('_mizzePortalNonces/'+bucket('nonce',nonce)).transaction(current=>{
   if(current&&(!Number.isSafeInteger(current.expiresAt)||current.expiresAt>=clock))return;
   return {createdAt:clock,expiresAt:Math.max(clock,timestamp)+30000};
  });if(!result.committed)p.fail('replay_rejected',401);
  if(preauth)return null;
  let identity;try{identity=await verifyIdToken(token,true);}catch{p.fail('unauthorized',401);}
  if(!identity||!s.uid(identity.uid))p.fail('unauthorized',401);
  await rate(bucket('uid',identity.uid),60,clock);await rate(bucket('ip',String(ip||'unknown')),180,clock);
  if(!creatingSession){
   const session=(await database.ref('_mizzePortalSessions/'+bucket('session',sessionId)).get()).val();
   if(!session||session.uid!==identity.uid||!Number.isSafeInteger(session.expiresAt)||!Number.isSafeInteger(session.revokedAt))p.fail('session_invalid',401);
   if(session.expiresAt<=clock)p.fail('session_expired',401);
   if(session.revokedAt!==0&&path!=='/portal/v1/sessions/logout')p.fail('session_revoked',401);
  }
  return identity;
 }
 async function byKey(key,ownerUid,clock){
  const alias=p.keyAlias(key,lookupKey),snapshot=await database.ref('portalKeyAliases/'+alias).get(),locator=snapshot.val();
  if(!locator||!s.HEX.test(locator.licenseId))p.fail('key_not_found',404);
  // Alias is a locator only. Every operation checks ownership in the same
  // authoritative license record used by issuance; alias fields never grant.
  const record=(await database.ref('licensesV9/'+locator.licenseId).get()).val();p.owned(record,ownerUid,clock);
  return {id:locator.licenseId,record};
 }
 async function handle(context){
  const preauth=context.path==='/portal/v1/auth/attempt';
  const identity=await authenticate(context,preauth),clock=now();
  let body;try{body=context.rawBody.length?JSON.parse(context.rawBody.toString('utf8')):{};}catch{p.fail('invalid_request');}
  if(preauth){
   if(!s.plain(body)||Object.keys(body).length!==2||!s.HEX.test(body.accountHash)||!s.HEX.test(body.ipHash))p.fail('invalid_request');
   await rate(bucket('login-account',body.accountHash),5,clock);await rate(bucket('login-ip',body.ipHash),20,clock);return {ok:true};
  }
  const ownerUid=identity.uid;
  if(context.path==='/portal/v1/sessions'){
   if(!s.plain(body)||Object.keys(body).length!==2||!s.HEX.test(body.sessionId)||!Number.isSafeInteger(body.expiresAt)||body.expiresAt<=clock||body.expiresAt>clock+8*3600000)p.fail('invalid_request');
   if(!Number.isSafeInteger(identity.auth_time)||identity.auth_time*1000>clock+5000||clock-identity.auth_time*1000>300000)p.fail('reauth_required',401);
   await rate(bucket('session-create',ownerUid),10,clock);
   const created=await database.ref('_mizzePortalSessions/'+bucket('session',body.sessionId)).transaction(current=>{
    if(current!==null&&current!==undefined)return;
    return {uid:ownerUid,createdAt:clock,expiresAt:body.expiresAt,revokedAt:0};
   });if(!created.committed)p.fail('session_exists',409);return {ok:true};
  }
  if(context.path==='/portal/v1/sessions/logout'){
   if(!s.plain(body)||Object.keys(body).length!==0)p.fail('invalid_request');
   const revoked=await database.ref('_mizzePortalSessions/'+bucket('session',context.headers['x-mizze-session'])).transaction(current=>{
    if(current===null)return null;
    if(current.uid!==ownerUid||!Number.isSafeInteger(current.expiresAt)||current.expiresAt<=clock||!Number.isSafeInteger(current.revokedAt))return;
    return {...current,revokedAt:current.revokedAt||clock};
   });if(!revoked.committed||revoked.snapshot.val()?.uid!==ownerUid)p.fail('session_invalid',401);return {ok:true};
  }
  if(context.path==='/portal/v1/licenses'){
   if(context.rawBody.length)p.fail('invalid_request');
   const snapshot=await database.ref('licensesV9').orderByChild('portal/ownerUid').equalTo(ownerUid).limitToFirst(2).get(),records=snapshot.val()||{};
   // Every account owns at most one key. Read a second row only to detect
   // inconsistent ownership; never hide extra keys by truncating the result.
   if(Object.keys(records).length>1)p.fail('account_limit',409);
   const licenses=[];for(const [id,record]of Object.entries(records)){p.owned(record,ownerUid,clock);licenses.push(p.dto(id,record,clock));}
   return {licenses};
  }
  const action=context.path==='/portal/v1/keys/status'?'status':context.path.split('/').at(-1);p.validateInput(action,body);
  const lookup=(action==='activate'||action==='status')?await byKey(body.key,ownerUid,clock):{id:body.licenseId};
  if(action==='status')return {license:p.dto(lookup.id,lookup.record,clock)};
  if(action==='reset'||action==='logout'){
   if(!Number.isSafeInteger(identity.auth_time)||identity.auth_time*1000>clock+5000||clock-identity.auth_time*1000>300000)p.fail('reauth_required',401);
  }
  let lastError;
  const result=await database.ref('licensesV9/'+lookup.id).transaction(record=>{
   lastError=undefined;
   // Admin SDK's first transaction callback can receive a cold-cache null.
   // Return null to fetch/retry; snapshot is validated before any success.
   if(record===null)return null;
   try{return p.change(record,{ownerUid,action,deviceId:body.deviceId,operationId:body.operationId},now());}
   catch(error){lastError=error;return;}
  });
  if(!result.committed)throw lastError||new p.PortalError('key_not_found',404);
  const updated=result.snapshot.val();p.owned(updated,ownerUid,now());return {license:p.dto(lookup.id,updated,now())};
 }
 return {handle,authenticate};
}
module.exports={createPortalService,canonical,sign,sha,decodeSecret};
