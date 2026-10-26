'use strict';
const crypto=require('node:crypto'),legacy=require('./lease-v9.cjs');
const identity=require('./game-license-v10.public.json');
const hex=(v,n)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
function validateRequest(body){
 if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length!==7||
 Object.keys(body).some(k=>!['v','release','brandDigest','keyHash','deviceHash','nonce','claim'].includes(k))||
 body.v!==10||body.release!==identity.release||body.brandDigest!==identity.brandDigest||body.claim!==false||
 !hex(body.keyHash,64)||!hex(body.deviceHash,64)||!hex(body.nonce,32))throw Error('invalid_request');
 return body;
}
function createService({database,signingKey,now=Date.now,expectedSigningKid=identity.kid}){
 let key=null;
 async function rate(path,limit,clock){
  const window=Math.floor(clock/60000),r=await database.ref('_mizzeRateV10/'+path).transaction(value=>{
   if(!value||value.window!==window)return {window,count:1,updatedAt:clock};
   if(!Number.isInteger(value.count)||value.count>=limit)return;
   return {...value,count:value.count+1,updatedAt:clock};
  });return r.committed;
 }
 return async(body,ip)=>{
  const request=validateRequest(body),clock=now(),secret=signingKey();
  if(!key){
   const parsed=crypto.createPrivateKey(secret),publicKey=crypto.createPublicKey(parsed);
   if(parsed.asymmetricKeyType!=='rsa'||parsed.asymmetricKeyDetails.modulusLength!==3072||
    crypto.createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex')!==expectedSigningKid)throw Error('invalid_signing_key');
   key=parsed;
  }
  const bucket=value=>crypto.createHmac('sha256',secret).update(value).digest('hex');
  if(!await rate('ip-'+bucket('ip:'+String(ip||'unknown')),600,clock)||
     !await rate('device-'+bucket(request.keyHash+':'+request.deviceHash),18,clock))return {status:429,error:'rate_limited'};
  const result=await database.ref('licensesV9/'+request.keyHash).transaction(record=>{
   if(record===null)return null;
   // Enrollment is a web operation. No legacy/self-claim fallback is allowed.
   if(!record.portal||!legacy.validRecord(record,clock))return;
   return legacy.bind(record,{keyHash:request.keyHash,deviceHash:request.deviceHash,nonce:request.nonce,claim:false},clock);
  });
  const record=result.snapshot.val();
  if(!result.committed||!record?.devices?.[request.deviceHash]||record.devices[request.deviceHash].portalLoggedOut!==false)return {status:403,error:'license_denied'};
  // Keep a bounded two-minute replay ledger per credential/device pair.
  const nonce=await database.ref('_mizzeNonceV10/'+bucket(request.keyHash+':'+request.deviceHash)).transaction(value=>{
   const entries=Object.fromEntries(Object.entries(value||{}).filter(([,at])=>Number.isSafeInteger(at)&&at>clock-120000));
   if(Object.hasOwn(entries,request.nonce)||Object.keys(entries).length>=36)return;
   entries[request.nonce]=clock;return entries;
  });
  if(!nonce.committed)return {status:403,error:'license_denied'};
  const payload=Buffer.from(JSON.stringify({v:10,aud:identity.audience,release:identity.release,brandDigest:identity.brandDigest,
   keyHash:request.keyHash,deviceHash:request.deviceHash,nonce:request.nonce,issuedAt:clock,
   expiresAt:Math.min(record.expiresAt,clock+30000),licenseExpiresAt:record.expiresAt,
   activatedAt:record.timeMode==='firstUse'?record.activatedAt:0,maxDevices:record.maxDevices,bindingVersion:record.portal.bindingVersion}));
  return {status:200,envelope:{alg:'RS256',kid:expectedSigningKid,payload:payload.toString('base64'),
   signature:crypto.sign('RSA-SHA256',payload,{key,padding:crypto.constants.RSA_PKCS1_PADDING}).toString('base64')}};
 };
}
module.exports={validateRequest,createService};
