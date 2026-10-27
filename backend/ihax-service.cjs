'use strict';
const crypto=require('node:crypto');
const LIFETIME=7*86400000;
const KEY_RE=/^IHAX(?:-[A-F0-9]{8}){4}$/;
const normalize=value=>typeof value==='string'?value.trim().toUpperCase():'';
const keyId=key=>crypto.createHash('sha256').update(key).digest('hex');
class IhaxError extends Error {constructor(code,status){super(code);this.code=code;this.status=status;}}
function createIhaxService({database,rateSecret,now=Date.now,randomBytes=crypto.randomBytes}){
 if(!rateSecret||Buffer.byteLength(rateSecret)<32)throw Error('ihax_not_configured');
 async function rate(label,ip,duration,limit){
  const clock=now(),window=Math.floor(clock/duration);
  const id=crypto.createHmac('sha256',rateSecret).update(label+':'+String(ip||'unknown')).digest('hex');
  const result=await database.ref('_ihaxWebRateV1/'+id).transaction(value=>{
   if(!value||value.window!==window)return {window,count:1,updatedAt:clock};
   if(!Number.isSafeInteger(value.count)||value.count>=limit)return;
   return {...value,count:value.count+1,updatedAt:clock};
  });if(!result.committed)throw new IhaxError('rate_limited',429);
 }
 return {
  async issue(ip){
   await rate('create-minute',ip,60000,5);await rate('create-hour',ip,3600000,30);
   for(let attempt=0;attempt<4;attempt++){
    const value=randomBytes(16).toString('hex').toUpperCase();
    const key='IHAX-'+value.match(/.{8}/g).join('-'),createdAt=now(),expiresAt=createdAt+LIFETIME;
    const record={v:1,product:'ihax',enabled:true,createdAt,expiresAt};
    const result=await database.ref('ihaxLicensesV1/'+keyId(key)).transaction(old=>old===null?record:undefined);
    if(result.committed)return {key,createdAt,expiresAt};
   }throw new IhaxError('try_again',503);
  },
  async verify(value,ip){
   const key=normalize(value);if(!KEY_RE.test(key))return false;
   // A shared VPS may verify many devices; this bucket allows 20 requests/sec.
   await rate('verify-minute',ip,60000,1200);
   const r=(await database.ref('ihaxLicensesV1/'+keyId(key)).get()).val(),clock=now();
   return !!r&&r.v===1&&r.product==='ihax'&&r.enabled===true&&Number.isSafeInteger(r.createdAt)&&r.createdAt>0&&r.createdAt<=clock&&
    Number.isSafeInteger(r.expiresAt)&&r.expiresAt-r.createdAt===LIFETIME&&r.expiresAt>clock;
  }
 };
}
module.exports={createIhaxService,IhaxError,KEY_RE,LIFETIME,keyId,normalize};
