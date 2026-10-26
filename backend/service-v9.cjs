'use strict';
const crypto=require('node:crypto');
const policy=require('./lease-v9.cjs');
function createService({database,signingKey,now=Date.now}){
  let parsedKey=null;
  async function rate(path,limit,clock){
    const window=Math.floor(clock/60000);
    const result=await database.ref('_mizzeRateV9/'+path).transaction(value=>{
      if(!value||value.window!==window)return {window,count:1,updatedAt:clock};
      if(!Number.isInteger(value.count)||value.count>=limit)return;
      return {window,count:value.count+1,updatedAt:clock};
    });return result.committed;
  }
  return async function service(body,ip){
    const request=policy.validateRequest(body),clock=now();
    const secret=signingKey();
    if(!parsedKey){
      const candidate=crypto.createPrivateKey(secret);
      if(candidate.asymmetricKeyType!=='rsa'||candidate.asymmetricKeyDetails.modulusLength<3072)throw Error('invalid_signing_key');
      parsedKey=candidate;
    }
    const bucket=value=>crypto.createHmac('sha256',secret).update(value).digest('hex');
    if(!await rate('ip-'+bucket('ip:'+String(ip||'unknown')),600,clock))return {status:429,error:'rate_limited'};
    if(!await rate('device-'+bucket('device:'+request.keyHash+':'+request.deviceHash),18,clock))return {status:429,error:'rate_limited'};
    // Admin SDK can invoke the first updater with a cold local-cache null even
    // when the server record exists. Returning null forces the conditional
    // transaction to fetch/retry the actual server value. Undefined would abort
    // locally and incorrectly deny every first connection. A truly missing
    // record stays null and issueLease below still denies it.
    const result=await database.ref('licensesV9/'+request.keyHash).transaction(record=>record===null?null:policy.bind(record,request,now()));
    if(!result.committed)return {status:403,error:'license_denied'};
    try{return {status:200,envelope:policy.issueLease(request,result.snapshot.val(),now(),parsedKey)};}
    catch{return {status:403,error:'license_denied'};}
  };
}
module.exports={createService};
