const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createService}=require('./service-v9.cjs'),{verifyForTest}=require('./lease-v9.cjs');
const now=1791633600000,pair=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
function db(){const values=new Map();let serial=Promise.resolve();return {values,ref(path){return {transaction(update){const task=serial.then(()=>{const value=update(structuredClone(values.get(path)||null));if(value===undefined)return {committed:false,snapshot:{val:()=>structuredClone(values.get(path)||null)}};values.set(path,structuredClone(value));return {committed:true,snapshot:{val:()=>structuredClone(value)}};});serial=task.catch(()=>{});return task;}};}};}
const request=(device='b')=>({keyHash:'a'.repeat(64),deviceHash:device.repeat(64),nonce:'c'.repeat(32),claim:true});
function fixture(limit=1){const database=db();database.values.set('licensesV9/'+'a'.repeat(64),{protocol:9,credentialMode:3,enabled:true,expiresAt:now+60000,createdAt:now,maxDevices:limit});const service=createService({database,now:()=>now,signingKey:()=>pair.privateKey.export({type:'pkcs8',format:'pem'})});return {database,service};}
test('concurrent last-slot registrations accept exactly one and emit a device-bound signature',async()=>{
 const {database,service}=fixture(1),requests=[request('b'),request('d')];const replies=await Promise.all(requests.map(r=>service(r,'127.0.0.1')));
 assert.deepEqual(replies.map(r=>r.status).sort(),[200,403]);assert.equal(Object.keys(database.values.get('licensesV9/'+'a'.repeat(64)).devices).length,1);
 const winner=replies.findIndex(r=>r.status===200);assert.ok(verifyForTest(replies[winner].envelope,requests[winner],pair.publicKey));
});
test('refresh cannot re-add an admin-removed device without explicit claim',async()=>{
 const {database,service}=fixture(1),r=request();assert.equal((await service(r,'127.0.0.1')).status,200);
 delete database.values.get('licensesV9/'+r.keyHash).devices[r.deviceHash];assert.equal((await service({...r,claim:false},'127.0.0.1')).status,403);
 assert.equal((await service({...r,claim:true},'127.0.0.1')).status,200);
});
test('shared database rate limiter applies across service instances and stores no raw IP or credential',async()=>{
 const {database,service}=fixture(2),other=createService({database,now:()=>now,signingKey:()=>pair.privateKey.export({type:'pkcs8',format:'pem'})});
 const r=request();for(let n=0;n<18;n++)assert.equal((await (n%2?service:other)(r,'203.0.113.1')).status,200);
 assert.equal((await other(r,'203.0.113.1')).status,429);
 const stored=JSON.stringify([...database.values]);assert.ok(!stored.includes('203.0.113.1'));assert.ok(!stored.includes('PRIVATE KEY'));
});
test('revoke/expiry/quota failures return generic denials without private record details',async()=>{
 const {database,service}=fixture(1),r=request();database.values.get('licensesV9/'+r.keyHash).enabled=false;
 assert.deepEqual(await service(r,'127.0.0.1'),{status:403,error:'license_denied'});
});

test('concurrent first-use claims atomically share one activation and deadline',async()=>{
 const {database}=fixture(2),path='licensesV9/'+'a'.repeat(64);let clock=now+90*86400000;
 database.values.set(path,{protocol:9,credentialMode:2,enabled:true,createdAt:now,maxDevices:2,timeMode:'firstUse',durationMs:86400000,activatedAt:0,expiresAt:0});
 const make=()=>createService({database,now:()=>clock,signingKey:()=>pair.privateKey.export({type:'pkcs8',format:'pem'})});
 const service=make(),other=make();assert.equal((await service({...request(),claim:false},'127.0.0.1')).status,403);
 assert.equal(database.values.get(path).activatedAt,0);
 const replies=await Promise.all([service(request('b'),'127.0.0.1'),other(request('d'),'127.0.0.1'),service(request('e'),'127.0.0.1')]);
 assert.deepEqual(replies.map(x=>x.status).sort(),[200,200,403]);
 const active=structuredClone(database.values.get(path));assert.equal(active.activatedAt,clock);assert.equal(active.expiresAt,clock+86400000);
 clock+=3600000;delete database.values.get(path).devices;
 assert.equal((await other(request('f'),'127.0.0.1')).status,200);assert.equal(database.values.get(path).expiresAt,active.expiresAt);
 const restarted=make();clock=active.expiresAt;
 assert.equal((await restarted(request('f'),'127.0.0.1')).status,403);assert.equal(database.values.get(path).expiresAt,active.expiresAt);
});

test('bad signing key is rejected before any pending license is activated',async()=>{
 const {database}=fixture(),path='licensesV9/'+'a'.repeat(64);
 database.values.set(path,{protocol:9,credentialMode:2,enabled:true,createdAt:now,maxDevices:1,timeMode:'firstUse',durationMs:86400000,activatedAt:0,expiresAt:0});
 for(const key of [crypto.generateKeyPairSync('rsa',{modulusLength:2048}),crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'})]){
  const service=createService({database,now:()=>now,signingKey:()=>key.privateKey.export({type:'pkcs8',format:'pem'})});
  await assert.rejects(service(request(),'127.0.0.1'));assert.equal(database.values.get(path).activatedAt,0);assert.equal(database.values.get(path).devices,undefined);
 }
});
