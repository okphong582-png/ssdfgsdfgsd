'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {ensureKey}=require('./key-source.cjs'),{createDatabase}=require('./test-db.cjs'),access=require('./key-access.cjs'),lease=require('./lease-v9.cjs'),{createService}=require('./service-v9.cjs');
const now=1793030000000,id='a'.repeat(64),device='b'.repeat(64);
const pending=()=>({protocol:9,credentialMode:2,enabled:true,createdAt:now-10000,maxDevices:1,timeMode:'firstUse',durationMs:86400000,activatedAt:0,expiresAt:0});
test('historical and newly-created keys resolve live from the original database without restarting time',async()=>{
 const primary=createDatabase(),source=createDatabase();assert.equal(await ensureKey(primary,async()=>source,id,now),null);
 const r=pending();await source.ref('licensesV9/'+id).set(r);assert.deepEqual(await ensureKey(primary,async()=>source,id,now),r);
 assert.deepEqual(source.read('licensesV9/'+id),r);assert.equal(primary.read('licensesV9/'+id).activatedAt,0);
});
test('existing primary bindings and expiry win; an original-source outage cannot replace them',async()=>{
 const record=access.activateForKey(pending(),device,now),primary=createDatabase({licensesV9:{[id]:record}});
 assert.deepEqual(await ensureKey(primary,()=>{throw Error('source unavailable');},id,now),record);
});
test('unknown, expired, disabled and locked source records never create a usable target',async()=>{
 for(const r of [null,{...pending(),enabled:false},{...pending(),lock:{until:0,message:'locked'}},{protocol:9,credentialMode:2,enabled:true,maxDevices:1,expiresAt:now-1}]){
  const primary=createDatabase(),source=createDatabase({licensesV9:{[id]:r}});assert.equal(await ensureKey(primary,async()=>source,id,now),null);assert.equal(primary.read('licensesV9/'+id),null);
 }
});
test('two imports racing with first activation preserve the committed activation deadline',async()=>{
 const primary=createDatabase(),source=createDatabase({licensesV9:{[id]:pending()}});
 await Promise.all([ensureKey(primary,async()=>source,id,now),ensureKey(primary,async()=>source,id,now)]);
 await primary.ref('licensesV9/'+id).transaction(r=>access.activateForKey(r,device,now));
 const active=primary.read('licensesV9/'+id);await ensureKey(primary,async()=>source,id,now+1000);assert.deepEqual(primary.read('licensesV9/'+id),active);
});
test('original key → web approval → signed game lease → reset denies old device and preserves expiry',async()=>{
 const primary=createDatabase(),source=createDatabase({licensesV9:{[id]:pending()}});
 await ensureKey(primary,async()=>source,id,now);await primary.ref('licensesV9/'+id).transaction(r=>access.activateForKey(r,device,now));
 const pair=crypto.generateKeyPairSync('rsa',{modulusLength:3072}),service=createService({database:primary,signingKey:()=>pair.privateKey.export({type:'pkcs8',format:'pem'}),now:()=>now});
 const request={keyHash:id,deviceHash:device,nonce:'c'.repeat(32),claim:false,sessionSeconds:600};const granted=await service(request,'test');assert.equal(granted.status,200);assert.ok(lease.verifyForTest(granted.envelope,request,pair.publicKey));
 const expiry=primary.read('licensesV9/'+id).expiresAt,next='d'.repeat(64);await primary.ref('licensesV9/'+id).transaction(r=>access.resetForKey(r,next,crypto.randomUUID(),now));
 assert.equal((await service(request,'test')).status,403);assert.equal((await service({...request,deviceHash:next},'test')).status,200);assert.equal(primary.read('licensesV9/'+id).expiresAt,expiry);assert.deepEqual(source.read('licensesV9/'+id),pending());
});
