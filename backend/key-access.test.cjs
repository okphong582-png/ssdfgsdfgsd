'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const key=require('./key-access.cjs'),{buildRecord}=require('./provision.cjs'),lease=require('./lease-v9.cjs'),{createDatabase}=require('./test-db.cjs');
const now=Date.parse('2026-10-26T23:59:55+07:00'),device='a'.repeat(64),other='b'.repeat(64),third='c'.repeat(64),password='synthetic-password-12345';
function fresh(){return buildRecord({ownerUid:'account-owner',key:'MZ-SYNTHETIC',password,durationMs:30*86400000,maxDevices:1,label:'Synthetic'},now).record;}
test('key and password hash exactly matches game credential framing, casing and device ID',()=>{
 const pair=key.credentials(' mz-synthetic ',password,'A'.repeat(64));
 const hash=crypto.createHash('sha256').update('mizze-pair-v1\n12:MZ-SYNTHETIC\n'+password.length+':'+password).digest('hex');
 assert.equal(pair.licenseId,hash);assert.equal(pair.deviceId,device);
 assert.notEqual(key.credentials('MZ-SYNTHETIC',password.toUpperCase(),device).licenseId,hash);
 assert.throws(()=>key.credentials('MZ-SYNTHETIC',password,'browser-id'),/invalid_request/);
});
test('first activation approves exact device, starts duration once, and preserves existing managed owner',()=>{
 const active=key.activateForKey(fresh(),device,now);assert.equal(active.portal.ownerUid,'account-owner');
 assert.equal(active.activatedAt,now);assert.equal(active.expiresAt,now+30*86400000);
 assert.equal(key.activateForKey(active,device,now+1000).expiresAt,active.expiresAt);
 assert.equal(key.activateForKey(active,other,now+2000),active);assert.equal(key.dto(active,other,now+2000).status,'reset_required');
});
test('legacy license acquires approval metadata without resetting previous expiration',()=>{
 const legacy={protocol:9,credentialMode:2,enabled:true,maxDevices:1,expiresAt:now+86400000};
 const active=key.activateForKey(legacy,device,now);assert.ok(active.portal);assert.equal(active.expiresAt,legacy.expiresAt);
 assert.ok(lease.validRecord(active,now));assert.equal(active.devices[device].portalLoggedOut,false);
});
test('reset transfers all bindings, denies old ID, preserves expiry and rejects third daily reset',()=>{
 const active=key.activateForKey(fresh(),device,now),op=crypto.randomUUID();
 const first=key.resetForKey(active,other,op,now+1);assert.deepEqual(Object.keys(first.devices),[other]);assert.equal(first.expiresAt,active.expiresAt);
 assert.deepEqual(key.resetForKey(first,other,op,now+2),first);
 assert.throws(()=>key.resetForKey(first,third,op,now+2),/idempotency_conflict/);
 const second=key.resetForKey(first,third,crypto.randomUUID(),now+2);
 assert.throws(()=>key.resetForKey(second,device,crypto.randomUUID(),now+3),/reset_limited/);
 const request={keyHash:'d'.repeat(64),deviceHash:device,nonce:'e'.repeat(32),claim:true};
 assert.equal(lease.bind(second,request,now+3),undefined);assert.ok(lease.bind(second,{...request,deviceHash:third},now+3));
 const midnight=Date.parse('2026-10-27T00:00:00+07:00'),next=key.resetForKey(second,device,crypto.randomUUID(),midnight);
 assert.equal(key.dto(next,device,midnight).reset.used,1);assert.equal(next.expiresAt,active.expiresAt);
});
test('concurrent key transfers cannot exceed the key daily limit',async()=>{
 let active=key.activateForKey(fresh(),device,now);active=key.resetForKey(active,other,crypto.randomUUID(),now+1);
 const db=createDatabase({record:active}),transfer=id=>db.ref('record').transaction(r=>{try{return key.resetForKey(r,id,crypto.randomUUID(),now+2);}catch(e){assert.equal(e.code,'reset_limited');return;}});
 const results=await Promise.all([transfer(device),transfer(third)]);assert.equal(results.filter(r=>r.committed).length,1);assert.equal(db.read('record').portal.resetHistory.length,2);
});
test('disabled, expired and indefinitely locked records cannot activate or reset',()=>{
 for(const record of [{...fresh(),enabled:false},{...fresh(),lock:{until:0,message:'locked'}},{protocol:9,credentialMode:2,enabled:true,maxDevices:1,expiresAt:now-1}]){
  assert.throws(()=>key.activateForKey(record,device,now),/license_denied/);assert.throws(()=>key.resetForKey(record,device,crypto.randomUUID(),now),/license_denied/);
 }
});
