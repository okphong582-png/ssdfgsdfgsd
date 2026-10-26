'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const policy=require('./portal-policy.cjs'),{buildRecord}=require('./provision.cjs'),{createDatabase}=require('./test-db.cjs'),lease=require('./lease-v9.cjs');
const now=Date.parse('2026-10-26T12:00:00+07:00'),device='a'.repeat(64),next='b'.repeat(64),ownerUid='synthetic-owner';
const mutation=(r,action,id=device,clock=now)=>policy.change(r,{ownerUid,action,deviceId:id,operationId:crypto.randomUUID()},clock);
function fresh(){return buildRecord({ownerUid,key:'MZ-SYNTHETIC-DAILY',password:'synthetic-password-12345',label:'Daily test',maxDevices:2,durationMs:30*policy.DAY},now).record;}
test('concurrent resets of different devices share one daily quota for the key',async()=>{
 let record=mutation(fresh(),'activate');record=mutation(record,'activate',next);record=mutation(record,'reset');record=mutation(record,'activate');
 const database=createDatabase({licensesV9:{test:record}}),reset=id=>database.ref('licensesV9/test').transaction(r=>{try{return mutation(r,'reset',id);}catch(e){assert.equal(e.code,'reset_limited');return;}});
 const results=await Promise.all([reset(device),reset(next)]);assert.equal(results.filter(r=>r.committed).length,1);
 const result=database.read('licensesV9/test');assert.equal(policy.resetInfo(result,now).used,2);assert.equal(result.expiresAt,record.expiresAt);
});
test('reset immediately denies old menu leases; only new approved ID can resume',()=>{
 const active=mutation(fresh(),'activate'),reset=mutation(active,'reset'),rebound=mutation(reset,'activate',next);
 const req={keyHash:'c'.repeat(64),deviceHash:device,nonce:'d'.repeat(32),claim:true};
 assert.equal(lease.bind(reset,req,now),undefined);assert.equal(lease.bind(rebound,req,now),undefined);
 assert.ok(lease.bind(rebound,{...req,deviceHash:next},now));assert.equal(rebound.expiresAt,active.expiresAt);
});
test('daily counts include exact midnight, exclude previous day, and use Vietnam timezone',()=>{
 const before=Date.parse('2026-10-26T23:59:59.999+07:00'),midnight=before+1;
 const r=fresh();r.portal.resetHistory=[before];r.portal.lastResetAt=before;
 assert.equal(policy.resetInfo(r,before).used,1);assert.equal(policy.resetInfo(r,midnight).used,0);
 r.portal.resetHistory=[midnight,midnight+1];r.portal.lastResetAt=midnight+1;
 assert.equal(policy.resetInfo(r,midnight+1).remaining,0);assert.equal(policy.resetInfo(r,midnight+1).nextAllowedAt,midnight+policy.DAY);
});
