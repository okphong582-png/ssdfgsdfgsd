'use strict';
const {test}=require('node:test'),a=require('node:assert/strict');
const {createDatabase}=require('./test-db.cjs');
const {createIhaxService,keyId,LIFETIME,KEY_RE}=require('./ihax-service.cjs');
const clock=1793120400000,secret=Buffer.alloc(32,7);
test('free Ihax keys match the native format, live exactly seven days, and never touch Mizze keys',async()=>{
 const db=createDatabase({licensesV9:{paid:{enabled:true}}}),s=createIhaxService({database:db,rateSecret:secret,now:()=>clock});
 const result=await s.issue('test-ip');a.ok(KEY_RE.test(result.key));a.equal(result.expiresAt-result.createdAt,LIFETIME);a.equal(result.expiresAt,clock+7*86400000);
 a.equal(await s.verify(result.key,'test-ip'),true);a.equal(await s.verify(result.key.toLowerCase(),'test-ip'),true);
 a.deepEqual(db.read('licensesV9'),{paid:{enabled:true}});a.ok(!JSON.stringify(db.read()).includes(result.key));a.ok(!JSON.stringify(db.read()).includes('test-ip'));
});
test('expiry, disabled records, altered product and extended duration fail closed',async()=>{
 const db=createDatabase(),s=createIhaxService({database:db,rateSecret:secret,now:()=>clock});
 const result=await s.issue('ip'),path='ihaxLicensesV1/'+keyId(result.key),base=db.read(path);
 for(const patch of [{enabled:false},{product:'mizze'},{createdAt:clock+1},{expiresAt:result.expiresAt+1}]){await db.ref(path).set({...base,...patch});a.equal(await s.verify(result.key,'ip'),false);}
 await db.ref(path).set(base);const later=createIhaxService({database:db,rateSecret:secret,now:()=>result.expiresAt});a.equal(await later.verify(result.key,'ip'),false);
 a.equal(await s.verify('not-a-key','ip'),false);a.equal(await s.verify('IHAX-'+'00000000-'.repeat(3)+'00000000','ip'),false);
});
test('concurrent clicks are bounded by a shared IP bucket across server instances',async()=>{
 const db=createDatabase(),make=()=>createIhaxService({database:db,rateSecret:secret,now:()=>clock});
 const results=await Promise.allSettled(Array.from({length:9},()=>make().issue('shared-ip')));a.equal(results.filter(r=>r.status==='fulfilled').length,5);
 for(const r of results.filter(r=>r.status==='rejected'))a.equal(r.reason.status,429);
 const next=createIhaxService({database:db,rateSecret:secret,now:()=>clock+60000});a.ok((await next.issue('shared-ip')).key);
});
test('key collisions never overwrite an existing record',async()=>{
 const db=createDatabase(),s=createIhaxService({database:db,rateSecret:secret,now:()=>clock,randomBytes:()=>Buffer.alloc(16,1)});
 const first=await s.issue('ip'),path='ihaxLicensesV1/'+keyId(first.key),before=db.read(path);await a.rejects(s.issue('ip'),/try_again/);a.deepEqual(db.read(path),before);
});
