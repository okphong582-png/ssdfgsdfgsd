const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const p=require('./lease-v9.cjs');
const now=1791633600000,request={keyHash:'a'.repeat(64),deviceHash:'b'.repeat(64),nonce:'c'.repeat(32),claim:true};
const fresh=(maxDevices=2)=>({protocol:9,credentialMode:3,enabled:true,expiresAt:now+60000,createdAt:now-1,maxDevices});
const pair=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
const pending=(maxDevices=2)=>({protocol:9,credentialMode:2,enabled:true,createdAt:now-86400000,maxDevices,timeMode:'firstUse',durationMs:86400000,activatedAt:0,expiresAt:0});

test('first-use license waits indefinitely until a valid claim, then starts exactly once',()=>{
 const idle=pending(),later=now+60*86400000;
 assert.ok(p.validRecord(idle,later));assert.equal(p.bind(idle,{...request,claim:false},later),undefined);
 assert.equal(idle.activatedAt,0);assert.throws(()=>p.issueLease(request,idle,later,pair.privateKey));
 const active=p.bind(idle,request,later);assert.equal(active.activatedAt,later);assert.equal(active.expiresAt,later+idle.durationMs);
 assert.equal(p.bind(active,{...request,claim:false},later+1000).expiresAt,active.expiresAt);
 const second=p.bind(active,{...request,deviceHash:'d'.repeat(64)},later+2000);assert.equal(second.activatedAt,later);assert.equal(second.expiresAt,active.expiresAt);
 const reset=p.bind({...active,devices:null},request,later+3000);assert.equal(reset.expiresAt,active.expiresAt);
 assert.equal(p.bind(active,request,active.expiresAt),undefined);
 assert.equal(p.bind({...active,devices:null},request,active.expiresAt),undefined);
 assert.throws(()=>p.issueLease(request,active,active.expiresAt,pair.privateKey));
 const lease=p.issueLease({...request,sessionSeconds:600},active,active.expiresAt-1200,pair.privateKey);
 assert.equal(JSON.parse(Buffer.from(lease.payload,'base64')).expiresAt,active.expiresAt);
});

test('malformed/locked/disabled pending schedules cannot start or bypass time checks',()=>{
 for(const patch of [{durationMs:0},{durationMs:Infinity},{durationMs:1000.5},{durationMs:315360000001},{timeMode:'other'},{activatedAt:-1},{activatedAt:now+1,expiresAt:now+86400001},{expiresAt:now+1},{enabled:false},{lock:{until:0,message:'locked'}},{devices:{[request.deviceHash]:{version:1,claimedAt:now}}}]){
  const value={...pending(),...patch};assert.equal(p.bind(value,request,now),undefined);assert.equal(value.activatedAt,patch.activatedAt??0);
 }
 const active=p.bind(pending(),request,now);
 assert.equal(p.bind({...active,expiresAt:active.expiresAt+1},request,now+1),undefined);
 assert.equal(p.bind({...active,durationMs:active.durationMs+1},request,now+1),undefined);
 assert.equal(p.bind({...pending(),timeMode:undefined},request,now),undefined);
 assert.equal(p.bind(pending(),request,Number.MAX_SAFE_INTEGER),undefined);
});
test('strict request shape and true boolean claim required',()=>{
 assert.deepEqual(p.validateRequest(request),request);
 for(const body of [null,[],{...request,keyHash:'bad'},{...request,deviceHash:'bad'},{...request,nonce:'x'},{...request,claim:'true'},{...request,extra:'no'}])assert.throws(()=>p.validateRequest(body));
});
test('license policy rejects disabled/expired/malformed caps and locks',()=>{
 for(const patch of [{protocol:8},{credentialMode:1},{enabled:false},{expiresAt:now},{expiresAt:NaN},{maxDevices:0},{maxDevices:51},{maxDevices:1.5},{lock:{until:0,message:'locked'}},{lock:{until:now+1,message:'locked'}},{lock:{until:0}},{devices:[]}])assert.equal(p.bind({...fresh(),...patch},request,now),undefined);
 assert.ok(p.bind({...fresh(),lock:{until:now-1,message:'over'}},request,now));
});
test('atomic decision allows existing devices, binds new devices only with claim and free capacity',()=>{
 const first=p.bind(fresh(1),request,now);assert.ok(first.devices[request.deviceHash]);assert.deepEqual(p.bind(first,{...request,claim:false},now),first);
 assert.equal(p.bind(fresh(1),{...request,claim:false},now),undefined);
 assert.equal(p.bind(first,{...request,deviceHash:'d'.repeat(64)},now),undefined);
 const two=p.bind(first,{...request,deviceHash:'d'.repeat(64)},now);assert.equal(two,undefined);
 const raised=p.bind({...first,maxDevices:2},{...request,deviceHash:'d'.repeat(64)},now);assert.equal(Object.keys(raised.devices).length,2);
 assert.equal(p.bind({...raised,maxDevices:1},request,now),undefined);
});
test('actual RSA signatures bind audience/key/device/nonce and last at most 30 seconds',()=>{
 const bound=p.bind(fresh(),request,now),envelope=p.issueLease(request,bound,now,pair.privateKey);
 assert.ok(p.verifyForTest(envelope,request,pair.publicKey));
 const body=JSON.parse(Buffer.from(envelope.payload,'base64'));assert.equal(body.aud,p.AUDIENCE);assert.equal(body.expiresAt-now,30000);
 assert.equal(body.licenseExpiresAt,bound.expiresAt);assert.equal(body.activatedAt,0);
 for(const field of ['keyHash','deviceHash','nonce'])assert.equal(p.verifyForTest(envelope,{...request,[field]:(field==='nonce'?'e'.repeat(32):'f'.repeat(64))},pair.publicKey),false);
 const changed={...envelope,payload:Buffer.from(JSON.stringify({...body,maxDevices:50})).toString('base64')};assert.equal(p.verifyForTest(changed,request,pair.publicKey),false);
 const forged={...envelope,signature:Buffer.alloc(384).toString('base64')};assert.equal(p.verifyForTest(forged,request,pair.publicKey),false);
 const short=p.issueLease(request,{...bound,expiresAt:now+1200},now,pair.privateKey);assert.equal(JSON.parse(Buffer.from(short.payload,'base64')).expiresAt,now+1200);
 assert.throws(()=>p.issueLease(request,fresh(),now,pair.privateKey));
});

test('two-input mode2 uses the same signed lease and quota policy while retaining mode3 compatibility',()=>{const record={...fresh(1),credentialMode:2},bound=p.bind(record,request,now);assert.ok(bound);assert.ok(p.verifyForTest(p.issueLease(request,bound,now,pair.privateKey),request,pair.publicKey));assert.equal(p.bind({...record,credentialMode:1},request,now),undefined);assert.ok(p.bind(fresh(1),request,now));});

test('negotiated ten-minute sessions are capped, signed and cannot outlive the license',()=>{
 const session={...request,sessionSeconds:600};assert.equal(p.validateRequest(session).sessionSeconds,600);
 for(const invalid of [0,30,601,Infinity,'600',null,true])assert.throws(()=>p.validateRequest({...request,sessionSeconds:invalid}));
 const long={...fresh(),expiresAt:now+3600000},bound=p.bind(long,session,now);
 const envelope=p.issueLease(session,bound,now,pair.privateKey),body=JSON.parse(Buffer.from(envelope.payload,'base64'));
 assert.equal(body.expiresAt-now,600000);assert.ok(p.verifyForTest(envelope,session,pair.publicKey));
 const short=p.issueLease(session,{...bound,expiresAt:now+1234},now,pair.privateKey);assert.equal(JSON.parse(Buffer.from(short.payload,'base64')).expiresAt,now+1234);
 const changed={...envelope,payload:Buffer.from(JSON.stringify({...body,expiresAt:body.expiresAt+1})).toString('base64')};assert.equal(p.verifyForTest(changed,session,pair.publicKey),false);
 assert.equal(JSON.parse(Buffer.from(p.issueLease(request,bound,now,pair.privateKey).payload,'base64')).expiresAt-now,30000);
});
