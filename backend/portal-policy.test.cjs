'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const p=require('./portal-policy.cjs'),lease=require('./lease-v9.cjs'),{buildRecord,parseArgs,provision}=require('./provision.cjs'),{createDatabase}=require('./test-db.cjs');
const now=1791633600000,uid='owner-one',device='b'.repeat(64),other='c'.repeat(64);
const options=()=>({ownerUid:uid,key:'MZ10-SYNTHETICKEY',password:'synthetic-password-long',durationMs:90*p.DAY,maxDevices:1,label:'Synthetic'});
const fresh=()=>buildRecord(options(),now).record;
const change=(record,action='activate',id=device,clock=now,operationId=crypto.randomUUID(),ownerUid=uid)=>p.change(record,{ownerUid,action,deviceId:id,operationId},clock);
test('managed record requires website approval; legacy claim never self-enrolls',()=>{
 const record=fresh(),request={keyHash:'a'.repeat(64),deviceHash:device,nonce:'d'.repeat(32),claim:true,sessionSeconds:600};
 assert.ok(lease.validRecord(record,now));assert.equal(lease.bind(record,request,now),undefined);
 const active=change(record);assert.ok(lease.bind(active,request,now));assert.equal(lease.bind(active,{...request,deviceHash:other},now),undefined);
 const signed=lease.issueLease(request,active,now,crypto.generateKeyPairSync('rsa',{modulusLength:3072}).privateKey),payload=JSON.parse(Buffer.from(signed.payload,'base64'));
 assert.equal(payload.expiresAt-now,30000);assert.equal(payload.bindingVersion,1);assert.equal(payload.aud,lease.AUDIENCE);
});
test('website activation binds exact ID atomically and starts purchased duration once',()=>{
 const active=change(fresh());assert.equal(active.activatedAt,now);assert.equal(active.expiresAt,now+90*p.DAY);assert.equal(active.devices[device].portalLoggedOut,false);
 assert.throws(()=>change(active,'activate',other),/device_limit/);
 assert.throws(()=>change(active,'activate',device,now,crypto.randomUUID(),'another-owner'),/key_not_found/);
 const publicDto=p.dto('a'.repeat(64),active,now);assert.equal(publicDto.status,'active');assert.equal(publicDto.label,'Synthetic');assert.ok(!JSON.stringify(publicDto).includes('ownerUid'));assert.ok(!JSON.stringify(publicDto).includes('password'));
});
test('key logout denies both claim and refresh until explicit website reactivation',()=>{
 const active=change(fresh()),request={keyHash:'a'.repeat(64),deviceHash:device,nonce:'d'.repeat(32),claim:true};
 const loggedOut=change(active,'logout');assert.equal(p.dto('a'.repeat(64),loggedOut,now).status,'logged_out');assert.equal(lease.bind(loggedOut,request,now),undefined);
 assert.equal(lease.bind(loggedOut,{...request,claim:false},now),undefined);
 const resumed=change(loggedOut);assert.ok(lease.bind(resumed,request,now));assert.equal(resumed.expiresAt,active.expiresAt);
});
test('two resets per Vietnam calendar day, midnight rollover, idempotency and unchanged expiry',()=>{
 const start=Date.parse('2026-10-26T23:59:55+07:00');
 const initial=buildRecord(options(),start).record;
 const active=change(initial,'activate',device,start),operationId=crypto.randomUUID();
 const first=change(active,'reset',device,start,operationId);
 assert.equal(first.devices,null);assert.equal(first.expiresAt,active.expiresAt);
 assert.deepEqual(change(first,'reset',device,start+1,operationId),first);
 assert.throws(()=>change(first,'logout',device,start+1,operationId),/idempotency_conflict/);
 const rebound=change(first,'activate',device,start+1);
 const second=change(rebound,'reset',device,start+2);assert.equal(p.resetInfo(second,start+2).remaining,0);
 const thirdDevice=change(second,'activate',other,start+3);
 assert.throws(()=>change(thirdDevice,'reset',other,start+4),/reset_limited/);
 const midnight=Date.parse('2026-10-27T00:00:00+07:00');
 assert.equal(p.resetInfo(thirdDevice,midnight).remaining,2);
 const third=change(thirdDevice,'reset',other,midnight);
 assert.deepEqual(third.portal.resetHistory,[midnight]);assert.equal(third.expiresAt,active.expiresAt);
 assert.equal(p.resetInfo(third,midnight).used,1);
});
test('unknown or malformed managed metadata never falls back to legacy enrollment',()=>{
 const record=fresh(),req={keyHash:'a'.repeat(64),deviceHash:device,nonce:'d'.repeat(32),claim:true};
 for(const portal of [null,{}, {...record.portal,v:2},{...record.portal,unknown:true},{...record.portal,ownerUid:''},{...record.portal,bindingVersion:0},{...record.portal,resetHistory:0},{...record.portal,operations:false}])assert.equal(lease.bind({...record,portal},req,now),undefined);
 for(const input of [{key:'short'},{key:'MZ10-SYNTHETICKEY',deviceId:device,operationId:'short'},{key:'MZ10-SYNTHETICKEY',deviceId:'not-device',operationId:crypto.randomUUID()},{key:'MZ10-SYNTHETICKEY',deviceId:device,operationId:crypto.randomUUID(),uid:'other'}])assert.throws(()=>p.validateInput('activate',input),/invalid_request/);
});
test('bounded idempotency ledger and immutable ownership resist repeated requests',()=>{
 let active=change(fresh());for(let n=0;n<80;n++)active=change(active,'activate',device,now+n);
 assert.equal(Object.keys(active.portal.operations).length,32);
 const disabled={...active,enabled:false};assert.throws(()=>change(disabled,'activate',device,now+100),/license_unavailable/);assert.equal(p.dto('a'.repeat(64),disabled,now+100).status,'disabled');
});
test('atomic provisioning reserves alias and owner, never overwrites existing license',async()=>{
 const db=createDatabase(),secret=crypto.randomBytes(32),opts=options();
 const attempts=await Promise.allSettled([provision(db,opts,secret,now),provision(db,opts,secret,now)]);assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);
 const id=buildRecord(opts,now).hash;assert.equal(db.read('licensesV9/'+id).portal.ownerUid,uid);assert.equal(db.read('portalKeyAliases/'+p.keyAlias(opts.key,secret)).licenseId,id);
 assert.equal(Object.keys(db.read('licensesV9')).length,1);
 assert.ok(!JSON.stringify(db.read('')).includes(opts.password));
 assert.throws(()=>parseArgs(['--uid',uid,'--days','0']),/invalid_arguments/);
});

test('an account with a key cannot receive a different second key',async()=>{
 const db=createDatabase(),secret=crypto.randomBytes(32),first=options(),second={...options(),key:'MZ10-SECONDKEY000'};
 await provision(db,first,secret,now);const before=db.read('');
 await assert.rejects(provision(db,second,secret,now+1),/provision_conflict_or_account_limit/);
 assert.deepEqual(db.read(''),before);
 assert.equal(db.read('portalKeyAliases/'+p.keyAlias(second.key,secret)),null);
});

test('different-key provisioning races reserve exactly one account slot',async()=>{
 const db=createDatabase(),secret=crypto.randomBytes(32),attempts=[options(),{...options(),key:'MZ10-RACINGKEY000'}];
 const replies=await Promise.allSettled(attempts.map(opts=>provision(db,opts,secret,now)));
 assert.equal(replies.filter(reply=>reply.status==='fulfilled').length,1);
 assert.equal(replies.filter(reply=>reply.status==='rejected').length,1);
 const root=db.read(''),licenses=Object.entries(root.licensesV9),aliases=Object.values(root.portalKeyAliases);
 assert.equal(licenses.length,1);assert.equal(aliases.length,1);
 assert.equal(licenses[0][1].portal.ownerUid,uid);assert.equal(aliases[0].licenseId,licenses[0][0]);
});

test('separate accounts each receive their own key without changing the other',async()=>{
 const db=createDatabase(),secret=crypto.randomBytes(32),first=options(),second={...options(),ownerUid:'owner-two',key:'MZ10-SEPARATEKEY0'};
 const replies=await Promise.all([provision(db,first,secret,now),provision(db,second,secret,now)]);
 assert.notEqual(replies[0].hash,replies[1].hash);
 assert.equal(db.read('licensesV9/'+replies[0].hash).portal.ownerUid,uid);
 assert.equal(db.read('licensesV9/'+replies[1].hash).portal.ownerUid,'owner-two');
 assert.equal(Object.keys(db.read('licensesV9')).length,2);
});
