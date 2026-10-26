const {test}=require('node:test'),a=require('node:assert/strict'),crypto=require('node:crypto');
const {createService,validateRequest}=require('./service-v10.cjs'),identity=require('./game-license-v10.public.json');
const {createDatabase}=require('./test-db.cjs'),{buildRecord}=require('./provision.cjs'),access=require('./key-access.cjs');
const now=Date.now(),keyHash='a'.repeat(64),device='b'.repeat(64);
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
const pem=privateKey.export({format:'pem',type:'pkcs8'}),kid=crypto.createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex');
function body(){return {v:10,release:identity.release,brandDigest:identity.brandDigest,keyHash,deviceHash:device,nonce:crypto.randomBytes(16).toString('hex'),claim:false};}
function fixture(){
 const pending=buildRecord({ownerUid:'owner',key:'TEST-KEY',password:'TEST-PASSWORD',durationMs:86400000,maxDevices:1,label:'Test'},now).record;
 const record=access.activateForKey(pending,device,now),db=createDatabase({licensesV9:{[keyHash]:record}});
 return {db,record,service:createService({database:db,signingKey:()=>pem,now:()=>now,expectedSigningKid:kid})};
}
test('v10 binds exact release, branding, key, device and nonce to an independently verified 30-second signature',async()=>{
 const f=fixture(),request=body(),result=await f.service(request,'127.0.0.1');a.equal(result.status,200);
 const raw=Buffer.from(result.envelope.payload,'base64'),payload=JSON.parse(raw);
 a.ok(crypto.verify('RSA-SHA256',raw,publicKey,Buffer.from(result.envelope.signature,'base64')));
 a.equal(result.envelope.kid,kid);a.equal(payload.v,10);a.equal(payload.aud,identity.audience);a.equal(payload.release,request.release);
 a.equal(payload.brandDigest,request.brandDigest);a.equal(payload.nonce,request.nonce);a.equal(payload.deviceHash,device);
 a.equal(payload.bindingVersion,f.record.portal.bindingVersion);a.equal(payload.expiresAt-now,30000);
 a.equal((await f.service(request,'127.0.0.1')).status,403);
 a.equal((await f.service(body(),'127.0.0.1')).status,200);
});
test('old protocol, altered brand/release, self-claim and lifetime negotiation are rejected',()=>{
 for(const wrong of [{v:9},{release:'other'},{brandDigest:'c'.repeat(64)},{claim:true},{sessionSeconds:600}])a.throws(()=>validateRequest({...body(),...wrong}),/invalid_request/);
});
test('new server requires web approval and rejects missing, removed, logged-out, disabled and expired devices',async()=>{
 for(const mode of ['legacy','missing','removed','logged-out','disabled','expired']){
  const f=fixture(),r=structuredClone(f.record);
  if(mode==='legacy'){delete r.portal;delete r.devices[device].portalLoggedOut;delete r.devices[device].portalApprovedAt;delete r.devices[device].portalBindingVersion;}
  if(mode==='removed')delete r.devices;
  if(mode==='logged-out')r.devices[device].portalLoggedOut=true;
  if(mode==='disabled')r.enabled=false;
  if(mode==='expired'){r.durationMs=1000;r.activatedAt=now-2000;r.expiresAt=now-1000;}
  await f.db.ref('licensesV9/'+keyHash).set(mode==='missing'?null:r);
  a.equal((await f.service(body(),'127.0.0.1')).status,403,mode);
 }
});
test('a retired signing identity cannot start issuing proofs or activate pending keys',async()=>{
 const f=fixture(),service=createService({database:f.db,signingKey:()=>pem,now:()=>now,expectedSigningKid:'0'.repeat(64)});
 await a.rejects(service(body(),'127.0.0.1'),/invalid_signing_key/);
});
