'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {readCredentials,deploymentConfig}=require('./credentials-v9.cjs');
test('operator credential validation pins project, Google token endpoint and signing identity',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mizze-credentials-test-'));
 const pair=crypto.generateKeyPairSync('rsa',{modulusLength:3072}),pem=pair.privateKey.export({type:'pkcs8',format:'pem'});
 const kid=crypto.createHash('sha256').update(pair.publicKey.export({type:'spki',format:'der'})).digest('hex');
 const accountFile=path.join(dir,'synthetic.json'),signingFile=path.join(dir,'ephemeral.pem');
 const account={type:'service_account',project_id:'vghgfhf-7000b',client_email:'synthetic-test@vghgfhf-7000b.iam.gserviceaccount.com',token_uri:'https://oauth2.googleapis.com/token',private_key:pem};
 try{
  fs.writeFileSync(signingFile,pem);fs.writeFileSync(accountFile,JSON.stringify(account));
  assert.equal(readCredentials(accountFile,signingFile,{kid}).account.project_id,'vghgfhf-7000b');
  assert.throws(()=>readCredentials(accountFile,signingFile,{kid:'0'.repeat(64)}),/signing_identity/);
  for(const changed of [{project_id:'wrong-project'},{type:'authorized_user'},{token_uri:'https://attacker.invalid/token'},{client_email:'other@attacker.invalid'}]){
   fs.writeFileSync(accountFile,JSON.stringify({...account,...changed}));assert.throws(()=>readCredentials(accountFile,signingFile,{kid}),/credential_project_or_type/);
  }
 }finally{
  const resolved=path.resolve(dir);assert.equal(path.dirname(resolved),path.resolve(os.tmpdir()));assert.ok(path.basename(resolved).startsWith('mizze-credentials-test-'));
  fs.rmSync(resolved,{recursive:true,force:true});
 }
});
test('explicit staging configuration cannot silently use production database or signer',()=>{
 assert.equal(deploymentConfig({}).projectId,'vghgfhf-7000b');
 assert.throws(()=>deploymentConfig({FIREBASE_PROJECT_ID:'mizze-staging'}),/explicit_firebase/);
 assert.throws(()=>deploymentConfig({FIREBASE_PROJECT_ID:'mizze-staging',FIREBASE_DATABASE_URL:'https://vghgfhf-7000b-default-rtdb.firebaseio.com'}),/staging_production/);
 assert.throws(()=>deploymentConfig({FIREBASE_PROJECT_ID:'mizze-staging',FIREBASE_DATABASE_URL:'https://mizze-staging-default-rtdb.firebaseio.com'}),/staging_public_identity/);
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mizze-staging-config-test-')),identityFile=path.join(dir,'public.json');
 try{
  fs.writeFileSync(identityFile,JSON.stringify({kid:'a'.repeat(64)}));const config=deploymentConfig({FIREBASE_PROJECT_ID:'mizze-staging',FIREBASE_DATABASE_URL:'https://mizze-staging-default-rtdb.firebaseio.com',MIZZE_LICENSE_PUBLIC_KEY_FILE:identityFile});
  assert.equal(config.projectId,'mizze-staging');assert.equal(config.identity.kid,'a'.repeat(64));
  fs.writeFileSync(identityFile,JSON.stringify(require('./license-public-key.json')));assert.throws(()=>deploymentConfig({FIREBASE_PROJECT_ID:'mizze-staging',FIREBASE_DATABASE_URL:'https://mizze-staging-default-rtdb.firebaseio.com',MIZZE_LICENSE_PUBLIC_KEY_FILE:identityFile}),/separate_staging/);
 }finally{
  const resolved=path.resolve(dir);assert.equal(path.dirname(resolved),path.resolve(os.tmpdir()));assert.ok(path.basename(resolved).startsWith('mizze-staging-config-test-'));fs.rmSync(resolved,{recursive:true,force:true});
 }
});
