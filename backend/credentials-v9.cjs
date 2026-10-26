'use strict';
const fs=require('node:fs'),crypto=require('node:crypto');
const PROJECT='vghgfhf-7000b';
function deploymentConfig(env=process.env){
 const configured=env.FIREBASE_PROJECT_ID!==undefined||env.FIREBASE_DATABASE_URL!==undefined;
 if(configured&&(!env.FIREBASE_PROJECT_ID||!env.FIREBASE_DATABASE_URL))throw Error('explicit_firebase_configuration_required');
 const projectId=configured?env.FIREBASE_PROJECT_ID:PROJECT;
 if(!/^[a-z][a-z0-9-]{4,29}$/.test(projectId))throw Error('invalid_firebase_project');
 const databaseURL=configured?env.FIREBASE_DATABASE_URL:'https://vghgfhf-7000b-default-rtdb.firebaseio.com';
 const url=new URL(databaseURL);if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.pathname!=='/'||
 !/\.(?:firebaseio\.com|firebasedatabase\.app)$/.test(url.hostname))throw Error('invalid_database_url');
 if(projectId!==PROJECT&&url.hostname.includes(PROJECT))throw Error('staging_production_database_forbidden');
 if(projectId!==PROJECT&&!env.MIZZE_LICENSE_PUBLIC_KEY_FILE)throw Error('staging_public_identity_required');
 const identity=env.MIZZE_LICENSE_PUBLIC_KEY_FILE?JSON.parse(fs.readFileSync(env.MIZZE_LICENSE_PUBLIC_KEY_FILE,'utf8').replace(/^\uFEFF/,'')):require('./license-public-key.json');
 if(!identity||!/^[a-f0-9]{64}$/.test(identity.kid||''))throw Error('invalid_public_identity');
 if(projectId!==PROJECT&&identity.kid===require('./license-public-key.json').kid)throw Error('separate_staging_signer_required');
 return {projectId,databaseURL:url.origin,identity};
}
function validateCredentialValues(account,signingKey,identity=require('./license-public-key.json'),projectId=PROJECT){
 if(typeof projectId!=='string'||!/^[a-z][a-z0-9-]{4,29}$/.test(projectId)||!account||typeof account!=='object'||Array.isArray(account)||
   account.type!=='service_account'||account.project_id!==projectId||
   !new RegExp('^[a-z0-9.-]+@'+projectId.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\.iam\\.gserviceaccount\\.com$').test(account.client_email||'')||
   account.token_uri!=='https://oauth2.googleapis.com/token')throw Error('credential_project_or_type');
 const accountKey=crypto.createPrivateKey(account.private_key);
 if(accountKey.asymmetricKeyType!=='rsa'||accountKey.asymmetricKeyDetails.modulusLength<2048)throw Error('credential_key');
 const parsed=crypto.createPrivateKey(signingKey);
 const kid=crypto.createHash('sha256').update(crypto.createPublicKey(parsed).export({type:'spki',format:'der'})).digest('hex');
 if(parsed.asymmetricKeyType!=='rsa'||parsed.asymmetricKeyDetails.modulusLength!==3072||!identity||kid!==identity.kid)throw Error('signing_identity');
 return {account,signingKey};
}
function readCredentials(accountFile,signingFile,identity=require('./license-public-key.json'),projectId=PROJECT){
 const account=JSON.parse(fs.readFileSync(accountFile,'utf8').replace(/^\uFEFF/,'')),signingKey=fs.readFileSync(signingFile,'utf8');
 return validateCredentialValues(account,signingKey,identity,projectId);
}
module.exports={readCredentials,validateCredentialValues,deploymentConfig,PROJECT};
