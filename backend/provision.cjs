'use strict';
const crypto=require('node:crypto');
const {normalizeKey,keyAlias}=require('./portal-policy.cjs');
const {decodeSecret}=require('./portal-service.cjs');
function parseArgs(args){
 const options={};for(let i=0;i<args.length;i+=2){const name=args[i];if(!['--uid','--days','--max-devices','--label','--key','--password'].includes(name)||args[i+1]===undefined||Object.hasOwn(options,name))throw Error('invalid_arguments');options[name]=args[i+1];}
 const ownerUid=options['--uid'],days=Number(options['--days']),maxDevices=Number(options['--max-devices']||1);
 if(typeof ownerUid!=='string'||!ownerUid.length||ownerUid.length>128||/[\u0000-\u0020]/.test(ownerUid)||!Number.isInteger(days)||days<1||days>3650||!Number.isInteger(maxDevices)||maxDevices<1||maxDevices>50)throw Error('invalid_arguments');
 const label=options['--label']||'Mizze';if(label.length>120)throw Error('invalid_arguments');
 const key=normalizeKey(options['--key']||'MZ10-'+crypto.randomBytes(16).toString('hex').toUpperCase()),password=options['--password']||crypto.randomBytes(24).toString('hex');
 if(!/^[!-~]{16,128}$/.test(password)||key===password)throw Error('invalid_password');
 return {ownerUid,durationMs:days*86400000,maxDevices,label,key,password};
}
function buildRecord(options,now){
 const hash=crypto.createHash('sha256').update('mizze-pair-v1\n'+options.key.length+':'+options.key+'\n'+options.password.length+':'+options.password).digest('hex');
 const record={protocol:9,credentialMode:2,enabled:true,createdAt:now,maxDevices:options.maxDevices,timeMode:'firstUse',durationMs:options.durationMs,activatedAt:0,expiresAt:0,
 portal:{v:1,ownerUid:options.ownerUid,label:options.label,bindingVersion:1,resetHistory:[],lastResetAt:0,operations:{}}};
 return {hash,record};
}
async function provision(database,options,lookupSecret,now=Date.now()){
 const {hash,record}=buildRecord(options,now),alias=keyAlias(options.key,lookupSecret);
 // One atomic provisioning operation reserves both alias and authoritative
 // license. This administrative CLI is intentionally low volume; a root
 // transaction also reserves the account's single license slot, including
 // concurrent requests with different keys. Every key has its own account.
 const result=await database.ref().transaction(root=>{
  root=root||{};const licenses=root.licensesV9||{},aliases=root.portalKeyAliases||{};
  if(Object.hasOwn(licenses,hash)||Object.hasOwn(aliases,alias)||Object.values(licenses).some(r=>r?.portal?.ownerUid===options.ownerUid))return;
  return {...root,licensesV9:{...licenses,[hash]:record},portalKeyAliases:{...aliases,[alias]:{licenseId:hash,createdAt:now}}};
 });
 if(!result.committed)throw Error('provision_conflict_or_account_limit');return {hash,record};
}
async function main(){
 const options=parseArgs(process.argv.slice(2)),lookupSecret=decodeSecret(process.env.MIZZE_KEY_LOOKUP_SECRET);
 // Imports are deliberately inside the explicit CLI entrypoint. Requiring
 // this module in unit tests never opens a Firebase connection.
 const {initializeApp,cert}=require('firebase-admin/app'),{getDatabase}=require('firebase-admin/database'),{getAuth}=require('firebase-admin/auth');
 const {readCredentials,deploymentConfig}=require('./credentials-v9.cjs'),config=deploymentConfig();
 const {account}=readCredentials(process.env.GOOGLE_APPLICATION_CREDENTIALS,process.env.MIZZE_LICENSE_PRIVATE_KEY_FILE,config.identity,config.projectId);
 const app=initializeApp({credential:cert(account),databaseURL:config.databaseURL,projectId:config.projectId});
 try{
  const user=await getAuth(app).getUser(options.ownerUid);if(user.disabled)throw Error('account_disabled');
  const {hash}=await provision(getDatabase(app),options,lookupSecret);
  process.stdout.write('Provisioned account-owned license. Store this delivery securely; password is not stored in the database.\n'+JSON.stringify({licenseId:hash,accountUid:options.ownerUid,key:options.key,password:options.password,durationDays:options.durationMs/86400000,maxDevices:options.maxDevices},null,2)+'\n');
 }finally{await require('firebase-admin/app').deleteApp(app);}
}
if(require.main===module){main().catch(()=>{process.stderr.write('Provisioning failed. Check arguments, account, private configuration or existing key locally.\n');process.exitCode=1;});}
module.exports={parseArgs,buildRecord,provision};
