import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { NextRequest } from 'next/server';
import { dispatchKey } from '../lib/key-http';
import { createDatabase } from '../backend/test-db.cjs';
import { buildRecord } from '../backend/provision.cjs';
import { credentials } from '../backend/key-access.cjs';

process.env.MIZZE_SESSION_SECRET=randomBytes(32).toString('base64');
process.env.MIZZE_DEMO_MODE='1';
const origin='http://127.0.0.1:3500',key='MZ-DEMO-2026',password='Mizze-Demo-2026!',device='a'.repeat(64),id=credentials(key,password,device).licenseId;
test('full key-only routes enforce credentials, CSRF, scope, two daily resets and durable logout',async()=>{
 const now=Date.now(),record=buildRecord({ownerUid:'owner',key,password,durationMs:86400000,maxDevices:1,label:'Test'},now).record;
 const other=buildRecord({ownerUid:'other',key:'MZ-OTHER-KEY',password:'other-synthetic-password',durationMs:86400000,maxDevices:1,label:'Other'},now);
 const db=createDatabase({licensesV9:{[id]:record,[other.hash]:other.record}});
 (globalThis as any).mizzeKeyDemo=db;
 const jar=new Map<string,string>();let csrf='';
 async function call(action:'session'|'login'|'logout'|'licenses'|'reset',body?:unknown,wrongOrigin=false){
  const headers:Record<string,string>={host:'127.0.0.1:3500',cookie:[...jar].map(([k,v])=>k+'='+v).join('; ')};
  if(body!==undefined)Object.assign(headers,{'content-type':'application/json','origin':wrongOrigin?'https://evil.example':origin,'x-csrf-token':csrf});
  const response=await dispatchKey(new NextRequest(origin+'/api/test',{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body)}),action);
  for(const cookie of response.cookies.getAll())jar.set(cookie.name,cookie.value);
  const data=await response.json();if(data.csrfToken)csrf=data.csrfToken;return {response,data};
 }
 await call('session');
 assert.equal((await call('login',{key,password:'Wrong-password-12345',deviceId:device})).response.status,403);
 assert.equal((await call('login',{key,password,deviceId:device},true)).response.status,403);
 const login=await call('login',{key,password,deviceId:device});assert.equal(login.response.status,200);assert.equal(login.data.license.status,'active');
 const expiry=login.data.license.expiresAt;assert.equal(db.read('licensesV9/'+id).devices[device].portalLoggedOut,false);
 assert.equal((await call('reset',{deviceId:'b'.repeat(64),operationId:randomBytes(16).toString('hex'),licenseId:other.hash})).response.status,400);
 const op=randomBytes(16).toString('hex'),first=await call('reset',{deviceId:'b'.repeat(64),operationId:op});assert.equal(first.response.status,200);assert.equal(first.data.license.reset.used,1);
 const retry=await call('reset',{deviceId:'b'.repeat(64),operationId:op});assert.equal(retry.data.license.reset.used,1);
 const second=await call('reset',{deviceId:'c'.repeat(64),operationId:randomBytes(16).toString('hex')});assert.equal(second.data.license.reset.used,2);assert.equal(second.data.license.expiresAt,expiry);
 assert.equal((await call('reset',{deviceId:'d'.repeat(64),operationId:randomBytes(16).toString('hex')})).response.status,409);
 assert.deepEqual(db.read('licensesV9/'+other.hash),other.record);
 const stolen=jar.get('mizze_session')!;await call('logout',{});jar.set('mizze_session',stolen);
 assert.equal((await call('licenses')).response.status,401);assert.equal((await call('session')).data.authenticated,false);
});
