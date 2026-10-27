import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { ihaxHandlers } from '../lib/ihax-http';
import { createIhaxService, keyId } from '../backend/ihax-service.cjs';
import { createDatabase } from '../backend/test-db.cjs';
const token='a'.repeat(64),origin='https://www.mizzeproxy.store',now=1793120400000;
function request(path:string,body:object={},headers:Record<string,string>={}) { return new NextRequest(origin+path,{method:'POST',headers:{host:'www.mizzeproxy.store',origin,'content-type':'application/json','x-csrf-token':token,cookie:'__Host-mizze_csrf='+token,'x-forwarded-for':'synthetic-ip',...headers},body:JSON.stringify(body)}); }
test('one click creates a seven-day key that the exact native Ihax header/query contract accepts',async()=>{
 const db=createDatabase(),service=createIhaxService({database:db,rateSecret:Buffer.alloc(32,3),now:()=>now}),h=ihaxHandlers(()=>service);
 const created=await h.create(request('/api/ihax/create'));assert.equal(created.status,200);const grant=await created.json();assert.equal(grant.expiresAt-grant.createdAt,7*86400000);
 for(const req of [new NextRequest(origin+'/api/ihax/verify',{headers:{'X-FF-Key':grant.key}}),new NextRequest(origin+'/api/ihax/verify?key='+grant.key)]){
  const response=await h.verify(req);assert.equal(response.status,200);assert.deepEqual(await response.json(),{ok:true,ihaxV5:true,error:''});assert.match(response.headers.get('cache-control')||'',/no-store/);
 }
 await db.ref('ihaxLicensesV1/'+keyId(grant.key)).update({enabled:false});assert.equal((await h.verify(new NextRequest(origin+'/api/ihax/verify?key='+grant.key))).status,403);
});
test('cross-origin, missing CSRF, caller-chosen keys/expiry and oversized requests are rejected before issuing',async()=>{
 let calls=0;const h=ihaxHandlers(()=>({async issue(){calls++;return {key:'',createdAt:0,expiresAt:0};},async verify(){return false;}}));
 assert.equal((await h.create(request('/api/ihax/create',{}, {origin:'https://attacker.invalid'}))).status,403);
 assert.equal((await h.create(request('/api/ihax/create',{}, {'x-csrf-token':''}))).status,403);
 assert.equal((await h.create(request('/api/ihax/create',{expiresAt:now+99999999999}))).status,400);
 assert.equal((await h.create(request('/api/ihax/create',{padding:'a'.repeat(200)}))).status,413);
 assert.equal((await h.create(new NextRequest(origin+'/api/ihax/create'))).status,405);assert.equal(calls,0);
});
test('native verification rejects missing, duplicate, conflicting and unknown credentials',async()=>{
 const db=createDatabase(),service=createIhaxService({database:db,rateSecret:Buffer.alloc(32,1),now:()=>now}),h=ihaxHandlers(()=>service),grant=await service.issue('ip');
 for(const req of [new NextRequest(origin+'/api/ihax/verify'),new NextRequest(origin+'/api/ihax/verify?key='+grant.key+'&key='+grant.key),new NextRequest(origin+'/api/ihax/verify?key='+grant.key,{headers:{'x-ff-key':'IHAX-00000000-00000000-00000000-00000000'}})]){
  const response=await h.verify(req);assert.equal(response.status,403);const value=await response.json();assert.equal(value.ok,false);assert.equal(value.ihaxV5,false);
 }
});
