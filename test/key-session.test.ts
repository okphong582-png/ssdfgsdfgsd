import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { open, seal, TTL } from '../lib/key-session';
import { assertCsrf, demoEnabled } from '../lib/security';
process.env.MIZZE_SESSION_SECRET=randomBytes(32).toString('base64');
test('key-only encrypted session rejects tampering, expiration and altered scope',()=>{
 const now=Date.now(),s={sid:'a'.repeat(64),licenseId:'b'.repeat(64),deviceId:'c'.repeat(64),createdAt:now,expiresAt:now+TTL};
 const value=seal(s);assert.deepEqual(open(value,now),s);assert.equal(open(value,now+TTL),null);
 const b=Buffer.from(value,'base64url');b[b.length-1]^=1;assert.equal(open(b.toString('base64url'),now),null);
 assert.equal(open(seal({...s,expiresAt:s.expiresAt+1}),now),null);assert.equal(open(seal({...s,licenseId:'other-key'}),now),null);
 assert.ok(!value.includes(s.licenseId));
});
test('CSRF requires exact origin and cookie-bound token; demo is denied on hosted production',()=>{
 const t='a'.repeat(64);assert.doesNotThrow(()=>assertCsrf('https://key.example','https://key.example',t,t));
 assert.throws(()=>assertCsrf('https://evil.example','https://key.example',t,t));assert.throws(()=>assertCsrf('https://key.example','https://key.example','b'.repeat(64),t));
 const d=process.env.MIZZE_DEMO_MODE,v=process.env.VERCEL;try{process.env.MIZZE_DEMO_MODE='1';process.env.VERCEL='1';assert.throws(()=>demoEnabled('localhost'));}finally{if(d===undefined)delete process.env.MIZZE_DEMO_MODE;else process.env.MIZZE_DEMO_MODE=d;if(v===undefined)delete process.env.VERCEL;else process.env.VERCEL=v;}
});
