import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { NextRequest } from 'next/server';
import { proxy } from '../proxy';
import { POST } from '../app/auth/enter/route';

process.env.MIZZE_SESSION_SECRET = randomBytes(32).toString('base64');
process.env.MIZZE_DEMO_MODE = '1';
const origin = 'http://127.0.0.1:3500';

test('first visits redirect to the login form at HTTP level without rendering a dashboard shell', () => {
  for (const path of ['/', '/dashboard']) {
    const response = proxy(new NextRequest(origin + path));
    assert.equal(response.status, 307);
    assert.equal(new URL(response.headers.get('location')!).pathname, '/login');
  }
});

test('the first HTML response and browser cookie share a CSRF token before JavaScript runs', () => {
  const response = proxy(new NextRequest(origin + '/login'));
  const cookie = response.cookies.get('mizze_csrf')!;
  assert.match(cookie.value, /^[a-f0-9]{64}$/);
  assert.ok(response.headers.get('x-middleware-request-cookie')?.includes('mizze_csrf=' + cookie.value));
});

test('plain HTML form can authenticate without JavaScript while still enforcing origin and CSRF', async () => {
  const csrf = randomBytes(32).toString('hex');
  const body = new URLSearchParams({ key: 'MZ-DEMO-2026', password: 'Mizze-Demo-2026!', deviceId: 'a'.repeat(64), csrfToken: csrf });
  function request(requestOrigin: string) {
    return new NextRequest(origin + '/auth/enter', { method: 'POST', headers: {
      host: '127.0.0.1:3500', origin: requestOrigin, cookie: 'mizze_csrf=' + csrf,
      'content-type': 'application/x-www-form-urlencoded',
    }, body: body.toString() });
  }
  const denied = await POST(request('https://evil.example'));
  assert.equal(new URL(denied.headers.get('location')!,origin).searchParams.get('error'), 'csrf_failed');
  assert.equal(denied.cookies.get('mizze_session'), undefined);
  const accepted = await POST(request(origin));
  assert.equal(accepted.status, 303);
  assert.equal(new URL(accepted.headers.get('location')!,origin).pathname, '/dashboard');
  assert.ok(accepted.cookies.get('mizze_session')?.httpOnly);
  assert.equal(accepted.headers.get('cache-control'), 'private, no-store');
});
