import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { NextRequest } from 'next/server';
import { POST } from '../app/auth/reset/route';
import { dispatchKey } from '../lib/key-http';
import { DashboardPage } from '../components/portal';
import { createDatabase } from '../backend/test-db.cjs';
import { buildRecord } from '../backend/provision.cjs';
import { credentials } from '../backend/key-access.cjs';
import { open } from '../lib/key-session';

process.env.MIZZE_SESSION_SECRET = randomBytes(32).toString('base64');
process.env.MIZZE_DEMO_MODE = '1';
const origin = 'http://127.0.0.1:3500', key = 'MZ-DEMO-2026', password = 'Mizze-Demo-2026!', firstDevice = 'a'.repeat(64);

test('dashboard reset is an ordinary enabled HTML form before hydration, without dialog or browser crypto', () => {
  const html = renderToStaticMarkup(createElement(DashboardPage, {
    initialSession: { authenticated: true, csrfToken: 'f'.repeat(64), demo: true },
    initialLicense: { status: 'reset_required', deviceId: '', devices: [firstDevice], maxDevices: 1, activatedAt: 1, expiresAt: Date.now() + 86400000, durationMs: 86400000, reset: { used: 0, remaining: 2, nextAllowedAt: 0 } },
  }));
  const resetForm = html.match(/<form[^>]*action="\/auth\/reset"[^>]*>/)![0];
  assert.match(resetForm, /method="post"/);
  assert.match(html, /name="csrfToken" value="f{64}"/);
  assert.match(html, /<textarea[^>]+name="deviceId"/);
  assert.match(html, /<button type="submit" class="primary">Reset thiết bị/);
  assert.doesNotMatch(html, /<dialog/);
});

test('native reset form confirms before writing, keeps expiry, deduplicates retry and enforces two turns', async () => {
  const now = Date.now(), built = buildRecord({ ownerUid: 'owner', key, password, durationMs: 86400000, maxDevices: 1, label: 'Test' }, now);
  const db = createDatabase({ licensesV9: { [built.hash]: built.record } });
  (globalThis as any).mizzeKeyDemo = db;
  const jar = new Map<string, string>(); let csrf = '';
  const cookies = () => [...jar].map(([k, v]) => k + '=' + v).join('; ');
  const save = (response: any) => { for (const cookie of response.cookies.getAll()) jar.set(cookie.name, cookie.value); };
  async function api(action: 'session' | 'login' | 'licenses', body?: unknown) {
    const response = await dispatchKey(new NextRequest(origin + '/api/' + action, { method: body ? 'POST' : 'GET', headers: {
      host: '127.0.0.1:3500', cookie: cookies(), ...(body ? { origin, 'content-type': 'application/json', 'x-csrf-token': csrf } : {}),
    }, body: body ? JSON.stringify(body) : undefined }), action);
    save(response); const data = await response.json(); if (data.csrfToken) csrf = data.csrfToken; return { response, data };
  }
  async function form(fields: Record<string, string>, overrides: Record<string, string> = {}) {
    const response = await POST(new NextRequest(origin + '/auth/reset', { method: 'POST', headers: {
      host: '127.0.0.1:3500', cookie: cookies(), origin, 'content-type': 'application/x-www-form-urlencoded', ...overrides,
    }, body: new URLSearchParams({ csrfToken: csrf, ...fields }).toString() }));
    save(response); return response;
  }
  await api('session'); assert.equal((await api('login', { key, password, deviceId: firstDevice })).response.status, 200);
  const expiry = db.read('licensesV9/' + built.hash).expiresAt;
  const earlierSession = jar.get('mizze_session')!;
  const denied = await form({ deviceId: 'b'.repeat(64) }, { origin: 'https://evil.example' });
  assert.equal(denied.status, 403); assert.match(await denied.text(), /Phiên bảo vệ/);
  assert.equal((await form({ deviceId: 'b'.repeat(64), csrfToken: '' })).status, 403);
  assert.equal((await form({ deviceId: '<script>alert(1)</script>' })).status, 400);
  assert.deepEqual(Object.keys(db.read('licensesV9/' + built.hash).devices), [firstDevice]);
  const prepared = await form({ deviceId: 'B'.repeat(32) + '\n' + 'B'.repeat(32) });
  assert.equal(prepared.status, 200); assert.equal(prepared.headers.get('cache-control'), 'private, no-store');
  const html = await prepared.text(); assert.match(html, /Đổi sang máy này/); assert.doesNotMatch(html, /<script/);
  assert.deepEqual(Object.keys(db.read('licensesV9/' + built.hash).devices), [firstDevice], 'preparing or cancelling confirmation never spends quota');
  const operationId = html.match(/name="operationId" value="([a-f0-9]{32})"/)![1];
  const accepted = await form({ deviceId: 'b'.repeat(64), operationId, confirmed: 'yes' });
  assert.equal(accepted.status, 303); assert.equal(accepted.headers.get('location'), '/dashboard?reset=done');
  assert.deepEqual(Object.keys(db.read('licensesV9/' + built.hash).devices), ['b'.repeat(64)]);
  assert.equal(db.read('licensesV9/' + built.hash).portal.resetHistory.length, 1);
  assert.equal(db.read('licensesV9/' + built.hash).expiresAt, expiry);
  assert.equal((await form({ deviceId: 'b'.repeat(64), operationId, confirmed: 'yes' })).status, 303);
  assert.equal(db.read('licensesV9/' + built.hash).portal.resetHistory.length, 1, 'double tap cannot spend a second reset');
  const racingRetry = await form({ deviceId: 'b'.repeat(64), operationId, confirmed: 'yes' }, { cookie: 'mizze_csrf=' + csrf + '; mizze_session=' + earlierSession });
  assert.equal(racingRetry.status, 303);
  assert.equal(open(racingRetry.cookies.get('mizze_session')!.value)!.deviceId, 'b'.repeat(64), 'an earlier in-flight session cannot put the dashboard back on the old device');
  assert.equal(db.read('licensesV9/' + built.hash).portal.resetHistory.length, 1);
  const second = await form({ deviceId: 'c'.repeat(64) }), secondHtml = await second.text();
  const nextOperation = secondHtml.match(/name="operationId" value="([a-f0-9]{32})"/)![1];
  assert.equal((await form({ deviceId: 'c'.repeat(64), operationId: nextOperation, confirmed: 'yes' })).status, 303);
  assert.equal(db.read('licensesV9/' + built.hash).portal.resetHistory.length, 2);
  assert.equal(db.read('licensesV9/' + built.hash).expiresAt, expiry);
  const third = await form({ deviceId: 'd'.repeat(64) }); assert.equal(third.status, 409); assert.match(await third.text(), /Đã hết 2 lượt/);
  assert.equal((await api('licenses')).data.license.reset.used, 2);
  assert.equal((await form({ deviceId: 'e'.repeat(64) }, { cookie: 'mizze_csrf=' + csrf })).status, 401);
  assert.equal(credentials(key, password, firstDevice).licenseId, built.hash);
});

test('native form rejects duplicate fields and oversized or non-form bodies', async () => {
  const fields = new URLSearchParams({ deviceId: 'a'.repeat(64), csrfToken: 'b'.repeat(64) }); fields.append('deviceId', 'c'.repeat(64));
  for (const [body, type, expected] of [[fields.toString(), 'application/x-www-form-urlencoded', 400], ['x'.repeat(2100), 'application/x-www-form-urlencoded', 413], ['{}', 'application/json', 400]] as const) {
    const response = await POST(new NextRequest(origin + '/auth/reset', { method: 'POST', headers: { origin, host: '127.0.0.1:3500', cookie: 'mizze_csrf=' + 'b'.repeat(64), 'content-type': type }, body }));
    assert.equal(response.status, expected);
  }
});
