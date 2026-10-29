import { randomBytes } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { dispatchKey } from './key-http';
import { assertCsrf, cookieNames } from './security';
import { open, seal } from './key-session';

const escape = (value: string) => value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const errors: Record<string, string> = {
  csrf_failed: 'Phiên bảo vệ đã thay đổi. Hãy quay lại và tải lại trang.',
  invalid_request: 'ID máy phải có đủ 64 ký tự gồm số và chữ a–f. Hãy dán lại ID từ menu.',
  unauthorized: 'Phiên đăng nhập đã hết. Hãy đăng nhập lại.',
  license_denied: 'Key đã khóa hoặc hết hạn.',
  reset_limited: 'Đã hết 2 lượt reset hôm nay. Hãy thử lại sau 00:00.',
  device_not_found: 'Key chưa có thiết bị để chuyển.',
  rate_limited: 'Thử lại sau một phút.',
};

function page(content: string, status = 200) {
  return new NextResponse(`<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Xác nhận đổi thiết bị · MIZZE</title><meta name="robots" content="noindex,nofollow"><style>
  *{box-sizing:border-box}body{margin:0;background:#080808;color:#efefef;font:14px Arial,Helvetica,sans-serif}main{max-width:430px;margin:50px auto;padding:24px}header{font-weight:bold;letter-spacing:4px;margin-bottom:32px}section{background:#111;border:1px solid #292929;border-radius:13px;padding:25px}h1{font-size:21px;font-weight:500;margin:0}p{color:#aaa;line-height:1.8;margin:18px 0}code{display:block;word-break:break-all;background:#080808;border:1px solid #333;border-radius:8px;padding:14px;font-size:12px;line-height:1.8}.actions{display:flex;gap:12px;margin-top:26px}button,a{font:inherit;text-decoration:none;text-align:center;display:block;border-radius:8px;padding:14px;border:1px solid #444;cursor:pointer}button,.primary{flex:1;background:#e9e9e9;color:#151515}a{background:transparent;color:#bbb}.actions a{flex:.6}.back{margin-top:24px}
  </style></head><body><main><header>MIZZE<sup>®</sup></header><section>${content}</section></main></body></html>`, {
    status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'private, no-store', 'Referrer-Policy': 'same-origin' },
  });
}
function failure(code: string, status = 400) {
  return page(`<h1>Chưa thể đổi thiết bị</h1><p role="alert">${escape(errors[code] || 'Kết nối gián đoạn. Hãy quay lại và thử lại.')}</p><a class="back" href="${code === 'unauthorized' ? '/login' : '/dashboard'}">Quay lại</a>`, status);
}
function complete() {
  return new NextResponse(null, { status: 303, headers: { Location: '/dashboard?reset=done', 'Cache-Control': 'private, no-store' } });
}
function copyCookies(from: NextResponse, to: NextResponse) {
  for (const cookie of from.cookies.getAll()) to.cookies.set(cookie);
  return to;
}

// Plain HTML submission remains usable when Safari cannot hydrate the client bundle.
// Preparing this page never changes a device or consumes reset quota.
export async function submitResetForm(request: NextRequest) {
  try {
    if (!/^application\/x-www-form-urlencoded(?:;|$)/i.test(request.headers.get('content-type') || '')) return failure('invalid_request');
    const reader = request.body?.getReader(), chunks: Uint8Array[] = []; let size = 0;
    if (reader) for (;;) {
      const part = await reader.read(); if (part.done) break;
      size += part.value.length; if (size > 2048) { await reader.cancel(); return failure('invalid_request', 413); }
      chunks.push(part.value);
    }
    const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
    for (const name of form.keys()) if (!['deviceId', 'csrfToken', 'operationId', 'confirmed'].includes(name) || form.getAll(name).length !== 1) return failure('invalid_request');
    const secure = request.nextUrl.protocol === 'https:', names = cookieNames(secure);
    const host = request.headers.get('host'), expectedOrigin = host ? new URL(`${secure ? 'https' : 'http'}://${host}`).origin : request.nextUrl.origin;
    const csrf = form.get('csrfToken') || '';
    assertCsrf(request.headers.get('origin'), expectedOrigin, csrf, request.cookies.get(names.csrf)?.value);
    const id = (form.get('deviceId') || '').replace(/[\s\u200B\uFEFF]/g, '').toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(id)) return failure('invalid_request');
    const headers = new Headers(request.headers); headers.delete('content-length'); headers.delete('content-type');
    const current = await dispatchKey(new NextRequest(new URL('/api/licenses', request.url), { headers }), 'licenses');
    const data = await current.json();
    if (!current.ok) return copyCookies(current, failure(data.error?.code || 'unauthorized', current.status));
    if (data.license.status === 'unavailable') return copyCookies(current, failure('license_denied', 403));
    // A replay or double tap for a device already linked must not spend another turn.
    if (data.license.devices.includes(id)) {
      const response = copyCookies(current, complete());
      const session = open(request.cookies.get(names.session)?.value);
      if (session) response.cookies.set(names.session, seal({ ...session, deviceId: id }), {
        secure, httpOnly: true, sameSite: 'strict', path: '/', maxAge: Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000)),
      });
      return response;
    }
    if (data.license.reset.remaining <= 0) return copyCookies(current, failure('reset_limited', 409));
    if (form.get('confirmed') !== 'yes') {
      const operationId = randomBytes(16).toString('hex');
      return copyCookies(current, page(`<h1>Đổi sang máy này?</h1><p>Máy cũ sẽ mất quyền truy cập. Hạn key giữ nguyên. Chỉ tính một lượt khi bạn xác nhận.</p><code>${escape(id)}</code><form method="post" action="/auth/reset"><input type="hidden" name="deviceId" value="${escape(id)}"><input type="hidden" name="csrfToken" value="${escape(csrf)}"><input type="hidden" name="operationId" value="${operationId}"><input type="hidden" name="confirmed" value="yes"><div class="actions"><a href="/dashboard">Hủy</a><button type="submit">Xác nhận</button></div></form>`));
    }
    const operationId = form.get('operationId') || '';
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(operationId)) return failure('invalid_request');
    headers.set('content-type', 'application/json'); headers.set('x-csrf-token', csrf);
    const result = await dispatchKey(new NextRequest(new URL('/api/reset', request.url), {
      method: 'POST', headers, body: JSON.stringify({ deviceId: id, operationId }),
    }), 'reset');
    const reset = await result.json();
    return copyCookies(result, result.ok ? complete() : failure(reset.error?.code || 'service_unavailable', result.status));
  } catch (error) {
    const code = error instanceof Error && 'code' in error ? String(error.code) : 'service_unavailable';
    return failure(code, code === 'csrf_failed' ? 403 : 503);
  }
}
