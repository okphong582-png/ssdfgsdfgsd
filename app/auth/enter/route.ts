import { NextRequest, NextResponse } from 'next/server';
import { dispatchKey } from '../../../lib/key-http';

export const runtime = 'nodejs';
export const maxDuration = 30;

export async function POST(request: NextRequest) {
  let response: NextResponse;
  try {
    if (!/^application\/x-www-form-urlencoded(?:;|$)/i.test(request.headers.get('content-type') || '')) throw Error('invalid_request');
    const reader = request.body?.getReader();
    const chunks: Uint8Array[] = []; let size = 0;
    if (reader) for (;;) {
      const part = await reader.read(); if (part.done) break;
      size += part.value.length;
      if (size > 2048) { await reader.cancel(); throw Error('invalid_request'); }
      chunks.push(part.value);
    }
    const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
    const headers = new Headers(request.headers);
    headers.set('content-type', 'application/json'); headers.delete('content-length');
    headers.set('x-csrf-token', form.get('csrfToken') || '');
    const result = await dispatchKey(new NextRequest(new URL('/api/auth/login', request.url), {
      method: 'POST', headers,
      body: JSON.stringify({ key: form.get('key'), password: form.get('password'), deviceId: form.get('deviceId') }),
    }), 'login');
    const data = await result.json();
    const destination = result.ok ? '/dashboard' : '/login?error=' + encodeURIComponent(data.error?.code || 'service_unavailable');
    response = new NextResponse(null,{status:303,headers:{Location:destination}});
    for (const cookie of result.cookies.getAll()) response.cookies.set(cookie);
  } catch {
    response = new NextResponse(null,{status:303,headers:{Location:'/login?error=invalid_request'}});
  }
  response.headers.set('Cache-Control', 'private, no-store');
  return response;
}
