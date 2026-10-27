import { NextRequest, NextResponse } from 'next/server';
import { AppError, assertCsrf, cookieNames } from './security';
import { normalize } from '../backend/ihax-service.cjs';

type Service = { issue(ip: string): Promise<{ key: string; createdAt: number; expiresAt: number }>; verify(key: string, ip: string): Promise<boolean> };
const headers = { 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };
const ipOf = (r: NextRequest) => r.headers.get('x-vercel-forwarded-for') || r.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || r.nextUrl.hostname;
function failure(error: unknown, native: boolean) {
  const e = error as { code?: string; status?: number };
  const status = e.code === 'rate_limited' ? 429 : e instanceof AppError ? e.status : 503;
  const message = status === 429 ? 'Thử lại sau ít phút.' : status === 403 ? 'Hãy tải lại trang rồi thử lại.' : 'Chưa thể kết nối. Thử lại sau.';
  return NextResponse.json(native ? { ok: false, ihaxV5: false, error: message } : { error: { message } }, { status, headers });
}
export function ihaxHandlers(getService: () => Service | Promise<Service>) {
  return {
    async create(request: NextRequest) {
      try {
        if (request.method !== 'POST') return new NextResponse(null, { status: 405, headers: { ...headers, Allow: 'POST' } });
        const secure = request.nextUrl.protocol === 'https:';
        if (!secure && !['localhost', '127.0.0.1', '[::1]'].includes(request.nextUrl.hostname)) throw new AppError('https_required', 403);
        const host = request.headers.get('host'), origin = host ? new URL(`${secure ? 'https' : 'http'}://${host}`).origin : request.nextUrl.origin;
        assertCsrf(request.headers.get('origin'), origin, request.headers.get('x-csrf-token'), request.cookies.get(cookieNames(secure).csrf)?.value);
        if (!/^application\/json(?:;|$)/i.test(request.headers.get('content-type') || '') || Number(request.headers.get('content-length')) > 128) throw new AppError('invalid_request', 400);
        const reader = request.body?.getReader(); const chunks: Uint8Array[] = []; let size = 0;
        if (reader) for (;;) { const next = await reader.read(); if (next.done) break; size += next.value.length; if (size > 128) { await reader.cancel(); throw new AppError('invalid_request', 413); } chunks.push(next.value); }
        let body; try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch { throw new AppError('invalid_request', 400); }
        if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) throw new AppError('invalid_request', 400);
        return NextResponse.json(await (await getService()).issue(ipOf(request)), { headers });
      } catch (error) { return failure(error, false); }
    },
    async verify(request: NextRequest) {
      try {
        const query = request.nextUrl.searchParams.getAll('key'), header = request.headers.get('x-ff-key');
        if (query.length > 1 || (header && query[0] && normalize(header) !== normalize(query[0]))) return NextResponse.json({ ok: false, ihaxV5: false, error: 'Key không hợp lệ.' }, { status: 403, headers });
        const key = header || query[0] || '';
        if (!await (await getService()).verify(key, ipOf(request))) return NextResponse.json({ ok: false, ihaxV5: false, error: 'Key không đúng, đã khóa hoặc hết hạn.' }, { status: 403, headers });
        return NextResponse.json({ ok: true, ihaxV5: true, error: '' }, { headers });
      } catch (error) { return failure(error, true); }
    },
  };
}
export const liveIhaxHandlers = ihaxHandlers(async () => (await import('./ihax-service')).ihaxService());
