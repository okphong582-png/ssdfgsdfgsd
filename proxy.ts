import { randomBytes } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';

export function proxy(request: NextRequest) {
  const nonce = randomBytes(18).toString('base64');
  const dev = process.env.NODE_ENV !== 'production';
  const policy = [
    "default-src 'self'",
    dev ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'" : `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:", "font-src 'self'",
    `connect-src 'self'${dev ? ' ws: wss:' : ''}`,
    "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'",
  ].join('; ');
  const headers = new Headers(request.headers);
  headers.set('x-nonce', nonce); headers.set('Content-Security-Policy', policy);
  const response = NextResponse.next({ request: { headers } });
  // Seed CSRF before hydration. Parallel initial session requests (including
  // React Strict Mode) must see one cookie rather than race two new tokens.
  const secure = request.nextUrl.protocol === 'https:';
  const csrfName = secure ? '__Host-mizze_csrf' : 'mizze_csrf';
  if (!/^[a-f0-9]{64}$/.test(request.cookies.get(csrfName)?.value || '')) {
    response.cookies.set(csrfName, randomBytes(32).toString('hex'), { secure, httpOnly: true, sameSite: 'strict', path: '/', maxAge: 86400 });
  }
  response.headers.set('Content-Security-Policy', policy);
  response.headers.set('Cache-Control', 'private, no-store');
  return response;
}
export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] };
