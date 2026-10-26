import { randomBytes } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { open } from './lib/key-session';

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
  // Seed CSRF before hydration. Parallel initial session requests (including
  // React Strict Mode) must see one cookie rather than race two new tokens.
  const secure = request.nextUrl.protocol === 'https:';
  const csrfName = secure ? '__Host-mizze_csrf' : 'mizze_csrf';
  const newCsrf = !/^[a-f0-9]{64}$/.test(request.cookies.get(csrfName)?.value || '') ? randomBytes(32).toString('hex') : null;
  if (newCsrf) {
    const jar = new Map(request.cookies.getAll().map(c => [c.name, c.value]));
    jar.set(csrfName, newCsrf);
    headers.set('cookie', [...jar].map(([name, value]) => `${name}=${value}`).join('; '));
  }
  const needsLogin = request.nextUrl.pathname === '/' || (request.nextUrl.pathname === '/dashboard' &&
    !open(request.cookies.get(secure ? '__Host-mizze_session' : 'mizze_session')?.value));
  const response = needsLogin
    ? NextResponse.redirect(new URL('/login', request.url), 307)
    : NextResponse.next({ request: { headers } });
  if (newCsrf) response.cookies.set(csrfName, newCsrf, { secure, httpOnly: true, sameSite: 'strict', path: '/', maxAge: 86400 });
  response.headers.set('Content-Security-Policy', policy);
  response.headers.set('Cache-Control', 'private, no-store');
  return response;
}
export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] };
