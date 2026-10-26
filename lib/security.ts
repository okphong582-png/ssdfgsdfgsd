import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Session } from './types';

export class AppError extends Error {
  constructor(public code: string, public status = 400, message = 'Không thể hoàn tất yêu cầu. Vui lòng thử lại.') { super(message); }
}

export const SESSION_TTL = 8 * 60 * 60 * 1000;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
let localDemoKey: Buffer | undefined;
export function demoEnabled(hostname?: string): boolean {
  if (process.env.MIZZE_DEMO_MODE !== '1') return false;
  if (process.env.VERCEL || process.env.NODE_ENV === 'production') throw new AppError('unsafe_demo', 503, 'Bản thử nghiệm chỉ được chạy cục bộ.');
  if (hostname && !LOCAL_HOSTS.has(hostname)) throw new AppError('unsafe_demo', 403);
  return true;
}
export function secret(name: string): Buffer {
  const raw = process.env[name];
  if (!raw || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) throw new AppError('not_configured', 503, 'Dịch vụ đang chờ cấu hình môi trường.');
  const key = Buffer.from(raw, 'base64');
  if (key.length < 32) throw new AppError('not_configured', 503, 'Dịch vụ đang chờ cấu hình môi trường.');
  return key;
}
function sessionKey() {
  if (process.env.MIZZE_SESSION_SECRET) return secret('MIZZE_SESSION_SECRET').subarray(0, 32);
  if (demoEnabled()) return localDemoKey ??= randomBytes(32);
  throw new AppError('not_configured', 503, 'Dịch vụ đang chờ cấu hình môi trường.');
}
export function sealSession(session: Session): string {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', sessionKey(), iv);
  cipher.setAAD(Buffer.from('mizze-portal-session-v1'));
  const payload = Buffer.concat([cipher.update(JSON.stringify(session), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), payload]).toString('base64url');
}
export function openSession(value: string | undefined, now = Date.now()): Session | null {
  if (!value || value.length > 16000) return null;
  try {
    const data = Buffer.from(value, 'base64url');
    if (data.length < 29) return null;
    const decipher = createDecipheriv('aes-256-gcm', sessionKey(), data.subarray(0, 12));
    decipher.setAAD(Buffer.from('mizze-portal-session-v1')); decipher.setAuthTag(data.subarray(12, 28));
    const session = JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8')) as Session;
    if (!/^[a-f0-9]{64}$/.test(session.sid || '') || !session.user?.uid || !session.user.email || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= now ||
        session.createdAt > now || session.expiresAt - session.createdAt > SESSION_TTL || !Number.isFinite(session.authTime) ||
        typeof session.idToken !== 'string' || typeof session.refreshToken !== 'string') return null;
    if (session.demo && !demoEnabled()) return null;
    return session;
  } catch { return null; }
}
export function sameSecret(a: string, b: string): boolean {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
export function assertCsrf(requestOrigin: string | null, expectedOrigin: string, header: string | null, cookie: string | undefined) {
  if (!requestOrigin || requestOrigin !== expectedOrigin || !header || !cookie || !/^[a-f0-9]{64}$/.test(header) || !sameSecret(header, cookie)) {
    throw new AppError('csrf_failed', 403, 'Phiên bảo vệ đã thay đổi. Hãy tải lại trang.');
  }
}
export function cookieNames(secure: boolean) { return { session: secure ? '__Host-mizze_session' : 'mizze_session', csrf: secure ? '__Host-mizze_csrf' : 'mizze_csrf' }; }
export function hashPrivate(value: string): string { return createHmac('sha256', secret('MIZZE_PORTAL_SERVICE_SECRET')).update(value).digest('hex'); }
