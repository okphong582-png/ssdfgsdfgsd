import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { secret } from './security';
export type KeySession = { sid: string; licenseId: string; deviceId: string; createdAt: number; expiresAt: number };
export const TTL = 8 * 3600000;
export function seal(value: KeySession) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', secret('MIZZE_SESSION_SECRET').subarray(0,32), iv);
  cipher.setAAD(Buffer.from('mizze-key-session-v1'));
  const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
  return Buffer.concat([iv,cipher.getAuthTag(),data]).toString('base64url');
}
export function open(raw: string | undefined, now = Date.now()): KeySession | null {
  if (!raw || raw.length > 2048) return null;
  try {
    const data=Buffer.from(raw,'base64url');if(data.length<29)return null;
    const decipher=createDecipheriv('aes-256-gcm',secret('MIZZE_SESSION_SECRET').subarray(0,32),data.subarray(0,12));
    decipher.setAAD(Buffer.from('mizze-key-session-v1'));decipher.setAuthTag(data.subarray(12,28));
    const s=JSON.parse(Buffer.concat([decipher.update(data.subarray(28)),decipher.final()]).toString()) as KeySession;
    if(![s.sid,s.licenseId,s.deviceId].every(v=>/^[a-f0-9]{64}$/.test(v))||!Number.isSafeInteger(s.createdAt)||!Number.isSafeInteger(s.expiresAt)||s.createdAt>now||s.expiresAt<=now||s.expiresAt-s.createdAt!==TTL)return null;
    return s;
  } catch {return null;}
}
