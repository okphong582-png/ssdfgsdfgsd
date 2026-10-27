'use client';
import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/client-api';
import styles from './ihax-key.module.css';
type Grant = { key: string; createdAt: number; expiresAt: number };
const storageKey = 'ihax.free-key.v1';
const valid = (v: Grant | null): v is Grant => !!v && /^IHAX(?:-[A-F0-9]{8}){4}$/.test(v.key) && Number.isSafeInteger(v.expiresAt) && v.expiresAt > Date.now();
async function copyKey(value: string) {
  try { await navigator.clipboard.writeText(value); return; } catch { /* Older Safari can use the selection API. */ }
  const field = document.createElement('textarea'); field.value = value; field.style.position = 'fixed'; field.style.opacity = '0';
  document.body.appendChild(field); field.select(); const copied = document.execCommand('copy'); field.remove();
  if (!copied) throw Error('Chạm giữ key để sao chép.');
}
export function IhaxKey({ csrf }: { csrf: string }) {
  const [grant, setGrant] = useState<Grant | null>(null), [busy, setBusy] = useState(false), [message, setMessage] = useState('');
  const pending = useRef(false);
  useEffect(() => { try { const saved = JSON.parse(localStorage.getItem(storageKey) || 'null'); if (valid(saved)) setGrant(saved); } catch { /* Storage may be disabled. */ } }, []);
  async function activate() {
    if (pending.current) return; pending.current = true; setBusy(true); setMessage('');
    try {
      if (valid(grant)) { await copyKey(grant.key); setMessage('Đã sao chép'); }
      else {
        const value = await api<Grant>('/api/ihax/create', csrf, {}); if (!valid(value)) throw Error('Chưa nhận được key. Thử lại.');
        setGrant(value); try { localStorage.setItem(storageKey, JSON.stringify(value)); } catch { /* The key is still shown. */ }
      }
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Chưa thể kết nối. Thử lại.'); }
    finally { pending.current = false; setBusy(false); }
  }
  return <main className={styles.page}><section className={styles.content} aria-label="Key Ihax">
    <p className={styles.brand}>IHAX<span>®</span></p>
    <button className={styles.action} disabled={busy} aria-busy={busy} onClick={activate}>
      <span>{busy ? 'Đang xử lý…' : valid(grant) ? 'Sao chép key' : 'Lấy key Ihax'}</span><span aria-hidden="true">{valid(grant) ? '↗' : '→'}</span>
    </button>
    {valid(grant) ? <div className={styles.result} aria-live="polite"><code>{grant.key}</code><p>Hết hạn <time dateTime={new Date(grant.expiresAt).toISOString()}>{new Date(grant.expiresAt).toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh', hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit', year: 'numeric' })}</time></p></div> : <p className={styles.duration}>7 ngày</p>}
    <p className={styles.message} role="status">{message}</p>
  </section></main>;
}
