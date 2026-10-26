import test from 'node:test';
import assert from 'node:assert/strict';
import { api } from '../lib/client-api';

test('a stalled connection or response body stops waiting and exposes a retryable error', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = (() => new Promise(() => {})) as typeof fetch;
    await assert.rejects(api('/api/session', undefined, undefined, 20), /Kết nối chậm/);
    globalThis.fetch = async () => new Response(new ReadableStream());
    await assert.rejects(api('/api/licenses', undefined, undefined, 20), /Kết nối chậm/);
  } finally { globalThis.fetch = original; }
});
