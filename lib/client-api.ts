export async function api<T>(path: string, csrf?: string, body?: unknown, timeoutMs = 12000): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const pending = (async () => {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'same-origin',
      signal: controller.signal,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf || '' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data;
    try { data = await response.json(); } catch { throw Error('Mất kết nối. Thử lại sau.'); }
    if (!response.ok) throw Error(data.error?.message || 'Chưa thể xử lý.');
    return data as T;
  })();
  try {
    return await Promise.race([pending, new Promise<never>((_, reject) => {
      timer = setTimeout(() => { reject(Error('Kết nối chậm. Vui lòng thử lại.')); controller.abort(); }, timeoutMs);
    })]);
  } finally { clearTimeout(timer); }
}
