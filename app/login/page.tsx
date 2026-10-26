import type { Metadata } from "next";
import { LoginPage } from "../../components/portal";
import { cookies } from 'next/headers';

export const metadata: Metadata = { title: "Đăng nhập" };
export default async function Page({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const jar = await cookies(), query = await searchParams;
  const csrfToken = jar.get('__Host-mizze_csrf')?.value || jar.get('mizze_csrf')?.value || '';
  const errors: Record<string, string> = {
    license_denied: 'Key hoặc mật khẩu không đúng, đã khóa hoặc hết hạn.',
    invalid_request: 'Nhập đủ key, mật khẩu và ID máy hợp lệ.',
    rate_limited: 'Thử lại sau một phút.',
    csrf_failed: 'Hãy tải lại trang rồi thử lại.',
  };
  return <LoginPage initialSession={csrfToken ? { authenticated: false, csrfToken, demo: false } : undefined}
    initialError={query.error ? errors[query.error] || 'Chưa thể kết nối. Vui lòng thử lại.' : ''} />;
}
