import type { Metadata } from 'next';
import { cookies } from 'next/headers';
import { IhaxKey } from '@/components/ihax-key';
export const metadata: Metadata = { title: { absolute: 'IHAX · Lấy key' }, description: 'Lấy key Ihax 7 ngày.' };
export default async function Page() {
  const jar = await cookies();
  return <IhaxKey csrf={jar.get('__Host-mizze_csrf')?.value || jar.get('mizze_csrf')?.value || ''} />;
}
