import type { Metadata } from "next";
import { DashboardPage } from "../../components/portal";
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { open } from '../../lib/key-session';

export const metadata: Metadata = { title: "Key & thiết bị" };
export default async function Page() {
  const jar = await cookies();
  if (!open(jar.get('__Host-mizze_session')?.value || jar.get('mizze_session')?.value)) redirect('/login');
  return <DashboardPage />;
}
