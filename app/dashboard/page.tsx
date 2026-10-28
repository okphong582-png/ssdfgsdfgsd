import type { Metadata } from "next";
import { DashboardPage, type License } from "../../components/portal";
import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { NextRequest } from 'next/server';
import { open } from '../../lib/key-session';
import { dispatchKey } from '../../lib/key-http';
export const metadata: Metadata = { title: "Key & thiáº¿t bá»‹" };
export default async function Page() {
 const jar=await cookies(),incoming=await headers();
 if(!open(jar.get('__Host-mizze_session')?.value||jar.get('mizze_session')?.value))redirect('/login');
 const host=incoming.get('host')||'localhost',local=/^(localhost|127\.0\.0\.1)(:|$)/.test(host);
 const scheme=local&&incoming.get('x-forwarded-proto')!=='https'?'http':'https';
 const requestHeaders=new Headers(incoming);requestHeaders.set('cookie',jar.getAll().map(c=>c.name+'='+c.value).join('; '));
 const response=await dispatchKey(new NextRequest(new URL('/api/licenses',scheme+'://'+host),{headers:requestHeaders}),'licenses');
 if(response.status===401)redirect('/login');
 const data=await response.json() as {license?:License;error?:{message?:string}};
 return <DashboardPage initialSession={{authenticated:true,csrfToken:jar.get('__Host-mizze_csrf')?.value||jar.get('mizze_csrf')?.value||'',demo:local&&process.env.MIZZE_DEMO_MODE==='1'}}
  initialLicense={response.ok?data.license:undefined} initialError={response.ok?'':data.error?.message||'Chưa tải được key. Vui lòng thử lại.'}/>;
}
