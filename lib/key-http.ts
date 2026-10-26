import { createHash, createHmac, randomBytes } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { AppError, assertCsrf, cookieNames, demoEnabled, secret } from './security';
import { open, seal, TTL, type KeySession } from './key-session';
import * as policy from '../backend/key-access.cjs';
import { createDatabase } from '../backend/test-db.cjs';
import { buildRecord } from '../backend/provision.cjs';
import { ensureKey } from '../backend/key-source.cjs';

const globals=globalThis as typeof globalThis & { mizzeKeyDemo?: ReturnType<typeof createDatabase>; mizzeKeyLegacyDemo?: ReturnType<typeof createDatabase> };
async function database(demo: boolean) {
  if(!demo)return (await import('./key-admin')).keyDatabase();
  if(!globals.mizzeKeyDemo){
    const pair=policy.credentials('MZ-DEMO-2026','Mizze-Demo-2026!','a'.repeat(64));
    const record=buildRecord({ownerUid:'synthetic-demo',key:'MZ-DEMO-2026',password:'Mizze-Demo-2026!',durationMs:30*86400000,maxDevices:1,label:'MIZZE'},Date.now()).record;
    globals.mizzeKeyDemo=createDatabase({licensesV9:{[pair.licenseId]:record}});
  }
  return globals.mizzeKeyDemo;
}
const messages: Record<string,string>={invalid_request:'Nhập đủ key, mật khẩu và ID máy hợp lệ.',license_denied:'Key hoặc mật khẩu không đúng, đã khóa hoặc hết hạn.',reset_limited:'Đã hết 2 lượt reset hôm nay. Thử lại sau 00:00.',device_not_found:'Chưa có thiết bị để reset.',idempotency_conflict:'Hãy tải lại trang rồi thử lại.',unauthorized:'Vui lòng nhập lại key và mật khẩu.',rate_limited:'Thử lại sau một phút.'};
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
async function rate(db: any, name: string, limit: number) {
  const now=Date.now(),window=Math.floor(now/60000),key=createHmac('sha256',secret('MIZZE_SESSION_SECRET')).update(name).digest('hex');
  const result=await db.ref('_mizzeKeyWebRate/'+key).transaction((r:any)=>{
    if(!r||r.window!==window)return {window,count:1,updatedAt:now};
    if(!Number.isInteger(r.count)||r.count>=limit)return;
    return {window,count:r.count+1,updatedAt:now};
  });if(!result.committed)throw new AppError('rate_limited',429);
}
async function handleKey(request: NextRequest, action: 'session'|'login'|'logout'|'licenses'|'reset') {
  const secure=request.nextUrl.protocol==='https:',names=cookieNames(secure),csrf=request.cookies.get(names.csrf)?.value||randomBytes(32).toString('hex');
  let next:KeySession|null=null,response:NextResponse;
  try {
    const demo=demoEnabled(request.nextUrl.hostname);
    if(!secure&&!['127.0.0.1','localhost','[::1]'].includes(request.nextUrl.hostname))throw new AppError('https_required',403);
    let body:Record<string,unknown>={};
    if(request.method!=='GET'){
      const host=request.headers.get('host'),origin=host?new URL(`${secure?'https':'http'}://${host}`).origin:request.nextUrl.origin;
      assertCsrf(request.headers.get('origin'),origin,request.headers.get('x-csrf-token'),request.cookies.get(names.csrf)?.value);
      if(!/^application\/json(?:;|$)/i.test(request.headers.get('content-type')||'')||Number(request.headers.get('content-length'))>2048)throw new AppError('invalid_request',400);
      const reader=request.body?.getReader();let bytes=0;const chunks:Uint8Array[]=[];
      if(reader)for(;;){const part=await reader.read();if(part.done)break;bytes+=part.value.length;if(bytes>2048){await reader.cancel();throw new AppError('invalid_request',413);}chunks.push(part.value);}
      try{body=JSON.parse(Buffer.concat(chunks).toString());}catch{throw new AppError('invalid_request',400);}
      if(!body||typeof body!=='object'||Array.isArray(body))throw new AppError('invalid_request',400);
    }
    const session=open(request.cookies.get(names.session)?.value);
    if(action==='session'){
      // Status checks use the durable session registry when a cookie exists.
      let authenticated=false;
      if(session){const db=await database(demo),saved=(await db.ref('_mizzeKeyWebSessions/'+hash(session.sid)).get()).val();authenticated=!!saved&&saved.licenseId===session.licenseId&&saved.expiresAt>Date.now()&&saved.revokedAt===0;}
      response=NextResponse.json({authenticated,csrfToken:csrf,demo});
    }else{
      const db=await database(demo);
      if(action==='login'){
        if(Object.keys(body).some(k=>!['key','password','deviceId'].includes(k)))throw new AppError('invalid_request',400);
        const pair=policy.credentials(body.key,body.password,body.deviceId),ip=request.headers.get('x-vercel-forwarded-for')||request.headers.get('x-forwarded-for')?.split(',')[0]||request.nextUrl.hostname;
        await rate(db,'login-ip:'+ip,30);await rate(db,'login-key:'+String(body.key).trim().toUpperCase(),10);
        await ensureKey(db,async()=>demo?(globals.mizzeKeyLegacyDemo||null):(await import('./key-admin')).legacyKeyDatabase(),pair.licenseId);
        let failure:any;
        const result=await db.ref('licensesV9/'+pair.licenseId).transaction((record:any)=>{
          if(record===null)return null;
          try{return policy.activateForKey(record,pair.deviceId,Date.now());}catch(e){failure=e;return;}
        });
        if(!result.committed||!result.snapshot.val())throw failure||new AppError('license_denied',403);
        const now=Date.now();next={sid:randomBytes(32).toString('hex'),licenseId:pair.licenseId,deviceId:pair.deviceId,createdAt:now,expiresAt:now+TTL};
        await db.ref('_mizzeKeyWebSessions/'+hash(next.sid)).set({licenseId:next.licenseId,createdAt:now,expiresAt:next.expiresAt,revokedAt:0});
        response=NextResponse.json({license:policy.dto(result.snapshot.val(),next.deviceId,now)});
      }else{
        if(!session)throw new AppError('unauthorized',401);
        const ref=db.ref('_mizzeKeyWebSessions/'+hash(session.sid)),saved=(await ref.get()).val();
        if(!saved||saved.licenseId!==session.licenseId||saved.expiresAt<=Date.now()||saved.revokedAt!==0)throw new AppError('unauthorized',401);
        if(action==='logout'){
          await ref.update({revokedAt:Date.now()});response=NextResponse.json({ok:true});response.cookies.set(names.session,'',{secure,httpOnly:true,sameSite:'strict',path:'/',maxAge:0});
        }else if(action==='licenses'){
          const record=(await db.ref('licensesV9/'+session.licenseId).get()).val();if(!record)throw new AppError('license_denied',403);
          response=NextResponse.json({license:policy.dto(record,session.deviceId,Date.now())});
        }else{
          if(Object.keys(body).some(k=>!['deviceId','operationId'].includes(k)))throw new AppError('invalid_request',400);
          const id=typeof body.deviceId==='string'?body.deviceId.trim().toLowerCase():'';let failure:any;
          await rate(db,'reset:'+session.licenseId,15);
          const result=await db.ref('licensesV9/'+session.licenseId).transaction((record:any)=>{
            if(record===null)return null;
            try{return policy.resetForKey(record,id,body.operationId,Date.now());}catch(e){failure=e;return;}
          });
          if(!result.committed||!result.snapshot.val())throw failure||new AppError('license_denied',403);
          next={...session,deviceId:id};response=NextResponse.json({license:policy.dto(result.snapshot.val(),id,Date.now())});
        }
      }
    }
  }catch(error){
    const detail=error as {code?:string;status?:number},code=detail?.code&&/^[a-z_]+$/.test(detail.code)?detail.code:'service_unavailable';
    response=NextResponse.json({error:{code,message:messages[code]||'Chưa thể kết nối. Vui lòng thử lại.'}},{status:[400,401,403,409,413,429].includes(detail?.status||0)?detail.status:503});
    next=null;if(detail?.status===401)response.cookies.set(names.session,'',{secure,httpOnly:true,sameSite:'strict',path:'/',maxAge:0});
  }
  if(next)response.cookies.set(names.session,seal(next),{secure,httpOnly:true,sameSite:'strict',path:'/',maxAge:Math.max(0,Math.floor((next.expiresAt-Date.now())/1000))});
  response.cookies.set(names.csrf,csrf,{secure,httpOnly:true,sameSite:'strict',path:'/',maxAge:86400});response.headers.set('Cache-Control','no-store');response.headers.set('Vary','Cookie');return response;
}
export async function dispatchKey(request: NextRequest, action: 'session'|'login'|'logout'|'licenses'|'reset') {
  let timer:ReturnType<typeof setTimeout>|undefined;
  try{return await Promise.race([handleKey(request,action),new Promise<NextResponse>(resolve=>{timer=setTimeout(()=>resolve(NextResponse.json({error:{code:'service_unavailable',message:'Kết nối chậm. Vui lòng thử lại.'}},{status:503,headers:{'Cache-Control':'no-store'}})),20000);})]);}
  finally{clearTimeout(timer);}
}
