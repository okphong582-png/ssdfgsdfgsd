import { NextRequest,NextResponse } from 'next/server';
import { validateRequest } from '../../../backend/service-v10.cjs';
import { gameServiceV10 } from '../../../lib/game-license-v10';
export const runtime='nodejs';
export const maxDuration=15;
export async function POST(request:NextRequest){
 const reply=(status:number,value:unknown)=>NextResponse.json(value,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
 if(!/^application\/json(?:;|$)/i.test(request.headers.get('content-type')||''))return reply(400,{error:'invalid_request'});
 let timer:ReturnType<typeof setTimeout>|undefined;
 try{
  if(Number(request.headers.get('content-length'))>1024)return reply(413,{error:'invalid_request'});
  const reader=request.body?.getReader(),chunks:Uint8Array[]=[];let size=0;
  if(reader)for(;;){const part=await reader.read();if(part.done)break;size+=part.value.length;if(size>1024){await reader.cancel();return reply(413,{error:'invalid_request'});}chunks.push(part.value);}
  const body=validateRequest(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  const ip=request.headers.get('x-vercel-forwarded-for')||request.headers.get('x-forwarded-for')?.split(',')[0]||'unknown';
  const result=await Promise.race([gameServiceV10()(body,ip),new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(Error('upstream_timeout')),8000);})]);
  return result.status===200?reply(200,result.envelope):reply(result.status,{error:result.error});
 }catch(error){const invalid=error instanceof SyntaxError||(error as Error)?.message==='invalid_request';return reply(invalid?400:503,{error:invalid?'invalid_request':'service_unavailable'});}
 finally{clearTimeout(timer);}
}
