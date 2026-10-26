import { NextResponse } from 'next/server';
export const runtime='nodejs';
export const maxDuration=15;
export async function GET(){
 try{const {gameServiceV10,gameV10Identity}=await import('@/lib/game-license-v10');gameServiceV10();return NextResponse.json({ok:true,protocol:10,kid:gameV10Identity.kid,release:gameV10Identity.release},{headers:{'Cache-Control':'no-store'}});}
 catch{return NextResponse.json({ok:false},{status:503,headers:{'Cache-Control':'no-store'}});}
}
