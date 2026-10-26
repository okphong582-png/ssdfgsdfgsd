import { NextResponse } from 'next/server';
export const runtime='nodejs';
export const maxDuration=15;
export async function GET(){
 try{const {gameService,gameKeyId}=await import('@/lib/game-license');gameService();return NextResponse.json({ok:true,protocol:9,kid:gameKeyId},{headers:{'Cache-Control':'no-store'}});}
 catch{return NextResponse.json({ok:false},{status:503,headers:{'Cache-Control':'no-store'}});}
}
