import { NextResponse } from 'next/server';
export const runtime='nodejs';
export const maxDuration=15;
export function POST(){return NextResponse.json({error:'menu_update_required'},{status:410,headers:{'Cache-Control':'no-store'}});}
