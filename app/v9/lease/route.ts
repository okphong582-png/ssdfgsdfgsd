import { NextRequest } from 'next/server';
import { leaseRequest } from '@/lib/game-http';
export const runtime='nodejs';
export const maxDuration=15;
export function POST(request:NextRequest){return leaseRequest(request);}
