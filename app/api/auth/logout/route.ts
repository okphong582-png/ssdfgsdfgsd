import { NextRequest } from 'next/server';
import { dispatchKey } from '@/lib/key-http';
export const runtime = 'nodejs';
export const maxDuration = 30;
export function POST(request: NextRequest) { return dispatchKey(request, 'logout'); }
