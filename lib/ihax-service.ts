import 'server-only';
import { createIhaxService } from '../backend/ihax-service.cjs';
import { keyDatabase } from './key-admin';
import { secret } from './security';
let service: ReturnType<typeof createIhaxService> | undefined;
export function ihaxService() {
  return service ??= createIhaxService({ database: keyDatabase(), rateSecret: secret('MIZZE_SESSION_SECRET') });
}
