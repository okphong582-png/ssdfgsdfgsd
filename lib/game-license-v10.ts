import 'server-only';
import { createHash,createPrivateKey,createPublicKey } from 'node:crypto';
import { createService } from '../backend/service-v10.cjs';
import { keyDatabase } from './key-admin';
import identity from '../backend/game-license-v10.public.json';
let service: ReturnType<typeof createService> | undefined;
export function gameServiceV10(){
 if(service)return service;
 const raw=process.env.MIZZE_LICENSE_V10_PRIVATE_KEY_BASE64;
 if(!raw||!/^[A-Za-z0-9+/]+={0,2}$/.test(raw))throw Error('signer_not_configured');
 const pem=Buffer.from(raw,'base64').toString('utf8');
 const key=createPrivateKey(pem);
 if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength!==3072||
   createHash('sha256').update(createPublicKey(key).export({format:'der',type:'spki'})).digest('hex')!==identity.kid)throw Error('signer_identity_mismatch');
 service=createService({database:keyDatabase(),signingKey:()=>pem});
 return service;
}
export const gameV10Identity=identity;
