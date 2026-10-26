import 'server-only';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { createService } from '../backend/service-v9.cjs';
import { keyDatabase } from './key-admin';
import identity from '../backend/game-license-public.json';
let service: ReturnType<typeof createService> | undefined;
export function gameService(){
 if(service)return service;
 const encoded=process.env.MIZZE_LICENSE_PRIVATE_KEY_BASE64;
 if(!encoded||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))throw Error('signer_not_configured');
 const pem=Buffer.from(encoded,'base64').toString('utf8'),key=createPrivateKey(pem);
 const kid=createHash('sha256').update(createPublicKey(key).export({type:'spki',format:'der'})).digest('hex');
 if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength!==3072||kid!==identity.kid)throw Error('signer_identity_mismatch');
 service=createService({database:keyDatabase(),signingKey:()=>pem});return service;
}
export const gameKeyId=identity.kid;
