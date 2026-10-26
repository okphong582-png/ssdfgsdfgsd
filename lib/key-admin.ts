import 'server-only';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { AppError } from './security';
export function keyDatabase() {
  let account;
  try { account=JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON || ''); } catch { throw new AppError('not_configured',503,'Website đang chờ cấu hình Firebase.'); }
  const project=process.env.FIREBASE_PROJECT_ID,url=new URL(process.env.FIREBASE_DATABASE_URL || 'https://invalid.local');
  if(!project||account.type!=='service_account'||account.project_id!==project||account.token_uri!=='https://oauth2.googleapis.com/token'||
    typeof account.client_email!=='string'||!account.client_email.endsWith(`@${project}.iam.gserviceaccount.com`)||
    url.protocol!=='https:'||url.username||url.password||url.port||url.pathname!=='/'||url.search||url.hash||!/\.(firebaseio\.com|firebasedatabase\.app)$/.test(url.hostname))throw new AppError('not_configured',503);
  const app=getApps().find(app=>app.name==='mizze-key-access')||initializeApp({credential:cert(account),projectId:project,databaseURL:url.origin},'mizze-key-access');
  return getDatabase(app);
}
