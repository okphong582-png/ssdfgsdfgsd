import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { credentials } from '../backend/key-access.cjs';
test('web accepts new 8-character bot credentials without changing long-key hashes or device validation',()=>{
  const expected=createHash('sha256').update('mizze-pair-v1\n8:ABCD2345\n8:WXYZ6789').digest('hex');
  assert.equal(credentials(' abcd2345 ','WXYZ6789','a'.repeat(64)).licenseId,expected);
  assert.throws(()=>credentials('ABCD2345','WXYZ678','a'.repeat(64)));
  assert.throws(()=>credentials('ABCD2345','WXYZ6789','wrong-device'));
  assert.doesNotThrow(()=>credentials('MZ10-LEGACY-KEY-123456','Legacy-password-0123456789','a'.repeat(64)));
});
