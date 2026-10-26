'use strict';
const HEX=/^[a-f0-9]{64}$/;
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const plain=o=>!!o&&typeof o==='object'&&!Array.isArray(o);
const uid=s=>typeof s==='string'&&s.length>0&&s.length<=128&&!/[\u0000-\u0020]/.test(s);
const operationId=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{16,128}$/.test(s);
const hasPortal=record=>!!record&&own(record,'portal');
function validPortal(record,now){
 if(!hasPortal(record))return true;
 const p=record.portal;
 if(!plain(p)||Object.keys(p).some(k=>!['v','ownerUid','bindingVersion','resetHistory','lastResetAt','operations','label'].includes(k))||
 p.v!==1||!uid(p.ownerUid)||!Number.isSafeInteger(p.bindingVersion)||p.bindingVersion<1||
 !Number.isSafeInteger(p.lastResetAt)||p.lastResetAt<0||p.lastResetAt>now||
 (p.label!==undefined&&(typeof p.label!=='string'||p.label.length>120)))return false;
 const history=p.resetHistory===undefined||p.resetHistory===null?[]:p.resetHistory;
 if(!Array.isArray(history)||history.length>2||history.some(t=>!Number.isSafeInteger(t)||t<=0||t>now)||
 history.some((t,i)=>i>0&&t<history[i-1])||(history.length&&history.at(-1)!==p.lastResetAt))return false;
 const ops=p.operations===undefined||p.operations===null?{}:p.operations;
 if(!plain(ops)||Object.keys(ops).length>32)return false;
 for(const [id,op]of Object.entries(ops))if(!operationId(id)||!plain(op)||Object.keys(op).some(k=>!['type','deviceId','at'].includes(k))||
 !['activate','reset','logout'].includes(op.type)||!HEX.test(op.deviceId)||!Number.isSafeInteger(op.at)||op.at<=0||op.at>now)return false;
 for(const device of Object.values(record.devices||{}))if(!plain(device)||typeof device.portalLoggedOut!=='boolean'||
 !Number.isSafeInteger(device.portalApprovedAt)||device.portalApprovedAt<=0||device.portalApprovedAt>now||
 !Number.isSafeInteger(device.portalBindingVersion)||device.portalBindingVersion<1||device.portalBindingVersion>p.bindingVersion||
 Object.keys(device).some(k=>!['version','claimedAt','portalLoggedOut','portalApprovedAt','portalBindingVersion'].includes(k)))return false;
 return true;
}
module.exports={HEX,own,plain,uid,operationId,hasPortal,validPortal};
