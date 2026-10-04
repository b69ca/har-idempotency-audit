import test from 'node:test';import assert from 'node:assert/strict';import { auditHar } from '../src/index.js';
const entry=(body,key,status=200,response='ok')=>({request:{method:'POST',url:'https://api.test/pay?token=x',headers:key?[{name:'Idempotency-Key',value:key}]:[],postData:{text:JSON.stringify(body)}},response:{status,content:{text:response}}});
const har=entries=>({log:{entries}});
test('finds repeated unkeyed mutations',()=>assert.equal(auditHar(har([entry({a:1}),entry({a:1})])).findings[0].kind,'repeated-without-key'));
test('finds key reuse across bodies',()=>assert.ok(auditHar(har([entry({a:1},'k'),entry({a:2},'k')])).findings.some(f=>f.kind==='key-reused-for-different-request')));
test('finds inconsistent keyed replay',()=>assert.ok(auditHar(har([entry({a:1},'k',200,'a'),entry({a:1},'k',409,'b')])).findings.some(f=>f.kind==='inconsistent-keyed-replay')));
test('strips query values',()=>assert.equal(auditHar(har([entry({a:1})]),{requireKey:true}).findings[0].url,'https://api.test/pay'));
