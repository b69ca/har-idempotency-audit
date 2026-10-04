import { createHash } from 'node:crypto';
const hash=value=>createHash('sha256').update(value).digest('hex').slice(0,12);
const header=(headers,name)=>(headers||[]).find(h=>String(h.name).toLowerCase()===name)?.value||null;
const safeUrl=raw=>{try{const u=new URL(raw);u.search='';u.hash='';return u.toString()}catch{return raw}};
const groupBy=(values,keyOf)=>{const out=new Map();for(const value of values){const key=keyOf(value),group=out.get(key)||[];group.push(value);out.set(key,group)}return out};
const canonical=value=>Array.isArray(value)?`[${value.map(canonical).join(',')}]`:value!==null&&typeof value==='object'?`{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`:JSON.stringify(value);
function bodyOf(entry){const text=entry?.request?.postData?.text||'';try{return canonical(JSON.parse(text))}catch{return text}}
export function auditHar(har,{methods=['POST','PATCH'],requireKey=false}={}){
  const entries=har?.log?.entries;if(!Array.isArray(entries))throw new Error('not a HAR document: log.entries is missing');
  const requests=[];
  for(const [index,entry] of entries.entries()){
    const method=String(entry?.request?.method||'').toUpperCase();if(!methods.includes(method))continue;
    const url=safeUrl(entry.request.url),bodyHash=hash(bodyOf(entry)),key=header(entry.request.headers,'idempotency-key')||header(entry.request.headers,'x-idempotency-key');
    const responseText=entry?.response?.content?.text||'';
    requests.push({index,method,url,bodyHash,key,status:entry?.response?.status,responseHash:hash(`${entry?.response?.status}:${responseText}`)});
  }
  const findings=[];
  const byRequest=groupBy(requests,r=>`${r.method}\0${r.url}\0${r.bodyHash}`);
  for(const group of byRequest.values()){
    if(group.length>1&&group.some(r=>!r.key))findings.push({severity:'warning',kind:'repeated-without-key',method:group[0].method,url:group[0].url,bodyHash:group[0].bodyHash,count:group.length,missingKey:group.filter(r=>!r.key).length});
    const keyed=group.filter(r=>r.key);for(const [key,replays] of groupBy(keyed,r=>r.key))if(replays.length>1&&new Set(replays.map(r=>r.responseHash)).size>1)findings.push({severity:'critical',kind:'inconsistent-keyed-replay',method:group[0].method,url:group[0].url,keyHash:hash(key),count:replays.length,statuses:[...new Set(replays.map(r=>r.status))]});
  }
  const byKey=groupBy(requests.filter(r=>r.key),r=>r.key);
  for(const [key,group] of byKey)if(new Set(group.map(r=>`${r.method}\0${r.url}\0${r.bodyHash}`)).size>1)findings.push({severity:'critical',kind:'key-reused-for-different-request',keyHash:hash(key),count:group.length,requests:group.map(r=>({method:r.method,url:r.url,bodyHash:r.bodyHash}))});
  if(requireKey)for(const r of requests)if(!r.key)findings.push({severity:'warning',kind:'missing-key',method:r.method,url:r.url,bodyHash:r.bodyHash,index:r.index});
  const counts={critical:findings.filter(f=>f.severity==='critical').length,warning:findings.filter(f=>f.severity==='warning').length};
  return {entryCount:entries.length,mutationCount:requests.length,findingCount:findings.length,counts,findings};
}
