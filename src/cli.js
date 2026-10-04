#!/usr/bin/env node
import { readFile } from 'node:fs/promises';import { auditHar } from './index.js';
const args=process.argv.slice(2),file=args.find(x=>!x.startsWith('--'));
if(!file||args.includes('--help')){console.log('Usage: har-idempotency-audit FILE.har [--require-key] [--include-put-delete] [--json]');process.exit(file?0:2)}
try{const methods=args.includes('--include-put-delete')?['POST','PATCH','PUT','DELETE']:['POST','PATCH'];const r=auditHar(JSON.parse(await readFile(file,'utf8')),{methods,requireKey:args.includes('--require-key')});if(args.includes('--json'))console.log(JSON.stringify(r,null,2));else{console.log(`${r.mutationCount} mutation(s), ${r.findingCount} finding(s)`);for(const f of r.findings)console.log(`${f.severity.toUpperCase()}\t${f.kind}\t${f.method||''} ${f.url||''}\t${f.count||1}`)}process.exitCode=r.findingCount?1:0}catch(e){console.error(`har-idempotency-audit: ${e.message}`);process.exitCode=2}
