# har-idempotency-audit

Audit a HAR capture for repeated POST/PATCH requests without idempotency keys, one key reused for different requests, and keyed replays that produced inconsistent responses.

```sh
npx --yes github:b69ca/har-idempotency-audit traffic.har
npx --yes github:b69ca/har-idempotency-audit traffic.har --require-key --json
```

Request bodies, response bodies, keys, query strings and fragments are never printed. The report uses short SHA-256 identifiers to correlate equality. `--include-put-delete` expands the default POST/PATCH scope; `--require-key` reports every unkeyed mutation. Findings exit 1 and invalid input exits 2.

This is a capture consistency check, not proof that a server implements idempotency correctly. Generic HAR tools display traffic; this utility looks specifically for replay hazards across the capture. Zero dependencies, Node.js 20+, MIT licensed.
