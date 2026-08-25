# DomScan Node.js SDK

Official Node.js and TypeScript client for the [DomScan API](https://domscan.net/docs).

The SDK is generated from DomScan's endpoint registry and OpenAPI contract, so the public client surface stays aligned with the current availability, DNS, WHOIS, security, pricing, recipes, and intelligence operations.

## Installation

Install the latest release directly from GitHub:

```bash
npm install https://github.com/estevecastells/domscan-sdk/releases/latest/download/domscan-sdk-node.tgz
```

Import the package as `@domscan/sdk`.

## Typed quickstart

The SDK includes generated parameter and response types for every supported operation.

```ts
import {
  DomScan,
  type OperationResponse,
} from '@domscan/sdk';

const domscan = new DomScan();

const result: OperationResponse<'checkDomainAvailability'> =
  await domscan.availability.checkDomainAvailability({
  name: 'launch',
  tlds: 'com,io,ai',
  prefer_cache: true,
});

console.log(result.results);
```

The client reads `DOMSCAN_API_KEY` automatically. You can also pass `apiKey` to the constructor.

## Configuration

```ts
const client = new DomScan({
  apiKey: process.env.DOMSCAN_API_KEY,
  baseUrl: 'https://domscan.net',
  timeout: 15_000,
});
```

## Namespaces

- `availability`
- `domain`
- `dns`
- `security`
- `intelligence`
- `social`
- `osint`
- `pricing`
- `recipes`
- `meta`

## Examples

```ts
const whois = await client.osint.getWhois({
  domain: 'openai.com',
});

const dns = await client.dns.getDnsRecords({
  domain: 'openai.com',
  type: 'MX',
});

const prices = await client.pricing.getTldPricing({
  tld: 'ai',
});
```

```ts
const health = await client.domain.getDomainHealth({
  domain: 'cloudflare.com',
});

console.log(health.enriched?.tls?.grade);
console.log(health.enriched?.hsts?.preload_status);

const dnsSecurity = await client.dns.getDnsSecurity({
  domain: 'google.com',
});

console.log(dnsSecurity.mta_sts?.policy_matches_mx);
console.log(dnsSecurity.resolver_latency?.avg_ms);

const ipInfo = await client.osint.getIpInfo({
  domain: 'openai.com',
});

console.log(ipInfo.security?.type_classification);
console.log(ipInfo.security?.fcrdns);
```

## Full-response metadata

Methods return response data by default. Pass `withResponse: true` when you also need request, credit, rate-limit, or freshness metadata.

```ts
const response =
  await domscan.availability.checkDomainAvailability(
    {
      name: 'launch',
      tlds: 'com,io,ai',
      prefer_cache: true,
    },
    { withResponse: true },
  );

console.log(response.data.results);
console.log(response.meta.requestId);
console.log(response.meta.credits);
console.log(response.meta.rateLimit);
console.log(response.meta.freshness);
```

## Error handling

Use the structured error fields instead of matching error messages.

```ts
import { DomScanAPIError } from '@domscan/sdk';

try {
  await domscan.domain.getDomainValue({
    domain: 'example.com',
  });
} catch (error) {
  if (error instanceof DomScanAPIError) {
    console.error({
      type: error.type,
      code: error.code,
      status: error.status,
      retryable: error.retryable,
      retryAfter: error.retryAfter,
      requestId: error.requestId,
      docsUrl: error.docsUrl,
    });
  } else {
    throw error;
  }
}
```

## Retries and idempotency

The SDK retries eligible GET requests up to two times by default when a network request fails, times out, or the API marks an error as retryable. It honors `Retry-After` when the API provides it.

Non-GET requests are attempted once unless you supply an idempotency key:

```ts
const domscan = new DomScan({
  maxRetries: 2,
});

const result = await domscan.domain.bulkDomainValue(
  {
    domains: ['example.com', 'example.net'],
  },
  {
    idempotencyKey: crypto.randomUUID(),
    maxRetries: 2,
  },
);
```

Set `maxRetries: 0` globally or per request to disable retries.

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- Repo hub: [../README.md](../README.md)
