# DomScan Node.js SDK

Official Node.js and TypeScript client for the [DomScan API](https://domscan.net/docs).

The SDK is generated from DomScan's endpoint registry, so the public client surface stays aligned with the live API. This release exposes 79 public endpoints across availability, DNS, WHOIS, security, pricing, recipes, and intelligence workflows.

## Installation

```bash
npm install @domscan/sdk
```

## Quick Start

```ts
import { DomScan } from '@domscan/sdk';

const client = new DomScan({
  apiKey: process.env.DOMSCAN_API_KEY,
});

const availability = await client.availability.checkDomainAvailability({
  name: 'launch',
  tlds: ['com', 'io', 'ai'],
  prefer_cache: true,
});

console.log(availability);
```

## Configuration

```ts
const client = new DomScan({
  apiKey: process.env.DOMSCAN_API_KEY,
  baseUrl: 'https://domscan.net',
  timeout: 15_000,
});
```

The client reads `DOMSCAN_API_KEY` automatically if you do not pass `apiKey`.

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

## Error Handling

```ts
import { DomScan, DomScanAPIError } from '@domscan/sdk';

const client = new DomScan({ apiKey: process.env.DOMSCAN_API_KEY });

try {
  await client.domain.getDomainValue({ domain: 'example.com' });
} catch (error) {
  if (error instanceof DomScanAPIError) {
    console.error(error.status, error.code, error.details);
  }
}
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- Repo hub: [../README.md](../README.md)
