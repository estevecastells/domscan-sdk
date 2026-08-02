# DomScan Node.js SDK

Official Node.js and TypeScript client for the [DomScan API](https://domscan.net/docs).

The SDK is generated from DomScan's endpoint registry, so the public client surface stays aligned with the live API. Version 0.2.0 exposes 113 public non-session endpoints across availability, DNS, WHOIS, security, pricing, recipes, and intelligence workflows.

## Installation

```bash
npm install https://github.com/estevecastells/domscan-sdk/releases/latest/download/domscan-sdk-node.tgz
```

The GitHub release tarball is the supported installation path for this version. The npm package name is reserved but is not yet published to the public registry.

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

const popularity = await client.domain.getDomainPopularity({
  domain: 'openai.com',
  include_history: true,
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
- Releases: [https://github.com/estevecastells/domscan-sdk/releases](https://github.com/estevecastells/domscan-sdk/releases)
- Repo hub: [../README.md](../README.md)
