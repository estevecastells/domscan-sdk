# DomScan Python SDK

Official Python client for the [DomScan API](https://domscan.net/docs).

The SDK is generated from DomScan's endpoint registry, so the public client surface stays aligned with the live API. This release exposes 79 public endpoints across availability, DNS, WHOIS, security, pricing, recipes, and intelligence workflows.

## Installation

```bash
pip install domscan-sdk
```

## Quick Start

```python
from domscan import DomScan

client = DomScan()

availability = client.availability.check_domain_availability(
    name="launch",
    tlds=["com", "io", "ai"],
    prefer_cache=True,
)

print(availability)
```

The client reads `DOMSCAN_API_KEY` automatically if you do not pass `api_key`.

## Configuration

```python
client = DomScan(
    api_key="dsk_your_key_here",
    base_url="https://domscan.net",
    timeout=15.0,
)
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

```python
whois = client.osint.get_whois(domain="openai.com")
dns = client.dns.get_dns_records(domain="openai.com", type="MX")
prices = client.pricing.get_tld_pricing(tld="ai")
```

## Error Handling

```python
from domscan import DomScan, DomScanAPIError

client = DomScan()

try:
    client.domain.get_domain_value(domain="example.com")
except DomScanAPIError as error:
    print(error.status, error.code, error.details)
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- Repo hub: [../README.md](../README.md)
