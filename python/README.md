# DomScan Python SDK

Official Python client for the [DomScan API](https://domscan.net/docs).

The SDK is generated from DomScan's endpoint registry and OpenAPI contract, so the public client surface stays aligned with the current availability, DNS, WHOIS, security, pricing, recipes, and intelligence operations.

## Installation

Install the latest release directly from GitHub:

```bash
python -m pip install https://github.com/estevecastells/domscan-sdk/releases/latest/download/domscan-sdk-python.tar.gz
```

## Typed quickstart

The package includes generated type hints for supported parameters and response shapes.

```python
from domscan import DomScan

domscan = DomScan()

result = domscan.availability.check_domain_availability(
    name="launch",
    tlds="com,io,ai",
    prefer_cache=True,
)

print(result["results"])
```

The client reads `DOMSCAN_API_KEY` automatically. You can also pass `api_key` to the constructor.

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

```python
health = client.domain.get_domain_health(domain="cloudflare.com")
print(health["enriched"]["tls"]["grade"])
print(health["enriched"]["hsts"]["preload_status"])

dns_security = client.dns.get_dns_security(domain="google.com")
print(dns_security["mta_sts"]["policy_matches_mx"])
print(dns_security["resolver_latency"]["avg_ms"])

ip_info = client.osint.get_ip_info(domain="openai.com")
print(ip_info["security"]["type_classification"])
print(ip_info["security"]["fcrdns"])
```

## Full-response metadata

Methods return response data by default. Pass `_with_response=True` when you also need request, credit, rate-limit, or freshness metadata.

```python
response = domscan.availability.check_domain_availability(
    name="launch",
    tlds="com,io,ai",
    prefer_cache=True,
    _with_response=True,
)

print(response.data["results"])
print(response.request_id)
print(response.credits_charged)
print(response.credits_remaining)
print(response.rate_limit_remaining)
print(response.freshness)
```

## Error handling

Use the structured error fields instead of matching error messages.

```python
from domscan import DomScanAPIError

try:
    domscan.domain.get_domain_value(domain="example.com")
except DomScanAPIError as error:
    print({
        "type": error.error_type,
        "code": error.code,
        "status": error.status,
        "retryable": error.retryable,
        "retry_after": error.retry_after,
        "request_id": error.request_id,
        "docs_url": error.docs_url,
    })
```

## Retries and idempotency

The SDK retries eligible GET requests up to two times by default when a network request fails, times out, or the API marks an error as retryable. It honors `Retry-After` when the API provides it.

Non-GET requests are attempted once unless you supply an idempotency key:

```python
from uuid import uuid4

domscan = DomScan(max_retries=2)

result = domscan.domain.bulk_domain_value(
    domains=["example.com", "example.net"],
    _idempotency_key=str(uuid4()),
    _max_retries=2,
)
```

Set `max_retries=0` globally or `_max_retries=0` per request to disable retries.

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- Repo hub: [../README.md](../README.md)
