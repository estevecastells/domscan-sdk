# DomScan Swift SDK

Official Swift client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
Add https://github.com/estevecastells/domscan-sdk.git and use the `DomScan` product
```

## Quick Start

```swift
import DomScan

let client = DomScanClient()
let response = try await client.availability.checkDomainAvailability([
    "name": "launch",
    "tlds": ["com", "io", "ai"],
    "prefer_cache": true,
])

print(response)
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)
