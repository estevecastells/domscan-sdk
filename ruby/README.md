# DomScan Ruby SDK

Official Ruby client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
bundle add domscan-sdk
```

## Quick Start

```ruby
require "domscan"

client = DomScan::Client.new
response = client.availability.check_domain_availability(
  "name" => "launch",
  "tlds" => ["com", "io", "ai"],
  "prefer_cache" => true
)

puts response
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)
