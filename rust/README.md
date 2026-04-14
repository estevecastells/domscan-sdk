# DomScan Rust SDK

Official Rust client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
cargo add domscan-sdk
```

## Quick Start

```rust
use serde_json::{json, Map, Value};

let client = domscan_sdk::DomScanClient::new(None);
let mut params = Map::new();
params.insert("name".into(), Value::String("launch".into()));
params.insert("tlds".into(), json!(["com", "io", "ai"]));
params.insert("prefer_cache".into(), Value::Bool(true));

let response = client.availability().check_domain_availability(params).await?;
println!("{response}");
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)
