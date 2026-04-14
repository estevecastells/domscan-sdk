# DomScan Kotlin SDK

Official Kotlin client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
implementation("net.domscan:domscan-sdk-kotlin:0.1.0")
```

## Quick Start

```kotlin
import net.domscan.DomScanClient

val client = DomScanClient()
val response = client.availability.checkDomainAvailability(
    mapOf(
        "name" to "launch",
        "tlds" to listOf("com", "io", "ai"),
        "prefer_cache" to true,
    )
)

println(response)
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)

## Notes

- The Kotlin SDK currently returns raw JSON strings for responses to stay dependency-light.
