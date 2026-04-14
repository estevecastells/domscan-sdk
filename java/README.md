# DomScan Java SDK

Official Java client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
mvn dependency:get -Dartifact=net.domscan:domscan-sdk-java:0.1.0
```

## Quick Start

```java
import java.util.List;
import java.util.Map;
import net.domscan.DomScanClient;

DomScanClient client = new DomScanClient();
String response = client.availability.checkDomainAvailability(Map.of(
    "name", "launch",
    "tlds", List.of("com", "io", "ai"),
    "prefer_cache", true
));
System.out.println(response);
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)

## Notes

- The Java SDK currently returns raw JSON strings for responses to keep the dependency footprint minimal.
