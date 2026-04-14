# DomScan C# SDK

Official C# client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
dotnet add package DomScan.Sdk
```

## Quick Start

```csharp
using DomScan;

var client = new DomScanClient();
var response = await client.Availability.CheckDomainAvailabilityAsync(new Dictionary<string, object?>
{
    ["name"] = "launch",
    ["tlds"] = new[] { "com", "io", "ai" },
    ["prefer_cache"] = true,
});

Console.WriteLine(response);
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)
