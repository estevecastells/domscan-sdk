# DomScan Go SDK

Official Go client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

```bash
go get github.com/estevecastells/domscan-sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"

    domscan "github.com/estevecastells/domscan-sdk/go/domscan"
)

func main() {
    client := domscan.NewClient(nil)
    response, err := client.Availability.CheckDomainAvailability(context.Background(), domscan.Params{
        "name": "launch",
        "tlds": []string{"com", "io", "ai"},
        "prefer_cache": true,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(response)
}
```

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)

## Notes

- Responses are decoded into Go `any` values via the standard `encoding/json` package.
