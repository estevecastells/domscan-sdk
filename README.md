# DomScan SDKs

Public home for the official DomScan API client libraries.

## Official SDKs

- [Node.js / TypeScript SDK](./node)
- [Python SDK](./python)
- [Go SDK](./go)
- [Ruby SDK](./ruby)
- [PHP SDK](./php)
- [Java SDK](./java)
- [C# SDK](./csharp)
- [Kotlin SDK](./kotlin)
- [Swift SDK](./swift)
- [Rust SDK](./rust)

## Package Names

- Node.js / TypeScript: `@domscan/sdk`
- Python: `domscan-sdk`
- Go module: `github.com/estevecastells/domscan-sdk/go`
- Ruby gem: `domscan-sdk`
- PHP package: `estevecastells/domscan-sdk`
- Java artifact: `net.domscan:domscan-sdk-java`
- C# package: `DomScan.Sdk`
- Kotlin artifact: `net.domscan:domscan-sdk-kotlin`
- Swift package: `DomScan`
- Rust crate: `domscan-sdk`

## Included Resources

- [API Docs](https://domscan.net/docs)
- [OpenAPI spec](https://domscan.net/v1/openapi.json)
- [Swagger spec](https://domscan.net/v1/swagger.json)
- [Postman collection](https://domscan.net/v1/postman.json)
- [MCP integration](https://domscan.net/mcp-domain-checker)

## Notes

- These SDKs are generated from DomScan's internal API registry and synced into this public repository.
- The public packages currently cover 79 public non-session endpoints across availability, DNS, WHOIS, security, pricing, recipes, and intelligence workflows.
- The committed `manifest/endpoints.json` file is the public endpoint source used to render the generated SDK packages in this repository.
