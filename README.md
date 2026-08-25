# DomScan SDKs

Public home for the official DomScan API client libraries.

## Official SDKs

| Language | Package | GitHub distribution |
| --- | --- | --- |
| [Node.js / TypeScript](./node) | `@domscan/sdk` | Release tarball |
| [Python](./python) | `domscan-sdk` | Release source archive and wheel |
| [Go](./go) | `github.com/estevecastells/domscan-sdk/go` | Tagged Go module |
| [Ruby](./ruby) | `domscan-sdk` | Release gem |
| [PHP](./php) | `estevecastells/domscan-sdk` | Composer artifact archive |
| [Java](./java) | `net.domscan:domscan-sdk-java` | Release JAR |
| [C#](./csharp) | `DomScan.Sdk` | Release NuGet package |
| [Kotlin](./kotlin) | `net.domscan:domscan-sdk-kotlin` | Release JAR |
| [Swift](./swift) | `DomScan` | Tagged Swift package |
| [Rust](./rust) | `domscan-sdk` | Tagged Git dependency and crate archive |

Package registry publication varies by language. Each language README documents a working GitHub installation path for this release.

## Included Resources

- [API Docs](https://domscan.net/docs)
- [OpenAPI spec](https://domscan.net/v1/openapi.json)
- [Swagger spec](https://domscan.net/v1/swagger.json)
- [Postman collection](https://domscan.net/v1/postman.json)
- [MCP integration](https://domscan.net/mcp-domain-checker)

## Notes

- These SDKs are generated from DomScan's internal API registry and synced into this public repository.
- The public packages currently cover 120 public non-session endpoints across availability, DNS, WHOIS, security, pricing, recipes, and intelligence workflows.
- The committed `manifest/endpoints.json` file is the public endpoint source used to render the generated SDK packages in this repository.
- Run `node scripts/generate-sdks.mjs` after updating the manifest. Continuous integration verifies that generated clients stay current.
