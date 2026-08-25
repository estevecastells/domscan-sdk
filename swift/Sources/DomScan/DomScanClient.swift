import Foundation

public struct EndpointDefinition {
    let method: String
    let path: String
    let pathParams: [String]
    let queryParams: [String]
    let hasBody: Bool
}

public struct DomScanAPIError: Error {
    public let status: Int
    public let code: String?
    public let message: String
    public let details: Any
    public let requestId: String?
}

public final class DomScanClient {
    private let apiKey: String?
    private let baseURL: String
    private let timeout: TimeInterval
    private let userAgent: String
    private let headers: [String: String]

    public lazy var availability: AvailabilityService = AvailabilityService(client: self)
    public lazy var dns: DnsService = DnsService(client: self)
    public lazy var domain: DomainService = DomainService(client: self)
    public lazy var intelligence: IntelligenceService = IntelligenceService(client: self)
    public lazy var meta: MetaService = MetaService(client: self)
    public lazy var osint: OsintService = OsintService(client: self)
    public lazy var pricing: PricingService = PricingService(client: self)
    public lazy var recipes: RecipesService = RecipesService(client: self)
    public lazy var security: SecurityService = SecurityService(client: self)
    public lazy var social: SocialService = SocialService(client: self)
    public lazy var user: UserService = UserService(client: self)

    public init(
        apiKey: String? = ProcessInfo.processInfo.environment["DOMSCAN_API_KEY"],
        baseURL: String = "https://domscan.net",
        timeout: TimeInterval = 10,
        headers: [String: String] = [:],
        userAgent: String = "domscan-swift/0.3.0"
    ) {
        self.apiKey = apiKey
        self.baseURL = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        self.timeout = timeout
        self.headers = headers
        self.userAgent = userAgent
    }

    func request(endpoint: EndpointDefinition, params: [String: Any?]) async throws -> Any {
        var requestPath = endpoint.path
        var remaining = params

        for pathParam in endpoint.pathParams {
            guard let rawValue = remaining.removeValue(forKey: pathParam) ?? nil else {
                throw NSError(domain: "DomScan", code: 0, userInfo: [NSLocalizedDescriptionKey: "Missing required path parameter: \(pathParam)"])
            }
            requestPath = requestPath.replacingOccurrences(of: ":\(pathParam)", with: String(describing: rawValue).addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? "")
        }

        var components = URLComponents(string: baseURL + requestPath)!
        let queryPayload: [String: Any?]
        if endpoint.hasBody {
            queryPayload = remaining.filter { endpoint.queryParams.contains($0.key) && $0.value != nil }
        } else {
            queryPayload = remaining.filter { $0.value != nil }
        }

        if !queryPayload.isEmpty {
            components.queryItems = queryPayload.compactMap { key, value in
                guard let value else { return nil }
                return URLQueryItem(name: key, value: serializeQueryValue(value))
            }
        }

        var request = URLRequest(url: components.url!)
        request.httpMethod = endpoint.method
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(userAgent, forHTTPHeaderField: "X-DomScan-SDK")
        if let apiKey, !apiKey.isEmpty {
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
            request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        }
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        if endpoint.hasBody {
            let bodyPayload = remaining.filter { !endpoint.queryParams.contains($0.key) && $0.value != nil }
                .mapValues { $0! }
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: bodyPayload, options: [])
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        let httpResponse = response as! HTTPURLResponse
        let payload = decodePayload(data)
        if httpResponse.statusCode < 400 {
            return payload
        }

        let errorObject = payload as? [String: Any]
        let nested = errorObject?["error"] as? [String: Any]
        throw DomScanAPIError(
            status: httpResponse.statusCode,
            code: nested?["code"] as? String,
            message: nested?["message"] as? String ?? "DomScan request failed with status \(httpResponse.statusCode)",
            details: payload,
            requestId: httpResponse.value(forHTTPHeaderField: "x-request-id")
        )
    }

    private func decodePayload(_ data: Data) -> Any {
        (try? JSONSerialization.jsonObject(with: data, options: [])) ?? String(data: data, encoding: .utf8) ?? ""
    }

    private func serializeQueryValue(_ value: Any) -> String {
        switch value {
        case let array as [Any]:
            return array.map(serializeQueryValue).joined(separator: ",")
        case let boolean as Bool:
            return boolean ? "true" : "false"
        case let date as Date:
            return ISO8601DateFormatter().string(from: date)
        case let dictionary as [String: Any]:
            if let data = try? JSONSerialization.data(withJSONObject: dictionary, options: []),
               let string = String(data: data, encoding: .utf8) {
                return string
            }
            return ""
        default:
            return String(describing: value)
        }
    }
}

public final class AvailabilityService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Check availability of multiple complete domain names at once.
    public func bulkCheckDomains(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/status/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
    public func checkDomainAvailability(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/status",
                pathParams: [],
                queryParams: ["name", "tlds", "domain", "prefer_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Create a resumable asynchronous search over a curated English single-word corpus sourced from iannuttall/unclaimed under the MIT License. Check each selected word across 1 to 5 supported TLDs, with a hard limit of 100 word-TLD checks per job. Available, registered, and unknown remain distinct outcomes. Jobs use the existing batch status, results, and cancellation lifecycle.
    public func createDomainDiscoveryJob(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/domain-discovery/jobs",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Get information about which TLDs are supported and their RDAP server status.
    public func getCoverage(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/coverage",
                pathParams: [],
                queryParams: ["live"],
                hasBody: false
            ),
            params: params
        )
    }
}

public final class DnsService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Build a DMARC record with policy, reporting, and alignment options.
    public func buildDmarc(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/tools/dmarc/build",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Build an SPF record from configuration options with validation and recommendations.
    public func buildSpf(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/tools/spf/build",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
    public func bulkDnsPropagation(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/dns/propagation/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Check a specific DKIM selector for a domain and validate the public key.
    public func checkDkim(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tools/dkim/check",
                pathParams: [],
                queryParams: ["domain", "selector"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Discover DKIM selectors for a domain by checking common selector names.
    public func discoverDkim(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tools/dkim/discover",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
    public func flattenSpf(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/tools/spf/flatten",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
    public func getAllDnsRecords(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/all",
                pathParams: [],
                queryParams: ["domain", "wildcard_probe"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
    public func getDnsHistory(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/history",
                pathParams: [],
                queryParams: ["domain", "type", "from", "to", "limit"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Compare answers from DomScan's configured public recursive resolvers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
    public func getDnsPropagation(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/propagation",
                pathParams: [],
                queryParams: ["domain", "type", "expected"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
    public func getDnsRecords(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns",
                pathParams: [],
                queryParams: ["domain", "type"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
    public func getDnsSecurity(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/security",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
    public func getDnsServers(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/servers",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Validate a DMARC record for syntax errors and configuration issues.
    public func validateDmarc(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/tools/dmarc/validate",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
    public func validateSpf(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/tools/spf/validate",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }
}

public final class DomainService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Get value estimates for multiple domains at once.
    public func bulkDomainValue(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/value/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    public func bulkGetDomainProfile(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/profile/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Compare up to 50 candidate brand names and return ranked scores.
    public func compareBrandNames(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/score/compare",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Compare two domains side-by-side across multiple metrics and attributes.
    public func compareDomains(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/compare",
                pathParams: [],
                queryParams: ["domains"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Comprehensive health checks with DNS, SSL, email, extended TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
    public func getDomainHealth(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/health",
                pathParams: [],
                queryParams: ["domain", "details"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
    public func getDomainOverview(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/overview",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
    public func getDomainPopularity(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/popularity",
                pathParams: [],
                queryParams: ["domain", "include_history", "history_limit"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
    public func getDomainPopularityHistory(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/popularity/history",
                pathParams: [],
                queryParams: ["domain", "limit"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    public func getDomainProfile(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/profile",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Calculate an overall domain quality score based on multiple factors.
    public func getDomainScore(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/score",
                pathParams: [],
                queryParams: ["name", "domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
    public func getDomainValue(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/value",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Fast health check with essential metrics only.
    public func getQuickHealth(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/health/quick",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Returns scoring dimensions, grade scale, and related scoring endpoints.
    public func getScoreInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/score/info",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get detailed information about a specific TLD.
    public func getTldDetail(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tlds/:tld",
                pathParams: ["tld"],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get list of all supported TLDs with metadata.
    public func getTlds(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tlds",
                pathParams: [],
                queryParams: ["type", "trust_tier", "use_case"],
                hasBody: false
            ),
            params: params
        )
    }

    /// AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
    public func suggestDomains(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/suggest",
                pathParams: [],
                queryParams: ["keywords", "tlds", "style", "industry", "language", "limit", "check"],
                hasBody: false
            ),
            params: params
        )
    }
}

public final class IntelligenceService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
    public func bulkGetHosting(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/hosting/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
    public func bulkGetUrlIntelligence(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/url-intelligence/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
    public func bulkGetWebsiteIdentityAssets(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/identity-assets/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
    public func bulkResolveInternetIdentity(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/identity-resolution/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Cancel unstarted technology scan work and settle item-level refunds. Work already in progress may finish and remains available in the job results.
    public func cancelTechScanJob(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "DELETE",
                path: "/v1/tech/jobs/:job_id",
                pathParams: ["job_id"],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
    public func categorizeWebsite(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/categorize",
                pathParams: [],
                queryParams: ["url", "domain", "skip_cache", "min_confidence"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Categorize up to 10 websites in parallel with caching.
    public func categorizeWebsiteBulk(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/categorize/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Queue 1 to 100 public page scrapes for asynchronous processing. Batch jobs are available to paid accounts, require an idempotency key, allow up to three active jobs and 300 queued items per account, and bill each accepted URL at the selected mode price. CAPTCHA solving and premium proxy selection are not offered.
    public func createScrapeJob(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/scrape/jobs",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
    public func createTechScanJob(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/tech/jobs",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
    public func getCategorizationTaxonomy(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/categorize/taxonomy",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Extract source-backed organization names, descriptions, declared social links, MX-inferred email providers, confidence, and provenance from public website and DNS metadata. Enrichment-only fields can be null.
    public func getCompany(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/company",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Compare domains for similarity. Detect typosquatting with multiple algorithms.
    public func getDomainSimilarity(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/similarity",
                pathParams: [],
                queryParams: ["domain1", "domain2"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
    public func getHosting(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/hosting",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
    public func getParkingDetection(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/parking",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
    public func getRedirects(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/redirects",
                pathParams: [],
                queryParams: ["url", "domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get owner-scoped progress, item counts, billing settlement, and expiration details.
    public func getScrapeJob(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/scrape/jobs/:job_id",
                pathParams: ["job_id"],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get ordered, paginated results for an owner-scoped scrape job. Full page results expire after 24 hours.
    public func getScrapeJobResults(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/scrape/jobs/:job_id/results",
                pathParams: ["job_id"],
                queryParams: ["limit", "offset"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
    public func getTechScanJob(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tech/jobs/:job_id",
                pathParams: ["job_id"],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
    public func getTechScanJobResults(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tech/jobs/:job_id/results",
                pathParams: ["job_id"],
                queryParams: ["cursor", "limit"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
    public func getTechStack(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tech",
                pathParams: [],
                queryParams: ["url", "domain", "mode", "max_pages", "skip_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
    public func getUrlIntelligence(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/url-intelligence",
                pathParams: [],
                queryParams: ["url", "skip_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
    public func getWebsiteIdentityAssets(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/identity-assets",
                pathParams: [],
                queryParams: ["domain", "skip_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// List recent short-lived technology scan jobs for the authenticated account.
    public func listTechScanJobs(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tech/jobs",
                pathParams: [],
                queryParams: ["limit", "cursor"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Run up to 10 ordered fast technology scans in one request. Each attempted target is billed independently, including target-site failures. Verified DomScan service failures are refunded independently.
    public func postTechStackBulk(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/tech/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
    public func resolveInternetIdentity(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/identity-resolution",
                pathParams: [],
                queryParams: ["domain", "skip_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Retrieve one public web page with bounded redirects and response size. Standard requests use one attempt, resilient requests may use one eligible retry, and rendered modes execute page JavaScript in an isolated browser. Free accounts can use standard mode with lower request, concurrency, daily, monthly, and response-size limits. CAPTCHA solving and premium proxy selection are not offered. Target-site failures remain billable after processing starts; verified platform failures are refunded.
    public func scrapePage(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/scrape",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }
}

public final class MetaService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
    public func cancelApiBatch(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "DELETE",
                path: "/v1/batches/:job_id",
                pathParams: ["job_id"],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and refund rules. Target-site outcomes remain billed, while verified service failures are refunded independently.
    public func createApiBatch(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/batches",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Download the full disposable email domain dataset in various formats.
    public func downloadEmailBlacklist(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/blacklist/download",
                pathParams: [],
                queryParams: ["format"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
    public func getApiBatch(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/batches/:job_id",
                pathParams: ["job_id"],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
    public func getApiBatchResults(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/batches/:job_id/results",
                pathParams: ["job_id"],
                queryParams: ["after", "limit", "format"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Browse the disposable email domain dataset as a paginated data feed.
    public func getEmailBlacklistInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/blacklist",
                pathParams: [],
                queryParams: ["limit", "offset", "format"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get credit costs per endpoint and API pricing information.
    public func getPricingInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/pricing",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// List unexpired asynchronous API batches for the active customer account.
    public func listApiBatches(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/batches",
                pathParams: [],
                queryParams: ["limit"],
                hasBody: false
            ),
            params: params
        )
    }
}

public final class OsintService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
    public func bulkGetRdap(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/rdap/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Get WHOIS data for multiple domains at once.
    public func bulkWhois(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/whois/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
    public func getDomainLifecycle(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/lifecycle",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
    public func getIpInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ip",
                pathParams: [],
                queryParams: ["ip", "domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Lookup MAC address vendor information. Identify network device manufacturers.
    public func getMacInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/mac",
                pathParams: [],
                queryParams: ["mac"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Returns parameter help and an example response for the MAC address lookup endpoint.
    public func getMacLookupInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/mac/info",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get raw RDAP response for a domain, IP address, or autonomous system number.
    public func getRdap(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/rdap",
                pathParams: [],
                queryParams: ["query", "type", "domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get structured WHOIS/RDAP registration data for a domain.
    public func getWhois(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/whois",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
    public func getWhoisHistory(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/whois/history",
                pathParams: [],
                queryParams: ["domain", "limit"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Fetch RDAP and traditional WHOIS in parallel, then merge available abuse contacts, registrar WHOIS details, glue addresses, and raw WHOIS evidence into the normalized response.
    public func getWhoisV2(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v2/whois",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }
}

public final class PricingService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
    public func bulkPricing(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/prices/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
    public func comparePrices(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/prices/compare",
                pathParams: [],
                queryParams: ["domain", "registrars", "skip_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
    public func getPrices(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/prices",
                pathParams: [],
                queryParams: ["tlds", "registrars", "skip_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
    public func getRegistrars(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/prices/registrars",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
    public func getTldPricing(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/prices/tld/:tld",
                pathParams: ["tld"],
                queryParams: ["registrars", "skip_cache"],
                hasBody: false
            ),
            params: params
        )
    }
}

public final class RecipesService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
    public func recipeBrandLaunch(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/brand-launch",
                pathParams: [],
                queryParams: ["domain", "brand_name", "platforms"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
    public func recipeCompetitorIntel(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/competitor-intel",
                pathParams: [],
                queryParams: ["domain", "discover_subdomains", "analyze_infrastructure", "analyze_email"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
    public func recipeDefensiveRegistration(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/defensive-registration",
                pathParams: [],
                queryParams: ["brand", "owned_domains", "priority_tlds", "include_typos", "budget"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
    public func recipeDnsMigration(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/dns-migration",
                pathParams: [],
                queryParams: ["domain", "target_nameservers", "critical_records"],
                hasBody: false
            ),
            params: params
        )
    }

    /// AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
    public func recipeDomainFinder(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/domain-finder",
                pathParams: [],
                queryParams: ["keywords", "tlds", "style", "max_length", "language", "limit"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
    public func recipeDueDiligence(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/due-diligence",
                pathParams: [],
                queryParams: ["domain", "include_competitors"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
    public func recipeEmailDeliverability(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/email-deliverability",
                pathParams: [],
                queryParams: ["domain", "dkim_selectors", "check_blacklists"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
    public func recipeInfrastructureDiscovery(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/infrastructure-discovery",
                pathParams: [],
                queryParams: ["domain", "depth", "include_historical"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
    public func recipePhishingInvestigation(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/phishing-investigation",
                pathParams: [],
                queryParams: ["suspicious_domain", "legitimate_domain", "collect_evidence"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
    public func recipePortfolioAudit(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/portfolio-audit",
                pathParams: [],
                queryParams: ["domains", "include_valuation", "include_health", "include_pricing", "alert_expiring_days"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Audit domain portfolio via POST for larger domain lists.
    public func recipePortfolioAuditPost(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/recipes/portfolio-audit",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
    public func recipeThreatAssessment(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/threat-assessment",
                pathParams: [],
                queryParams: ["domain", "analyze_threats", "max_threats", "include_evidence"],
                hasBody: false
            ),
            params: params
        )
    }
}

public final class SecurityService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Check multiple email domains against blacklists at once.
    public func bulkEmailCheck(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/email/check/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
    public func bulkGetCertificates(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/certificates/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
    public func bulkGetEmailAuth(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/email-auth/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
    public func bulkGetSubdomains(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/subdomains/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Check if an email domain is on disposable/temporary email blacklists.
    public func checkEmailBlacklist(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/check",
                pathParams: [],
                queryParams: ["email", "checks"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
    public func getCertificates(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/certificates",
                pathParams: [],
                queryParams: ["domain", "include_subdomains", "include_expired", "limit", "cursor"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
    public func getDomainReputation(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/reputation",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
    public func getEmailAuth(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email-auth",
                pathParams: [],
                queryParams: ["domain", "selectors"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and mail security checks.
    public func getEmailCompliance(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/compliance",
                pathParams: [],
                queryParams: ["domain", "selectors", "providers"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
    public func getSslAudit(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ssl/audit",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Analyze the certificate chain including issuer, validity, and trust chain verification.
    public func getSslChain(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ssl/chain",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
    public func getSslDeepScan(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ssl/deep-scan",
                pathParams: [],
                queryParams: ["domain", "refresh", "profile"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Check if an SSL certificate is expiring soon with configurable alert threshold.
    public func getSslExpiring(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ssl/expiring",
                pathParams: [],
                queryParams: ["domain", "days", "threshold_days"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
    public func getSslGrade(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ssl/grade",
                pathParams: [],
                queryParams: ["domain"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Return best-effort hostname evidence from public certificate and passive discovery sources. Coverage is incomplete, and results include provenance with optional DNS verification.
    public func getSubdomains(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/subdomains",
                pathParams: [],
                queryParams: ["domain", "sources", "verify", "include_wildcards", "limit", "prefer_cache"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
    public func getTyposquatting(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/typos",
                pathParams: [],
                queryParams: ["domain", "check_registered", "limit", "include_tld_swap"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Correlate exposed software versions with authoritative public advisories and exploitation-priority data, and report deterministic web security misconfigurations separately. Results preserve evidence and unknown coverage.
    public func getVulnerabilities(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/vulnerabilities",
                pathParams: [],
                queryParams: ["url", "domain", "mode"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Validate, normalize, and enrich international phone numbers with maintained offline numbering-plan and public allocation data. Results include coverage, provenance, freshness, and limitations without paid or per-number third-party lookups, and never claim current carrier, reachability, subscriber identity, or individual-number assignment.
    public func validatePhoneNumber(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/phone/validate",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and makes no paid or per-number third-party lookup.
    public func validatePhoneNumbersBulk(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/phone/validate/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
    public func verifyEmail(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/verify",
                pathParams: [],
                queryParams: ["email", "full"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Verify multiple email addresses at once. Max 100 emails per request.
    public func verifyEmailBulk(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/email/verify/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }
}

public final class SocialService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
    public func bulkCheckSocialHandles(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "POST",
                path: "/v1/social/bulk",
                pathParams: [],
                queryParams: [],
                hasBody: true
            ),
            params: params
        )
    }

    /// Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
    public func checkSocialHandles(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/social",
                pathParams: [],
                queryParams: ["handle", "platforms", "resources"],
                hasBody: false
            ),
            params: params
        )
    }

    /// Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
    public func getSocialInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/social/info",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }
}

public final class UserService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Get the active customer account credit balance without exposing transaction history.
    public func getCreditBalance(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/credits",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }
}
