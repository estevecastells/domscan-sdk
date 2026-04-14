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

    public init(
        apiKey: String? = ProcessInfo.processInfo.environment["DOMSCAN_API_KEY"],
        baseURL: String = "https://domscan.net",
        timeout: TimeInterval = 10,
        headers: [String: String] = [:],
        userAgent: String = "domscan-swift/0.1.0"
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

    /// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
    public func checkDomainAvailability(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/status",
                pathParams: [],
                queryParams: ["name", "tlds", "prefer_cache"],
                hasBody: false
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
                queryParams: [],
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

    /// Check a specific DKIM selector for a domain and validate the public key.
    public func checkDkim(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tools/dkim/check",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
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

    /// Get all DNS record types for a domain in a single call.
    public func getAllDnsRecords(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/all",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Compare DNS records between two dates to see what changed.
    public func getDnsDiff(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/diff",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Track DNS record changes over time. Data accumulates from API lookups.
    public func getDnsHistory(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/history",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Check DNS propagation across multiple global DNS servers.
    public func getDnsPropagation(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/propagation",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
    public func getDnsRecords(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
    public func getDnsSecurity(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/security",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get list of global DNS servers used for propagation checks.
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

    /// Compare two domains side-by-side across multiple metrics and attributes.
    public func compareDomains(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/compare",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
    public func getDomainHealth(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/health",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
    public func getDomainOverview(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/overview",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
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
                queryParams: [],
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
                queryParams: [],
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
                queryParams: [],
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
                queryParams: [],
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

    /// Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
    public func categorizeWebsite(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/categorize",
                pathParams: [],
                queryParams: [],
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

    /// Extract company information from a domain. Get name, industry, and contact details.
    public func getCompany(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/company",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
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
                queryParams: [],
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
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Detect website technologies: CDN, CMS, frameworks, analytics, and more.
    public func getTechStack(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/tech",
                pathParams: [],
                queryParams: [],
                hasBody: false
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
}

public final class OsintService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
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

    /// Find domains that use a specific nameserver.
    public func getDnsReverseNs(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/dns/reverse/ns",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Map domain relationships through shared infrastructure and registrant data.
    public func getDomainGraph(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/graph",
                pathParams: [],
                queryParams: [],
                hasBody: false
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

    /// Get IP addresses with geolocation, ASN, and hosting provider information.
    public func getIpInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ip",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Find all domains hosted on a specific IP address.
    public func getReverseIp(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/reverse/ip",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Find all domains using a specific mail server for email infrastructure mapping.
    public func getReverseMx(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/reverse/mx",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
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
}

public final class PricingService {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

    /// Get pricing for multiple domains at once.
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

    /// Compare domain prices across multiple registrars.
    public func comparePrices(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/prices/compare",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get domain registration and renewal prices across registrars.
    public func getPrices(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/prices",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get list of supported registrars with pricing data.
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

    /// Get pricing for a specific TLD across registrars.
    public func getTldPricing(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/prices/tld/:tld",
                pathParams: ["tld"],
                queryParams: [],
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

    /// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
    public func recipeBrandLaunch(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/brand-launch",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
    public func recipeCompetitorIntel(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/competitor-intel",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
    public func recipeDefensiveRegistration(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/defensive-registration",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
    public func recipeDnsMigration(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/dns-migration",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
    public func recipeDomainFinder(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/domain-finder",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
    public func recipeDueDiligence(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/due-diligence",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
    public func recipeEmailDeliverability(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/email-deliverability",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
    public func recipeInfrastructureDiscovery(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/infrastructure-discovery",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
    public func recipePhishingInvestigation(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/phishing-investigation",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
    public func recipePortfolioAudit(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/portfolio-audit",
                pathParams: [],
                queryParams: [],
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

    /// Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
    public func recipeThreatAssessment(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/recipes/threat-assessment",
                pathParams: [],
                queryParams: [],
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

    /// Check if an email domain is on disposable/temporary email blacklists.
    public func checkEmailBlacklist(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/check",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Download the full email blacklist database in various formats.
    public func downloadEmailBlacklist(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/blacklist/download",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Check domain reputation across security feeds, blacklists, and threat intelligence.
    public func getDomainReputation(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/reputation",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Check DMARC, SPF, and DKIM configurations for email security auditing.
    public func getEmailAuth(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email-auth",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Get information about the email blacklist database.
    public func getEmailBlacklistInfo(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/email/blacklist",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
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
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
    public func getSslGrade(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/ssl/grade",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Discover subdomains using Certificate Transparency and DNS enumeration.
    public func getSubdomains(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/subdomains",
                pathParams: [],
                queryParams: [],
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
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }

    /// Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
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

    /// Check username availability across social platforms like GitHub, Reddit, and more.
    public func checkSocialHandles(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: "GET",
                path: "/v1/social",
                pathParams: [],
                queryParams: [],
                hasBody: false
            ),
            params: params
        )
    }
}
