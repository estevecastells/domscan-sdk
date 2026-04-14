package net.domscan

import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.temporal.TemporalAccessor

data class EndpointDefinition(
    val method: String,
    val path: String,
    val pathParams: List<String>,
    val queryParams: List<String>,
    val hasBody: Boolean
)

class DomScanApiException(
    message: String,
    val status: Int,
    val codeValue: String? = null,
    val details: String? = null,
    val requestId: String? = null
) : RuntimeException(message)

class DomScanClient(
    apiKey: String? = System.getenv("DOMSCAN_API_KEY"),
    baseUrl: String = "https://domscan.net",
    private val timeout: Duration = Duration.ofSeconds(10),
    private val headers: Map<String, String> = emptyMap(),
    private val userAgent: String = "domscan-kotlin/0.1.0",
    private val httpClient: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
) {
    private val apiKey: String? = apiKey?.takeUnless { it.isBlank() }
    private val baseUrl: String = baseUrl.trimEnd('/')

    val availability: AvailabilityService = AvailabilityService(this)
    val dns: DnsService = DnsService(this)
    val domain: DomainService = DomainService(this)
    val intelligence: IntelligenceService = IntelligenceService(this)
    val meta: MetaService = MetaService(this)
    val osint: OsintService = OsintService(this)
    val pricing: PricingService = PricingService(this)
    val recipes: RecipesService = RecipesService(this)
    val security: SecurityService = SecurityService(this)
    val social: SocialService = SocialService(this)

    internal fun request(endpoint: EndpointDefinition, params: Map<String, Any?> = emptyMap()): String {
        var requestPath = endpoint.path
        val remaining = params.toMutableMap()

        endpoint.pathParams.forEach { pathParam ->
            val value = remaining.remove(pathParam)
                ?: throw IllegalArgumentException("Missing required path parameter: $pathParam")
            requestPath = requestPath.replace(":$pathParam", encode(value.toString()))
        }

        val queryPayload = if (endpoint.hasBody) {
            remaining.filterKeys { endpoint.queryParams.contains(it) && remaining[it] != null }
        } else {
            remaining.filterValues { it != null }
        }

        val url = buildString {
            append(baseUrl)
            append(requestPath)
            if (queryPayload.isNotEmpty()) {
                append('?')
                append(
                    queryPayload.entries.joinToString("&") { (key, value) ->
                        "${encode(key)}=${encode(serializeQueryValue(value))}"
                    }
                )
            }
        }

        val requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("X-DomScan-SDK", userAgent)

        if (!apiKey.isNullOrBlank()) {
            requestBuilder.header("Authorization", "Bearer $apiKey")
            requestBuilder.header("X-API-Key", apiKey)
        }

        headers.forEach { (key, value) -> requestBuilder.header(key, value) }

        if (endpoint.hasBody) {
            val bodyPayload = remaining.filterKeys { !endpoint.queryParams.contains(it) && remaining[it] != null }
            requestBuilder.header("Content-Type", "application/json")
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.ofString(toJson(bodyPayload)))
        } else {
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.noBody())
        }

        val response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() < 400) {
            return response.body()
        }

        throw DomScanApiException(
            extractJsonField(response.body(), "message") ?: "DomScan request failed with status ${response.statusCode()}",
            response.statusCode(),
            extractJsonField(response.body(), "code"),
            response.body(),
            response.headers().firstValue("x-request-id").orElse(null)
        )
    }

    private fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

    private fun serializeQueryValue(value: Any?): String = when (value) {
        null -> ""
        is String -> value
        is Boolean -> if (value) "true" else "false"
        is TemporalAccessor -> value.toString()
        is Iterable<*> -> value.filterNotNull().joinToString(",") { serializeQueryValue(it) }
        is Map<*, *> -> toJson(value)
        else -> value.toString()
    }

    private fun toJson(value: Any?): String = when (value) {
        null -> "null"
        is String -> "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""
        is Number, is Boolean -> value.toString()
        is Map<*, *> -> value.entries.joinToString(prefix = "{", postfix = "}") { (key, item) ->
            "\"${key.toString()}\":${toJson(item)}"
        }
        is Iterable<*> -> value.joinToString(prefix = "[", postfix = "]") { item -> toJson(item) }
        else -> "\"${value.toString()}\""
    }

    private fun extractJsonField(json: String, field: String): String? {
        val marker = "\"$field\":\""
        val start = json.indexOf(marker)
        if (start < 0) {
            return null
        }
        val valueStart = start + marker.length
        val valueEnd = json.indexOf('"', valueStart)
        return if (valueEnd < 0) null else json.substring(valueStart, valueEnd)
    }
}

class AvailabilityService(private val client: DomScanClient) {
    /**
     * Check availability of multiple complete domain names at once.
     */
    fun bulkCheckDomains(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/status/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
     */
    fun checkDomainAvailability(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/status",
                pathParams = listOf(),
                queryParams = listOf("name", "tlds", "prefer_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * Get information about which TLDs are supported and their RDAP server status.
     */
    fun getCoverage(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/coverage",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}

class DnsService(private val client: DomScanClient) {
    /**
     * Build a DMARC record with policy, reporting, and alignment options.
     */
    fun buildDmarc(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/tools/dmarc/build",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Build an SPF record from configuration options with validation and recommendations.
     */
    fun buildSpf(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/tools/spf/build",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Check a specific DKIM selector for a domain and validate the public key.
     */
    fun checkDkim(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tools/dkim/check",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Discover DKIM selectors for a domain by checking common selector names.
     */
    fun discoverDkim(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tools/dkim/discover",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
     */
    fun flattenSpf(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/tools/spf/flatten",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Get all DNS record types for a domain in a single call.
     */
    fun getAllDnsRecords(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/all",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Compare DNS records between two dates to see what changed.
     */
    fun getDnsDiff(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/diff",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Track DNS record changes over time. Data accumulates from API lookups.
     */
    fun getDnsHistory(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/history",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Check DNS propagation across multiple global DNS servers.
     */
    fun getDnsPropagation(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/propagation",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
     */
    fun getDnsRecords(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
     */
    fun getDnsSecurity(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/security",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get list of global DNS servers used for propagation checks.
     */
    fun getDnsServers(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/servers",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Validate a DMARC record for syntax errors and configuration issues.
     */
    fun validateDmarc(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/tools/dmarc/validate",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
     */
    fun validateSpf(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/tools/spf/validate",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )
}

class DomainService(private val client: DomScanClient) {
    /**
     * Get value estimates for multiple domains at once.
     */
    fun bulkDomainValue(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/value/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Compare two domains side-by-side across multiple metrics and attributes.
     */
    fun compareDomains(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/compare",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
     */
    fun getDomainHealth(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/health",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
     */
    fun getDomainOverview(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/overview",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
     */
    fun getDomainProfile(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/profile",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Calculate an overall domain quality score based on multiple factors.
     */
    fun getDomainScore(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/score",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
     */
    fun getDomainValue(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/value",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Fast health check with essential metrics only.
     */
    fun getQuickHealth(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/health/quick",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get detailed information about a specific TLD.
     */
    fun getTldDetail(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tlds/:tld",
                pathParams = listOf("tld"),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get list of all supported TLDs with metadata.
     */
    fun getTlds(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tlds",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
     */
    fun suggestDomains(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/suggest",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}

class IntelligenceService(private val client: DomScanClient) {
    /**
     * Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
     */
    fun categorizeWebsite(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/categorize",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Categorize up to 10 websites in parallel with caching.
     */
    fun categorizeWebsiteBulk(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/categorize/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Extract company information from a domain. Get name, industry, and contact details.
     */
    fun getCompany(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/company",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Compare domains for similarity. Detect typosquatting with multiple algorithms.
     */
    fun getDomainSimilarity(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/similarity",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
     */
    fun getHosting(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/hosting",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
     */
    fun getParkingDetection(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/parking",
                pathParams = listOf(),
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
     */
    fun getRedirects(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/redirects",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Detect website technologies: CDN, CMS, frameworks, analytics, and more.
     */
    fun getTechStack(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tech",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}

class MetaService(private val client: DomScanClient) {
    /**
     * Get credit costs per endpoint and API pricing information.
     */
    fun getPricingInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/pricing",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}

class OsintService(private val client: DomScanClient) {
    /**
     * Get WHOIS data for multiple domains at once.
     */
    fun bulkWhois(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/whois/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Find domains that use a specific nameserver.
     */
    fun getDnsReverseNs(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/reverse/ns",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Map domain relationships through shared infrastructure and registrant data.
     */
    fun getDomainGraph(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/graph",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
     */
    fun getDomainLifecycle(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/lifecycle",
                pathParams = listOf(),
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Get IP addresses with geolocation, ASN, and hosting provider information.
     */
    fun getIpInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ip",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Lookup MAC address vendor information. Identify network device manufacturers.
     */
    fun getMacInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/mac",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Find all domains hosted on a specific IP address.
     */
    fun getReverseIp(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/reverse/ip",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Find all domains using a specific mail server for email infrastructure mapping.
     */
    fun getReverseMx(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/reverse/mx",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get structured WHOIS/RDAP registration data for a domain.
     */
    fun getWhois(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/whois",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
     */
    fun getWhoisHistory(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/whois/history",
                pathParams = listOf(),
                queryParams = listOf("domain", "limit"),
                hasBody = false
            ),
            params
        )
}

class PricingService(private val client: DomScanClient) {
    /**
     * Get pricing for multiple domains at once.
     */
    fun bulkPricing(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/prices/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Compare domain prices across multiple registrars.
     */
    fun comparePrices(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/prices/compare",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get domain registration and renewal prices across registrars.
     */
    fun getPrices(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/prices",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get list of supported registrars with pricing data.
     */
    fun getRegistrars(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/prices/registrars",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get pricing for a specific TLD across registrars.
     */
    fun getTldPricing(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/prices/tld/:tld",
                pathParams = listOf("tld"),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}

class RecipesService(private val client: DomScanClient) {
    /**
     * Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
     */
    fun recipeBrandLaunch(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/brand-launch",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
     */
    fun recipeCompetitorIntel(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/competitor-intel",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
     */
    fun recipeDefensiveRegistration(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/defensive-registration",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
     */
    fun recipeDnsMigration(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/dns-migration",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
     */
    fun recipeDomainFinder(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/domain-finder",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
     */
    fun recipeDueDiligence(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/due-diligence",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
     */
    fun recipeEmailDeliverability(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/email-deliverability",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
     */
    fun recipeInfrastructureDiscovery(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/infrastructure-discovery",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
     */
    fun recipePhishingInvestigation(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/phishing-investigation",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
     */
    fun recipePortfolioAudit(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/portfolio-audit",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Audit domain portfolio via POST for larger domain lists.
     */
    fun recipePortfolioAuditPost(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/recipes/portfolio-audit",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
     */
    fun recipeThreatAssessment(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/threat-assessment",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}

class SecurityService(private val client: DomScanClient) {
    /**
     * Check multiple email domains against blacklists at once.
     */
    fun bulkEmailCheck(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/email/check/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Check if an email domain is on disposable/temporary email blacklists.
     */
    fun checkEmailBlacklist(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email/check",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Download the full email blacklist database in various formats.
     */
    fun downloadEmailBlacklist(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email/blacklist/download",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
     */
    fun getCertificates(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/certificates",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Check domain reputation across security feeds, blacklists, and threat intelligence.
     */
    fun getDomainReputation(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/reputation",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Check DMARC, SPF, and DKIM configurations for email security auditing.
     */
    fun getEmailAuth(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email-auth",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get information about the email blacklist database.
     */
    fun getEmailBlacklistInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email/blacklist",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Analyze the certificate chain including issuer, validity, and trust chain verification.
     */
    fun getSslChain(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ssl/chain",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Check if an SSL certificate is expiring soon with configurable alert threshold.
     */
    fun getSslExpiring(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ssl/expiring",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
     */
    fun getSslGrade(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ssl/grade",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Discover subdomains using Certificate Transparency and DNS enumeration.
     */
    fun getSubdomains(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/subdomains",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
     */
    fun getTyposquatting(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/typos",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
     */
    fun verifyEmail(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email/verify",
                pathParams = listOf(),
                queryParams = listOf("email", "full"),
                hasBody = false
            ),
            params
        )

    /**
     * Verify multiple email addresses at once. Max 100 emails per request.
     */
    fun verifyEmailBulk(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/email/verify/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )
}

class SocialService(private val client: DomScanClient) {
    /**
     * Check username availability across social platforms like GitHub, Reddit, and more.
     */
    fun checkSocialHandles(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/social",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}
