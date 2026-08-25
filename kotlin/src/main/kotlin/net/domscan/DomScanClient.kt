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
    private val userAgent: String = "domscan-kotlin/0.3.0",
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
    val user: UserService = UserService(this)

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
            .header("User-Agent", userAgent)
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
     * Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
     */
    fun checkDomainAvailability(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/status",
                pathParams = listOf(),
                queryParams = listOf("name", "tlds", "domain", "prefer_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * Create a resumable asynchronous search over a curated English single-word corpus sourced from iannuttall/unclaimed under the MIT License. Check each selected word across 1 to 5 supported TLDs, with a hard limit of 100 word-TLD checks per job. Available, registered, and unknown remain distinct outcomes. Jobs use the existing batch status, results, and cancellation lifecycle.
     */
    fun createDomainDiscoveryJob(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/domain-discovery/jobs",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
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
                queryParams = listOf("live"),
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
     * Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
     */
    fun bulkDnsPropagation(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/dns/propagation/bulk",
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
                queryParams = listOf("domain", "selector"),
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
                queryParams = listOf("domain"),
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
     * Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
     */
    fun getAllDnsRecords(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/all",
                pathParams = listOf(),
                queryParams = listOf("domain", "wildcard_probe"),
                hasBody = false
            ),
            params
        )

    /**
     * Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
     */
    fun getDnsHistory(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/history",
                pathParams = listOf(),
                queryParams = listOf("domain", "type", "from", "to", "limit"),
                hasBody = false
            ),
            params
        )

    /**
     * Compare answers from DomScan's configured public recursive resolvers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
     */
    fun getDnsPropagation(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/propagation",
                pathParams = listOf(),
                queryParams = listOf("domain", "type", "expected"),
                hasBody = false
            ),
            params
        )

    /**
     * Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
     */
    fun getDnsRecords(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns",
                pathParams = listOf(),
                queryParams = listOf("domain", "type"),
                hasBody = false
            ),
            params
        )

    /**
     * Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
     */
    fun getDnsSecurity(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/dns/security",
                pathParams = listOf(),
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
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
     * Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
     */
    fun bulkGetDomainProfile(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/profile/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Compare up to 50 candidate brand names and return ranked scores.
     */
    fun compareBrandNames(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/score/compare",
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
                queryParams = listOf("domains"),
                hasBody = false
            ),
            params
        )

    /**
     * Comprehensive health checks with DNS, SSL, email, extended TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
     */
    fun getDomainHealth(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/health",
                pathParams = listOf(),
                queryParams = listOf("domain", "details"),
                hasBody = false
            ),
            params
        )

    /**
     * Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
     */
    fun getDomainOverview(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/overview",
                pathParams = listOf(),
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
     */
    fun getDomainPopularity(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/popularity",
                pathParams = listOf(),
                queryParams = listOf("domain", "include_history", "history_limit"),
                hasBody = false
            ),
            params
        )

    /**
     * Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
     */
    fun getDomainPopularityHistory(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/popularity/history",
                pathParams = listOf(),
                queryParams = listOf("domain", "limit"),
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
                queryParams = listOf("domain"),
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
                queryParams = listOf("name", "domain"),
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
                queryParams = listOf("domain"),
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
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Returns scoring dimensions, grade scale, and related scoring endpoints.
     */
    fun getScoreInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/score/info",
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
                queryParams = listOf("type", "trust_tier", "use_case"),
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
                queryParams = listOf("keywords", "tlds", "style", "industry", "language", "limit", "check"),
                hasBody = false
            ),
            params
        )
}

class IntelligenceService(private val client: DomScanClient) {
    /**
     * Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
     */
    fun bulkGetHosting(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/hosting/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
     */
    fun bulkGetUrlIntelligence(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/url-intelligence/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
     */
    fun bulkGetWebsiteIdentityAssets(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/identity-assets/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
     */
    fun bulkResolveInternetIdentity(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/identity-resolution/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Cancel unstarted technology scan work and settle item-level refunds. Work already in progress may finish and remains available in the job results.
     */
    fun cancelTechScanJob(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "DELETE",
                path = "/v1/tech/jobs/:job_id",
                pathParams = listOf("job_id"),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
     */
    fun categorizeWebsite(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/categorize",
                pathParams = listOf(),
                queryParams = listOf("url", "domain", "skip_cache", "min_confidence"),
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
     * Queue 1 to 100 public page scrapes for asynchronous processing. Batch jobs are available to paid accounts, require an idempotency key, allow up to three active jobs and 300 queued items per account, and bill each accepted URL at the selected mode price. CAPTCHA solving and premium proxy selection are not offered.
     */
    fun createScrapeJob(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/scrape/jobs",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
     */
    fun createTechScanJob(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/tech/jobs",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
     */
    fun getCategorizationTaxonomy(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/categorize/taxonomy",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Extract source-backed organization names, descriptions, declared social links, MX-inferred email providers, confidence, and provenance from public website and DNS metadata. Enrichment-only fields can be null.
     */
    fun getCompany(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/company",
                pathParams = listOf(),
                queryParams = listOf("domain"),
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
                queryParams = listOf("domain1", "domain2"),
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
                queryParams = listOf("domain"),
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
                queryParams = listOf("url", "domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Get owner-scoped progress, item counts, billing settlement, and expiration details.
     */
    fun getScrapeJob(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/scrape/jobs/:job_id",
                pathParams = listOf("job_id"),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get ordered, paginated results for an owner-scoped scrape job. Full page results expire after 24 hours.
     */
    fun getScrapeJobResults(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/scrape/jobs/:job_id/results",
                pathParams = listOf("job_id"),
                queryParams = listOf("limit", "offset"),
                hasBody = false
            ),
            params
        )

    /**
     * Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
     */
    fun getTechScanJob(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tech/jobs/:job_id",
                pathParams = listOf("job_id"),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
     */
    fun getTechScanJobResults(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tech/jobs/:job_id/results",
                pathParams = listOf("job_id"),
                queryParams = listOf("cursor", "limit"),
                hasBody = false
            ),
            params
        )

    /**
     * Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
     */
    fun getTechStack(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tech",
                pathParams = listOf(),
                queryParams = listOf("url", "domain", "mode", "max_pages", "skip_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
     */
    fun getUrlIntelligence(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/url-intelligence",
                pathParams = listOf(),
                queryParams = listOf("url", "skip_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
     */
    fun getWebsiteIdentityAssets(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/identity-assets",
                pathParams = listOf(),
                queryParams = listOf("domain", "skip_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * List recent short-lived technology scan jobs for the authenticated account.
     */
    fun listTechScanJobs(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/tech/jobs",
                pathParams = listOf(),
                queryParams = listOf("limit", "cursor"),
                hasBody = false
            ),
            params
        )

    /**
     * Run up to 10 ordered fast technology scans in one request. Each attempted target is billed independently, including target-site failures. Verified DomScan service failures are refunded independently.
     */
    fun postTechStackBulk(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/tech/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
     */
    fun resolveInternetIdentity(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/identity-resolution",
                pathParams = listOf(),
                queryParams = listOf("domain", "skip_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * Retrieve one public web page with bounded redirects and response size. Standard requests use one attempt, resilient requests may use one eligible retry, and rendered modes execute page JavaScript in an isolated browser. Free accounts can use standard mode with lower request, concurrency, daily, monthly, and response-size limits. CAPTCHA solving and premium proxy selection are not offered. Target-site failures remain billable after processing starts; verified platform failures are refunded.
     */
    fun scrapePage(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/scrape",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )
}

class MetaService(private val client: DomScanClient) {
    /**
     * Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
     */
    fun cancelApiBatch(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "DELETE",
                path = "/v1/batches/:job_id",
                pathParams = listOf("job_id"),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and refund rules. Target-site outcomes remain billed, while verified service failures are refunded independently.
     */
    fun createApiBatch(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/batches",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Download the full disposable email domain dataset in various formats.
     */
    fun downloadEmailBlacklist(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email/blacklist/download",
                pathParams = listOf(),
                queryParams = listOf("format"),
                hasBody = false
            ),
            params
        )

    /**
     * Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
     */
    fun getApiBatch(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/batches/:job_id",
                pathParams = listOf("job_id"),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
     */
    fun getApiBatchResults(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/batches/:job_id/results",
                pathParams = listOf("job_id"),
                queryParams = listOf("after", "limit", "format"),
                hasBody = false
            ),
            params
        )

    /**
     * Browse the disposable email domain dataset as a paginated data feed.
     */
    fun getEmailBlacklistInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email/blacklist",
                pathParams = listOf(),
                queryParams = listOf("limit", "offset", "format"),
                hasBody = false
            ),
            params
        )

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

    /**
     * List unexpired asynchronous API batches for the active customer account.
     */
    fun listApiBatches(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/batches",
                pathParams = listOf(),
                queryParams = listOf("limit"),
                hasBody = false
            ),
            params
        )
}

class OsintService(private val client: DomScanClient) {
    /**
     * Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
     */
    fun bulkGetRdap(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/rdap/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

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
     * Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
     */
    fun getIpInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ip",
                pathParams = listOf(),
                queryParams = listOf("ip", "domain"),
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
                queryParams = listOf("mac"),
                hasBody = false
            ),
            params
        )

    /**
     * Returns parameter help and an example response for the MAC address lookup endpoint.
     */
    fun getMacLookupInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/mac/info",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )

    /**
     * Get raw RDAP response for a domain, IP address, or autonomous system number.
     */
    fun getRdap(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/rdap",
                pathParams = listOf(),
                queryParams = listOf("query", "type", "domain"),
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
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
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

    /**
     * Fetch RDAP and traditional WHOIS in parallel, then merge available abuse contacts, registrar WHOIS details, glue addresses, and raw WHOIS evidence into the normalized response.
     */
    fun getWhoisV2(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v2/whois",
                pathParams = listOf(),
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )
}

class PricingService(private val client: DomScanClient) {
    /**
     * Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
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
     * Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
     */
    fun comparePrices(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/prices/compare",
                pathParams = listOf(),
                queryParams = listOf("domain", "registrars", "skip_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
     */
    fun getPrices(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/prices",
                pathParams = listOf(),
                queryParams = listOf("tlds", "registrars", "skip_cache"),
                hasBody = false
            ),
            params
        )

    /**
     * List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
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
     * Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
     */
    fun getTldPricing(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/prices/tld/:tld",
                pathParams = listOf("tld"),
                queryParams = listOf("registrars", "skip_cache"),
                hasBody = false
            ),
            params
        )
}

class RecipesService(private val client: DomScanClient) {
    /**
     * Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
     */
    fun recipeBrandLaunch(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/brand-launch",
                pathParams = listOf(),
                queryParams = listOf("domain", "brand_name", "platforms"),
                hasBody = false
            ),
            params
        )

    /**
     * Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
     */
    fun recipeCompetitorIntel(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/competitor-intel",
                pathParams = listOf(),
                queryParams = listOf("domain", "discover_subdomains", "analyze_infrastructure", "analyze_email"),
                hasBody = false
            ),
            params
        )

    /**
     * Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
     */
    fun recipeDefensiveRegistration(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/defensive-registration",
                pathParams = listOf(),
                queryParams = listOf("brand", "owned_domains", "priority_tlds", "include_typos", "budget"),
                hasBody = false
            ),
            params
        )

    /**
     * Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
     */
    fun recipeDnsMigration(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/dns-migration",
                pathParams = listOf(),
                queryParams = listOf("domain", "target_nameservers", "critical_records"),
                hasBody = false
            ),
            params
        )

    /**
     * AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
     */
    fun recipeDomainFinder(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/domain-finder",
                pathParams = listOf(),
                queryParams = listOf("keywords", "tlds", "style", "max_length", "language", "limit"),
                hasBody = false
            ),
            params
        )

    /**
     * Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
     */
    fun recipeDueDiligence(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/due-diligence",
                pathParams = listOf(),
                queryParams = listOf("domain", "include_competitors"),
                hasBody = false
            ),
            params
        )

    /**
     * Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
     */
    fun recipeEmailDeliverability(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/email-deliverability",
                pathParams = listOf(),
                queryParams = listOf("domain", "dkim_selectors", "check_blacklists"),
                hasBody = false
            ),
            params
        )

    /**
     * Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
     */
    fun recipeInfrastructureDiscovery(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/infrastructure-discovery",
                pathParams = listOf(),
                queryParams = listOf("domain", "depth", "include_historical"),
                hasBody = false
            ),
            params
        )

    /**
     * Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
     */
    fun recipePhishingInvestigation(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/phishing-investigation",
                pathParams = listOf(),
                queryParams = listOf("suspicious_domain", "legitimate_domain", "collect_evidence"),
                hasBody = false
            ),
            params
        )

    /**
     * Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
     */
    fun recipePortfolioAudit(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/portfolio-audit",
                pathParams = listOf(),
                queryParams = listOf("domains", "include_valuation", "include_health", "include_pricing", "alert_expiring_days"),
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
     * Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
     */
    fun recipeThreatAssessment(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/recipes/threat-assessment",
                pathParams = listOf(),
                queryParams = listOf("domain", "analyze_threats", "max_threats", "include_evidence"),
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
     * Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
     */
    fun bulkGetCertificates(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/certificates/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
     */
    fun bulkGetEmailAuth(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/email-auth/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
     */
    fun bulkGetSubdomains(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/subdomains/bulk",
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
                queryParams = listOf("email", "checks"),
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
                queryParams = listOf("domain", "include_subdomains", "include_expired", "limit", "cursor"),
                hasBody = false
            ),
            params
        )

    /**
     * Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
     */
    fun getDomainReputation(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/reputation",
                pathParams = listOf(),
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
     */
    fun getEmailAuth(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email-auth",
                pathParams = listOf(),
                queryParams = listOf("domain", "selectors"),
                hasBody = false
            ),
            params
        )

    /**
     * Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and mail security checks.
     */
    fun getEmailCompliance(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/email/compliance",
                pathParams = listOf(),
                queryParams = listOf("domain", "selectors", "providers"),
                hasBody = false
            ),
            params
        )

    /**
     * Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
     */
    fun getSslAudit(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ssl/audit",
                pathParams = listOf(),
                queryParams = listOf("domain"),
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
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
     */
    fun getSslDeepScan(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ssl/deep-scan",
                pathParams = listOf(),
                queryParams = listOf("domain", "refresh", "profile"),
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
                queryParams = listOf("domain", "days", "threshold_days"),
                hasBody = false
            ),
            params
        )

    /**
     * Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
     */
    fun getSslGrade(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/ssl/grade",
                pathParams = listOf(),
                queryParams = listOf("domain"),
                hasBody = false
            ),
            params
        )

    /**
     * Return best-effort hostname evidence from public certificate and passive discovery sources. Coverage is incomplete, and results include provenance with optional DNS verification.
     */
    fun getSubdomains(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/subdomains",
                pathParams = listOf(),
                queryParams = listOf("domain", "sources", "verify", "include_wildcards", "limit", "prefer_cache"),
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
                queryParams = listOf("domain", "check_registered", "limit", "include_tld_swap"),
                hasBody = false
            ),
            params
        )

    /**
     * Correlate exposed software versions with authoritative public advisories and exploitation-priority data, and report deterministic web security misconfigurations separately. Results preserve evidence and unknown coverage.
     */
    fun getVulnerabilities(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/vulnerabilities",
                pathParams = listOf(),
                queryParams = listOf("url", "domain", "mode"),
                hasBody = false
            ),
            params
        )

    /**
     * Validate, normalize, and enrich international phone numbers with maintained offline numbering-plan and public allocation data. Results include coverage, provenance, freshness, and limitations without paid or per-number third-party lookups, and never claim current carrier, reachability, subscriber identity, or individual-number assignment.
     */
    fun validatePhoneNumber(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/phone/validate",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and makes no paid or per-number third-party lookup.
     */
    fun validatePhoneNumbersBulk(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/phone/validate/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
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
     * Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
     */
    fun bulkCheckSocialHandles(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "POST",
                path = "/v1/social/bulk",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = true
            ),
            params
        )

    /**
     * Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
     */
    fun checkSocialHandles(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/social",
                pathParams = listOf(),
                queryParams = listOf("handle", "platforms", "resources"),
                hasBody = false
            ),
            params
        )

    /**
     * Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
     */
    fun getSocialInfo(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/social/info",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}

class UserService(private val client: DomScanClient) {
    /**
     * Get the active customer account credit balance without exposing transaction history.
     */
    fun getCreditBalance(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = "GET",
                path = "/v1/credits",
                pathParams = listOf(),
                queryParams = listOf(),
                hasBody = false
            ),
            params
        )
}
