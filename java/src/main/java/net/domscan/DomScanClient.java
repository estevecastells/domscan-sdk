package net.domscan;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

public final class DomScanClient {
    private final String apiKey;
    private final String baseUrl;
    private final Duration timeout;
    private final String userAgent;
    private final HttpClient httpClient;
    private final Map<String, String> defaultHeaders;
    public final AvailabilityService availability;
    public final DnsService dns;
    public final DomainService domain;
    public final IntelligenceService intelligence;
    public final MetaService meta;
    public final OsintService osint;
    public final PricingService pricing;
    public final RecipesService recipes;
    public final SecurityService security;
    public final SocialService social;
    public final UserService user;

    public DomScanClient() {
        this(new Builder());
    }

    private DomScanClient(Builder builder) {
        this.apiKey = builder.apiKey != null ? builder.apiKey : System.getenv("DOMSCAN_API_KEY");
        this.baseUrl = trimTrailingSlash(builder.baseUrl != null ? builder.baseUrl : "https://domscan.net");
        this.timeout = builder.timeout != null ? builder.timeout : Duration.ofSeconds(10);
        this.userAgent = builder.userAgent != null ? builder.userAgent : "domscan-java/0.3.0";
        this.httpClient = builder.httpClient != null ? builder.httpClient : HttpClient.newBuilder().connectTimeout(this.timeout).build();
        this.defaultHeaders = builder.headers != null ? new LinkedHashMap<>(builder.headers) : new LinkedHashMap<>();
        this.availability = new AvailabilityService(this);
        this.dns = new DnsService(this);
        this.domain = new DomainService(this);
        this.intelligence = new IntelligenceService(this);
        this.meta = new MetaService(this);
        this.osint = new OsintService(this);
        this.pricing = new PricingService(this);
        this.recipes = new RecipesService(this);
        this.security = new SecurityService(this);
        this.social = new SocialService(this);
        this.user = new UserService(this);
    }

    private String request(Endpoint endpoint, Map<String, Object> params) throws IOException, InterruptedException {
        Map<String, Object> source = params != null ? new LinkedHashMap<>(params) : new LinkedHashMap<>();
        String requestPath = endpoint.path;
        Map<String, Boolean> consumedKeys = new LinkedHashMap<>();

        for (String pathParam : endpoint.pathParams) {
            Object value = source.get(pathParam);
            if (value == null) {
                throw new IllegalArgumentException("Missing required path parameter: " + pathParam);
            }
            requestPath = requestPath.replace(":" + pathParam, encode(value));
            consumedKeys.put(pathParam, true);
        }

        Map<String, Object> remaining = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            if (entry.getValue() == null || consumedKeys.containsKey(entry.getKey())) {
                continue;
            }
            remaining.put(entry.getKey(), entry.getValue());
        }

        Map<String, Object> queryPayload = new LinkedHashMap<>();
        if (endpoint.hasBody) {
            for (String queryKey : endpoint.queryParams) {
                if (remaining.containsKey(queryKey)) {
                    queryPayload.put(queryKey, remaining.get(queryKey));
                }
            }
        } else {
            queryPayload.putAll(remaining);
        }

        StringBuilder urlBuilder = new StringBuilder(baseUrl).append(requestPath);
        if (!queryPayload.isEmpty()) {
            StringJoiner joiner = new StringJoiner("&");
            for (Map.Entry<String, Object> entry : queryPayload.entrySet()) {
                joiner.add(encode(entry.getKey()) + "=" + encode(serializeQueryValue(entry.getValue())));
            }
            urlBuilder.append("?").append(joiner);
        }

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(urlBuilder.toString()))
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("User-Agent", userAgent)
            .header("X-DomScan-SDK", userAgent);

        if (apiKey != null && !apiKey.isBlank()) {
            requestBuilder.header("Authorization", "Bearer " + apiKey);
            requestBuilder.header("X-API-Key", apiKey);
        }

        for (Map.Entry<String, String> header : defaultHeaders.entrySet()) {
            requestBuilder.header(header.getKey(), header.getValue());
        }

        if (endpoint.hasBody) {
            Map<String, Object> bodyPayload = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : remaining.entrySet()) {
                if (!endpoint.queryParams.contains(entry.getKey())) {
                    bodyPayload.put(entry.getKey(), entry.getValue());
                }
            }
            requestBuilder.header("Content-Type", "application/json");
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.ofString(toJson(bodyPayload)));
        } else {
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        String payload = response.body();
        if (response.statusCode() < 400) {
            return payload;
        }

        throw new APIError(
            extractJsonField(payload, "message", "DomScan request failed with status " + response.statusCode()),
            response.statusCode(),
            extractJsonField(payload, "code", null),
            payload,
            response.headers().firstValue("x-request-id").orElse(null)
        );
    }

    private static String trimTrailingSlash(String value) {
        return value.replaceAll("/+$", "");
    }

    private static String encode(Object value) {
        return URLEncoder.encode(String.valueOf(value), StandardCharsets.UTF_8);
    }

    private static String serializeQueryValue(Object value) {
        if (value instanceof Iterable<?> iterable) {
            List<String> parts = new ArrayList<>();
            for (Object item : iterable) {
                if (item != null) {
                    parts.add(serializeQueryValue(item));
                }
            }
            return String.join(",", parts);
        }
        if (value instanceof Boolean boolValue) {
            return boolValue ? "true" : "false";
        }
        if (value instanceof TemporalAccessor) {
            return value.toString();
        }
        if (value instanceof Map<?, ?> || value instanceof List<?>) {
            return toJson(value);
        }
        return String.valueOf(value);
    }

    private static String toJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String stringValue) {
            return quote(stringValue);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        if (value instanceof Map<?, ?> mapValue) {
            StringJoiner joiner = new StringJoiner(",", "{", "}");
            for (Map.Entry<?, ?> entry : mapValue.entrySet()) {
                joiner.add(quote(String.valueOf(entry.getKey())) + ":" + toJson(entry.getValue()));
            }
            return joiner.toString();
        }
        if (value instanceof Iterable<?> iterable) {
            StringJoiner joiner = new StringJoiner(",", "[", "]");
            for (Object item : iterable) {
                joiner.add(toJson(item));
            }
            return joiner.toString();
        }
        return quote(String.valueOf(value));
    }

    private static String quote(String value) {
        return "\""+ value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t") + "\"";
    }

    private static String extractJsonField(String json, String field, String fallback) {
        String needle = "\"" + field + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) {
            return fallback;
        }
        int valueStart = start + needle.length();
        int valueEnd = json.indexOf('"', valueStart);
        if (valueEnd < 0) {
            return fallback;
        }
        return json.substring(valueStart, valueEnd);
    }

    public static final class Builder {
        private String apiKey;
        private String baseUrl;
        private Duration timeout;
        private String userAgent;
        private HttpClient httpClient;
        private Map<String, String> headers;

        public Builder apiKey(String value) {
            this.apiKey = value;
            return this;
        }

        public Builder baseUrl(String value) {
            this.baseUrl = value;
            return this;
        }

        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        public Builder userAgent(String value) {
            this.userAgent = value;
            return this;
        }

        public Builder httpClient(HttpClient value) {
            this.httpClient = value;
            return this;
        }

        public Builder headers(Map<String, String> value) {
            this.headers = value;
            return this;
        }

        public DomScanClient build() {
            return new DomScanClient(this);
        }
    }

    public abstract static class Service {
        protected final DomScanClient client;

        protected Service(DomScanClient client) {
            this.client = client;
        }
    }

    public static final class APIError extends IOException {
        public final int status;
        public final String code;
        public final String details;
        public final String requestId;

        public APIError(String message, int status, String code, String details, String requestId) {
            super(message);
            this.status = status;
            this.code = code;
            this.details = details;
            this.requestId = requestId;
        }
    }

    private record Endpoint(String method, String path, List<String> pathParams, List<String> queryParams, boolean hasBody) {}

    public static final class AvailabilityService extends Service {
        private AvailabilityService(DomScanClient client) {
            super(client);
        }

        /**
         * Check availability of multiple complete domain names at once.
         */
        public String bulkCheckDomains(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/status/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
         */
        public String checkDomainAvailability(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/status",
                List.of(),
                List.of("name", "tlds", "domain", "prefer_cache"),
                false
            ), params);
        }

        /**
         * Create a resumable asynchronous search over a curated English single-word corpus sourced from iannuttall/unclaimed under the MIT License. Check each selected word across 1 to 5 supported TLDs, with a hard limit of 100 word-TLD checks per job. Available, registered, and unknown remain distinct outcomes. Jobs use the existing batch status, results, and cancellation lifecycle.
         */
        public String createDomainDiscoveryJob(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/domain-discovery/jobs",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Get information about which TLDs are supported and their RDAP server status.
         */
        public String getCoverage(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/coverage",
                List.of(),
                List.of("live"),
                false
            ), params);
        }
    }

    public static final class DnsService extends Service {
        private DnsService(DomScanClient client) {
            super(client);
        }

        /**
         * Build a DMARC record with policy, reporting, and alignment options.
         */
        public String buildDmarc(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/tools/dmarc/build",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Build an SPF record from configuration options with validation and recommendations.
         */
        public String buildSpf(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/tools/spf/build",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
         */
        public String bulkDnsPropagation(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/dns/propagation/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Check a specific DKIM selector for a domain and validate the public key.
         */
        public String checkDkim(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tools/dkim/check",
                List.of(),
                List.of("domain", "selector"),
                false
            ), params);
        }

        /**
         * Discover DKIM selectors for a domain by checking common selector names.
         */
        public String discoverDkim(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tools/dkim/discover",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
         */
        public String flattenSpf(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/tools/spf/flatten",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
         */
        public String getAllDnsRecords(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/all",
                List.of(),
                List.of("domain", "wildcard_probe"),
                false
            ), params);
        }

        /**
         * Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
         */
        public String getDnsHistory(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/history",
                List.of(),
                List.of("domain", "type", "from", "to", "limit"),
                false
            ), params);
        }

        /**
         * Compare answers from DomScan's configured public recursive resolvers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
         */
        public String getDnsPropagation(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/propagation",
                List.of(),
                List.of("domain", "type", "expected"),
                false
            ), params);
        }

        /**
         * Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
         */
        public String getDnsRecords(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns",
                List.of(),
                List.of("domain", "type"),
                false
            ), params);
        }

        /**
         * Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
         */
        public String getDnsSecurity(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/security",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
         */
        public String getDnsServers(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/servers",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Validate a DMARC record for syntax errors and configuration issues.
         */
        public String validateDmarc(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/tools/dmarc/validate",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
         */
        public String validateSpf(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/tools/spf/validate",
                List.of(),
                List.of(),
                true
            ), params);
        }
    }

    public static final class DomainService extends Service {
        private DomainService(DomScanClient client) {
            super(client);
        }

        /**
         * Get value estimates for multiple domains at once.
         */
        public String bulkDomainValue(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/value/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
         */
        public String bulkGetDomainProfile(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/profile/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Compare up to 50 candidate brand names and return ranked scores.
         */
        public String compareBrandNames(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/score/compare",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Compare two domains side-by-side across multiple metrics and attributes.
         */
        public String compareDomains(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/compare",
                List.of(),
                List.of("domains"),
                false
            ), params);
        }

        /**
         * Comprehensive health checks with DNS, SSL, email, extended TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
         */
        public String getDomainHealth(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/health",
                List.of(),
                List.of("domain", "details"),
                false
            ), params);
        }

        /**
         * Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
         */
        public String getDomainOverview(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/overview",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
         */
        public String getDomainPopularity(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/popularity",
                List.of(),
                List.of("domain", "include_history", "history_limit"),
                false
            ), params);
        }

        /**
         * Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
         */
        public String getDomainPopularityHistory(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/popularity/history",
                List.of(),
                List.of("domain", "limit"),
                false
            ), params);
        }

        /**
         * Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
         */
        public String getDomainProfile(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/profile",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Calculate an overall domain quality score based on multiple factors.
         */
        public String getDomainScore(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/score",
                List.of(),
                List.of("name", "domain"),
                false
            ), params);
        }

        /**
         * Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
         */
        public String getDomainValue(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/value",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Fast health check with essential metrics only.
         */
        public String getQuickHealth(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/health/quick",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Returns scoring dimensions, grade scale, and related scoring endpoints.
         */
        public String getScoreInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/score/info",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Get detailed information about a specific TLD.
         */
        public String getTldDetail(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tlds/:tld",
                List.of("tld"),
                List.of(),
                false
            ), params);
        }

        /**
         * Get list of all supported TLDs with metadata.
         */
        public String getTlds(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tlds",
                List.of(),
                List.of("type", "trust_tier", "use_case"),
                false
            ), params);
        }

        /**
         * AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
         */
        public String suggestDomains(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/suggest",
                List.of(),
                List.of("keywords", "tlds", "style", "industry", "language", "limit", "check"),
                false
            ), params);
        }
    }

    public static final class IntelligenceService extends Service {
        private IntelligenceService(DomScanClient client) {
            super(client);
        }

        /**
         * Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
         */
        public String bulkGetHosting(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/hosting/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
         */
        public String bulkGetUrlIntelligence(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/url-intelligence/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
         */
        public String bulkGetWebsiteIdentityAssets(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/identity-assets/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
         */
        public String bulkResolveInternetIdentity(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/identity-resolution/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Cancel unstarted technology scan work and settle item-level refunds. Work already in progress may finish and remains available in the job results.
         */
        public String cancelTechScanJob(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "DELETE",
                "/v1/tech/jobs/:job_id",
                List.of("job_id"),
                List.of(),
                false
            ), params);
        }

        /**
         * Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
         */
        public String categorizeWebsite(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/categorize",
                List.of(),
                List.of("url", "domain", "skip_cache", "min_confidence"),
                false
            ), params);
        }

        /**
         * Categorize up to 10 websites in parallel with caching.
         */
        public String categorizeWebsiteBulk(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/categorize/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Queue 1 to 100 public page scrapes for asynchronous processing. Batch jobs are available to paid accounts, require an idempotency key, allow up to three active jobs and 300 queued items per account, and bill each accepted URL at the selected mode price. CAPTCHA solving and premium proxy selection are not offered.
         */
        public String createScrapeJob(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/scrape/jobs",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
         */
        public String createTechScanJob(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/tech/jobs",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
         */
        public String getCategorizationTaxonomy(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/categorize/taxonomy",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Extract source-backed organization names, descriptions, declared social links, MX-inferred email providers, confidence, and provenance from public website and DNS metadata. Enrichment-only fields can be null.
         */
        public String getCompany(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/company",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Compare domains for similarity. Detect typosquatting with multiple algorithms.
         */
        public String getDomainSimilarity(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/similarity",
                List.of(),
                List.of("domain1", "domain2"),
                false
            ), params);
        }

        /**
         * Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
         */
        public String getHosting(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/hosting",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
         */
        public String getParkingDetection(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/parking",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
         */
        public String getRedirects(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/redirects",
                List.of(),
                List.of("url", "domain"),
                false
            ), params);
        }

        /**
         * Get owner-scoped progress, item counts, billing settlement, and expiration details.
         */
        public String getScrapeJob(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/scrape/jobs/:job_id",
                List.of("job_id"),
                List.of(),
                false
            ), params);
        }

        /**
         * Get ordered, paginated results for an owner-scoped scrape job. Full page results expire after 24 hours.
         */
        public String getScrapeJobResults(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/scrape/jobs/:job_id/results",
                List.of("job_id"),
                List.of("limit", "offset"),
                false
            ), params);
        }

        /**
         * Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
         */
        public String getTechScanJob(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tech/jobs/:job_id",
                List.of("job_id"),
                List.of(),
                false
            ), params);
        }

        /**
         * Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
         */
        public String getTechScanJobResults(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tech/jobs/:job_id/results",
                List.of("job_id"),
                List.of("cursor", "limit"),
                false
            ), params);
        }

        /**
         * Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
         */
        public String getTechStack(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tech",
                List.of(),
                List.of("url", "domain", "mode", "max_pages", "skip_cache"),
                false
            ), params);
        }

        /**
         * Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
         */
        public String getUrlIntelligence(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/url-intelligence",
                List.of(),
                List.of("url", "skip_cache"),
                false
            ), params);
        }

        /**
         * Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
         */
        public String getWebsiteIdentityAssets(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/identity-assets",
                List.of(),
                List.of("domain", "skip_cache"),
                false
            ), params);
        }

        /**
         * List recent short-lived technology scan jobs for the authenticated account.
         */
        public String listTechScanJobs(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tech/jobs",
                List.of(),
                List.of("limit", "cursor"),
                false
            ), params);
        }

        /**
         * Run up to 10 ordered fast technology scans in one request. Each attempted target is billed independently, including target-site failures. Verified DomScan service failures are refunded independently.
         */
        public String postTechStackBulk(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/tech/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
         */
        public String resolveInternetIdentity(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/identity-resolution",
                List.of(),
                List.of("domain", "skip_cache"),
                false
            ), params);
        }

        /**
         * Retrieve one public web page with bounded redirects and response size. Standard requests use one attempt, resilient requests may use one eligible retry, and rendered modes execute page JavaScript in an isolated browser. Free accounts can use standard mode with lower request, concurrency, daily, monthly, and response-size limits. CAPTCHA solving and premium proxy selection are not offered. Target-site failures remain billable after processing starts; verified platform failures are refunded.
         */
        public String scrapePage(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/scrape",
                List.of(),
                List.of(),
                true
            ), params);
        }
    }

    public static final class MetaService extends Service {
        private MetaService(DomScanClient client) {
            super(client);
        }

        /**
         * Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
         */
        public String cancelApiBatch(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "DELETE",
                "/v1/batches/:job_id",
                List.of("job_id"),
                List.of(),
                false
            ), params);
        }

        /**
         * Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and refund rules. Target-site outcomes remain billed, while verified service failures are refunded independently.
         */
        public String createApiBatch(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/batches",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Download the full disposable email domain dataset in various formats.
         */
        public String downloadEmailBlacklist(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/blacklist/download",
                List.of(),
                List.of("format"),
                false
            ), params);
        }

        /**
         * Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
         */
        public String getApiBatch(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/batches/:job_id",
                List.of("job_id"),
                List.of(),
                false
            ), params);
        }

        /**
         * Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
         */
        public String getApiBatchResults(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/batches/:job_id/results",
                List.of("job_id"),
                List.of("after", "limit", "format"),
                false
            ), params);
        }

        /**
         * Browse the disposable email domain dataset as a paginated data feed.
         */
        public String getEmailBlacklistInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/blacklist",
                List.of(),
                List.of("limit", "offset", "format"),
                false
            ), params);
        }

        /**
         * Get credit costs per endpoint and API pricing information.
         */
        public String getPricingInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/pricing",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * List unexpired asynchronous API batches for the active customer account.
         */
        public String listApiBatches(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/batches",
                List.of(),
                List.of("limit"),
                false
            ), params);
        }
    }

    public static final class OsintService extends Service {
        private OsintService(DomScanClient client) {
            super(client);
        }

        /**
         * Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
         */
        public String bulkGetRdap(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/rdap/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Get WHOIS data for multiple domains at once.
         */
        public String bulkWhois(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/whois/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
         */
        public String getDomainLifecycle(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/lifecycle",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
         */
        public String getIpInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ip",
                List.of(),
                List.of("ip", "domain"),
                false
            ), params);
        }

        /**
         * Lookup MAC address vendor information. Identify network device manufacturers.
         */
        public String getMacInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/mac",
                List.of(),
                List.of("mac"),
                false
            ), params);
        }

        /**
         * Returns parameter help and an example response for the MAC address lookup endpoint.
         */
        public String getMacLookupInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/mac/info",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Get raw RDAP response for a domain, IP address, or autonomous system number.
         */
        public String getRdap(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/rdap",
                List.of(),
                List.of("query", "type", "domain"),
                false
            ), params);
        }

        /**
         * Get structured WHOIS/RDAP registration data for a domain.
         */
        public String getWhois(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/whois",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
         */
        public String getWhoisHistory(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/whois/history",
                List.of(),
                List.of("domain", "limit"),
                false
            ), params);
        }

        /**
         * Fetch RDAP and traditional WHOIS in parallel, then merge available abuse contacts, registrar WHOIS details, glue addresses, and raw WHOIS evidence into the normalized response.
         */
        public String getWhoisV2(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v2/whois",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }
    }

    public static final class PricingService extends Service {
        private PricingService(DomScanClient client) {
            super(client);
        }

        /**
         * Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
         */
        public String bulkPricing(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/prices/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
         */
        public String comparePrices(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/prices/compare",
                List.of(),
                List.of("domain", "registrars", "skip_cache"),
                false
            ), params);
        }

        /**
         * Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
         */
        public String getPrices(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/prices",
                List.of(),
                List.of("tlds", "registrars", "skip_cache"),
                false
            ), params);
        }

        /**
         * List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
         */
        public String getRegistrars(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/prices/registrars",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
         */
        public String getTldPricing(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/prices/tld/:tld",
                List.of("tld"),
                List.of("registrars", "skip_cache"),
                false
            ), params);
        }
    }

    public static final class RecipesService extends Service {
        private RecipesService(DomScanClient client) {
            super(client);
        }

        /**
         * Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
         */
        public String recipeBrandLaunch(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/brand-launch",
                List.of(),
                List.of("domain", "brand_name", "platforms"),
                false
            ), params);
        }

        /**
         * Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
         */
        public String recipeCompetitorIntel(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/competitor-intel",
                List.of(),
                List.of("domain", "discover_subdomains", "analyze_infrastructure", "analyze_email"),
                false
            ), params);
        }

        /**
         * Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
         */
        public String recipeDefensiveRegistration(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/defensive-registration",
                List.of(),
                List.of("brand", "owned_domains", "priority_tlds", "include_typos", "budget"),
                false
            ), params);
        }

        /**
         * Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
         */
        public String recipeDnsMigration(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/dns-migration",
                List.of(),
                List.of("domain", "target_nameservers", "critical_records"),
                false
            ), params);
        }

        /**
         * AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
         */
        public String recipeDomainFinder(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/domain-finder",
                List.of(),
                List.of("keywords", "tlds", "style", "max_length", "language", "limit"),
                false
            ), params);
        }

        /**
         * Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
         */
        public String recipeDueDiligence(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/due-diligence",
                List.of(),
                List.of("domain", "include_competitors"),
                false
            ), params);
        }

        /**
         * Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
         */
        public String recipeEmailDeliverability(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/email-deliverability",
                List.of(),
                List.of("domain", "dkim_selectors", "check_blacklists"),
                false
            ), params);
        }

        /**
         * Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
         */
        public String recipeInfrastructureDiscovery(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/infrastructure-discovery",
                List.of(),
                List.of("domain", "depth", "include_historical"),
                false
            ), params);
        }

        /**
         * Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
         */
        public String recipePhishingInvestigation(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/phishing-investigation",
                List.of(),
                List.of("suspicious_domain", "legitimate_domain", "collect_evidence"),
                false
            ), params);
        }

        /**
         * Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
         */
        public String recipePortfolioAudit(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/portfolio-audit",
                List.of(),
                List.of("domains", "include_valuation", "include_health", "include_pricing", "alert_expiring_days"),
                false
            ), params);
        }

        /**
         * Audit domain portfolio via POST for larger domain lists.
         */
        public String recipePortfolioAuditPost(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/recipes/portfolio-audit",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
         */
        public String recipeThreatAssessment(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/threat-assessment",
                List.of(),
                List.of("domain", "analyze_threats", "max_threats", "include_evidence"),
                false
            ), params);
        }
    }

    public static final class SecurityService extends Service {
        private SecurityService(DomScanClient client) {
            super(client);
        }

        /**
         * Check multiple email domains against blacklists at once.
         */
        public String bulkEmailCheck(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/email/check/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
         */
        public String bulkGetCertificates(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/certificates/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
         */
        public String bulkGetEmailAuth(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/email-auth/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
         */
        public String bulkGetSubdomains(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/subdomains/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Check if an email domain is on disposable/temporary email blacklists.
         */
        public String checkEmailBlacklist(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/check",
                List.of(),
                List.of("email", "checks"),
                false
            ), params);
        }

        /**
         * Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
         */
        public String getCertificates(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/certificates",
                List.of(),
                List.of("domain", "include_subdomains", "include_expired", "limit", "cursor"),
                false
            ), params);
        }

        /**
         * Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
         */
        public String getDomainReputation(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/reputation",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
         */
        public String getEmailAuth(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email-auth",
                List.of(),
                List.of("domain", "selectors"),
                false
            ), params);
        }

        /**
         * Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and mail security checks.
         */
        public String getEmailCompliance(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/compliance",
                List.of(),
                List.of("domain", "selectors", "providers"),
                false
            ), params);
        }

        /**
         * Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
         */
        public String getSslAudit(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ssl/audit",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Analyze the certificate chain including issuer, validity, and trust chain verification.
         */
        public String getSslChain(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ssl/chain",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
         */
        public String getSslDeepScan(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ssl/deep-scan",
                List.of(),
                List.of("domain", "refresh", "profile"),
                false
            ), params);
        }

        /**
         * Check if an SSL certificate is expiring soon with configurable alert threshold.
         */
        public String getSslExpiring(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ssl/expiring",
                List.of(),
                List.of("domain", "days", "threshold_days"),
                false
            ), params);
        }

        /**
         * Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
         */
        public String getSslGrade(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ssl/grade",
                List.of(),
                List.of("domain"),
                false
            ), params);
        }

        /**
         * Return best-effort hostname evidence from public certificate and passive discovery sources. Coverage is incomplete, and results include provenance with optional DNS verification.
         */
        public String getSubdomains(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/subdomains",
                List.of(),
                List.of("domain", "sources", "verify", "include_wildcards", "limit", "prefer_cache"),
                false
            ), params);
        }

        /**
         * Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
         */
        public String getTyposquatting(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/typos",
                List.of(),
                List.of("domain", "check_registered", "limit", "include_tld_swap"),
                false
            ), params);
        }

        /**
         * Correlate exposed software versions with authoritative public advisories and exploitation-priority data, and report deterministic web security misconfigurations separately. Results preserve evidence and unknown coverage.
         */
        public String getVulnerabilities(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/vulnerabilities",
                List.of(),
                List.of("url", "domain", "mode"),
                false
            ), params);
        }

        /**
         * Validate, normalize, and enrich international phone numbers with maintained offline numbering-plan and public allocation data. Results include coverage, provenance, freshness, and limitations without paid or per-number third-party lookups, and never claim current carrier, reachability, subscriber identity, or individual-number assignment.
         */
        public String validatePhoneNumber(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/phone/validate",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and makes no paid or per-number third-party lookup.
         */
        public String validatePhoneNumbersBulk(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/phone/validate/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
         */
        public String verifyEmail(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/verify",
                List.of(),
                List.of("email", "full"),
                false
            ), params);
        }

        /**
         * Verify multiple email addresses at once. Max 100 emails per request.
         */
        public String verifyEmailBulk(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/email/verify/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }
    }

    public static final class SocialService extends Service {
        private SocialService(DomScanClient client) {
            super(client);
        }

        /**
         * Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
         */
        public String bulkCheckSocialHandles(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "POST",
                "/v1/social/bulk",
                List.of(),
                List.of(),
                true
            ), params);
        }

        /**
         * Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
         */
        public String checkSocialHandles(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/social",
                List.of(),
                List.of("handle", "platforms", "resources"),
                false
            ), params);
        }

        /**
         * Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
         */
        public String getSocialInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/social/info",
                List.of(),
                List.of(),
                false
            ), params);
        }
    }

    public static final class UserService extends Service {
        private UserService(DomScanClient client) {
            super(client);
        }

        /**
         * Get the active customer account credit balance without exposing transaction history.
         */
        public String getCreditBalance(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/credits",
                List.of(),
                List.of(),
                false
            ), params);
        }
    }
}
