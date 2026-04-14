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

    public DomScanClient() {
        this(new Builder());
    }

    private DomScanClient(Builder builder) {
        this.apiKey = builder.apiKey != null ? builder.apiKey : System.getenv("DOMSCAN_API_KEY");
        this.baseUrl = trimTrailingSlash(builder.baseUrl != null ? builder.baseUrl : "https://domscan.net");
        this.timeout = builder.timeout != null ? builder.timeout : Duration.ofSeconds(10);
        this.userAgent = builder.userAgent != null ? builder.userAgent : "domscan-java/0.1.0";
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
         * Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
         */
        public String checkDomainAvailability(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/status",
                List.of(),
                List.of("name", "tlds", "prefer_cache"),
                false
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
                List.of(),
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
         * Check a specific DKIM selector for a domain and validate the public key.
         */
        public String checkDkim(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tools/dkim/check",
                List.of(),
                List.of(),
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
                List.of(),
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
         * Get all DNS record types for a domain in a single call.
         */
        public String getAllDnsRecords(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/all",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Compare DNS records between two dates to see what changed.
         */
        public String getDnsDiff(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/diff",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Track DNS record changes over time. Data accumulates from API lookups.
         */
        public String getDnsHistory(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/history",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Check DNS propagation across multiple global DNS servers.
         */
        public String getDnsPropagation(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/propagation",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
         */
        public String getDnsRecords(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
         */
        public String getDnsSecurity(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/security",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Get list of global DNS servers used for propagation checks.
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
         * Compare two domains side-by-side across multiple metrics and attributes.
         */
        public String compareDomains(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/compare",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
         */
        public String getDomainHealth(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/health",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
         */
        public String getDomainOverview(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/overview",
                List.of(),
                List.of(),
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
                List.of(),
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
                List.of(),
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
                List.of(),
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
                List.of(),
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
                List.of(),
                false
            ), params);
        }
    }

    public static final class IntelligenceService extends Service {
        private IntelligenceService(DomScanClient client) {
            super(client);
        }

        /**
         * Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
         */
        public String categorizeWebsite(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/categorize",
                List.of(),
                List.of(),
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
         * Extract company information from a domain. Get name, industry, and contact details.
         */
        public String getCompany(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/company",
                List.of(),
                List.of(),
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
                List.of(),
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
                List.of(),
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
                List.of(),
                false
            ), params);
        }

        /**
         * Detect website technologies: CDN, CMS, frameworks, analytics, and more.
         */
        public String getTechStack(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/tech",
                List.of(),
                List.of(),
                false
            ), params);
        }
    }

    public static final class MetaService extends Service {
        private MetaService(DomScanClient client) {
            super(client);
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
    }

    public static final class OsintService extends Service {
        private OsintService(DomScanClient client) {
            super(client);
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
         * Find domains that use a specific nameserver.
         */
        public String getDnsReverseNs(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/dns/reverse/ns",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Map domain relationships through shared infrastructure and registrant data.
         */
        public String getDomainGraph(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/graph",
                List.of(),
                List.of(),
                false
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
         * Get IP addresses with geolocation, ASN, and hosting provider information.
         */
        public String getIpInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ip",
                List.of(),
                List.of(),
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
                List.of(),
                false
            ), params);
        }

        /**
         * Find all domains hosted on a specific IP address.
         */
        public String getReverseIp(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/reverse/ip",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Find all domains using a specific mail server for email infrastructure mapping.
         */
        public String getReverseMx(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/reverse/mx",
                List.of(),
                List.of(),
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
                List.of(),
                false
            ), params);
        }

        /**
         * Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
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
    }

    public static final class PricingService extends Service {
        private PricingService(DomScanClient client) {
            super(client);
        }

        /**
         * Get pricing for multiple domains at once.
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
         * Compare domain prices across multiple registrars.
         */
        public String comparePrices(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/prices/compare",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Get domain registration and renewal prices across registrars.
         */
        public String getPrices(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/prices",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Get list of supported registrars with pricing data.
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
         * Get pricing for a specific TLD across registrars.
         */
        public String getTldPricing(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/prices/tld/:tld",
                List.of("tld"),
                List.of(),
                false
            ), params);
        }
    }

    public static final class RecipesService extends Service {
        private RecipesService(DomScanClient client) {
            super(client);
        }

        /**
         * Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
         */
        public String recipeBrandLaunch(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/brand-launch",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
         */
        public String recipeCompetitorIntel(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/competitor-intel",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
         */
        public String recipeDefensiveRegistration(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/defensive-registration",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
         */
        public String recipeDnsMigration(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/dns-migration",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
         */
        public String recipeDomainFinder(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/domain-finder",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
         */
        public String recipeDueDiligence(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/due-diligence",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
         */
        public String recipeEmailDeliverability(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/email-deliverability",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
         */
        public String recipeInfrastructureDiscovery(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/infrastructure-discovery",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
         */
        public String recipePhishingInvestigation(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/phishing-investigation",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
         */
        public String recipePortfolioAudit(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/portfolio-audit",
                List.of(),
                List.of(),
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
         * Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
         */
        public String recipeThreatAssessment(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/recipes/threat-assessment",
                List.of(),
                List.of(),
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
         * Check if an email domain is on disposable/temporary email blacklists.
         */
        public String checkEmailBlacklist(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/check",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Download the full email blacklist database in various formats.
         */
        public String downloadEmailBlacklist(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/blacklist/download",
                List.of(),
                List.of(),
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
                List.of(),
                false
            ), params);
        }

        /**
         * Check domain reputation across security feeds, blacklists, and threat intelligence.
         */
        public String getDomainReputation(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/reputation",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Check DMARC, SPF, and DKIM configurations for email security auditing.
         */
        public String getEmailAuth(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email-auth",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Get information about the email blacklist database.
         */
        public String getEmailBlacklistInfo(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/email/blacklist",
                List.of(),
                List.of(),
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
                List.of(),
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
                List.of(),
                false
            ), params);
        }

        /**
         * Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
         */
        public String getSslGrade(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/ssl/grade",
                List.of(),
                List.of(),
                false
            ), params);
        }

        /**
         * Discover subdomains using Certificate Transparency and DNS enumeration.
         */
        public String getSubdomains(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/subdomains",
                List.of(),
                List.of(),
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
                List.of(),
                false
            ), params);
        }

        /**
         * Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
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
         * Check username availability across social platforms like GitHub, Reddit, and more.
         */
        public String checkSocialHandles(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                "GET",
                "/v1/social",
                List.of(),
                List.of(),
                false
            ), params);
        }
    }
}
