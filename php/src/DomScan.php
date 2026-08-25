<?php

declare(strict_types=1);

namespace DomScan;

use RuntimeException;

final class ApiException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $status,
        public readonly ?string $codeValue = null,
        public readonly mixed $details = null,
        public readonly ?string $requestId = null
    ) {
        parent::__construct($message, $status);
    }
}

abstract class AbstractService
{
    public function __construct(protected Client $client)
    {
    }
}

final class Client
{
    private string $apiKey;
    private string $baseUrl;
    private int $timeout;
    private string $userAgent;
    private array $defaultHeaders;
    private AvailabilityService $availability;
    private DnsService $dns;
    private DomainService $domain;
    private IntelligenceService $intelligence;
    private MetaService $meta;
    private OsintService $osint;
    private PricingService $pricing;
    private RecipesService $recipes;
    private SecurityService $security;
    private SocialService $social;
    private UserService $user;

    public function __construct(
        ?string $apiKey = null,
        string $baseUrl = 'https://domscan.net',
        int $timeout = 10,
        array $headers = [],
        string $userAgent = 'domscan-php/0.3.0'
    ) {
        $this->apiKey = $apiKey ?? (getenv('DOMSCAN_API_KEY') ?: '');
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->timeout = $timeout;
        $this->userAgent = $userAgent;
        $this->defaultHeaders = $headers;
        $this->availability = new AvailabilityService($this);
        $this->dns = new DnsService($this);
        $this->domain = new DomainService($this);
        $this->intelligence = new IntelligenceService($this);
        $this->meta = new MetaService($this);
        $this->osint = new OsintService($this);
        $this->pricing = new PricingService($this);
        $this->recipes = new RecipesService($this);
        $this->security = new SecurityService($this);
        $this->social = new SocialService($this);
        $this->user = new UserService($this);
    }

    public function availability(): AvailabilityService
    {
        return $this->availability;
    }

    public function dns(): DnsService
    {
        return $this->dns;
    }

    public function domain(): DomainService
    {
        return $this->domain;
    }

    public function intelligence(): IntelligenceService
    {
        return $this->intelligence;
    }

    public function meta(): MetaService
    {
        return $this->meta;
    }

    public function osint(): OsintService
    {
        return $this->osint;
    }

    public function pricing(): PricingService
    {
        return $this->pricing;
    }

    public function recipes(): RecipesService
    {
        return $this->recipes;
    }

    public function security(): SecurityService
    {
        return $this->security;
    }

    public function social(): SocialService
    {
        return $this->social;
    }

    public function user(): UserService
    {
        return $this->user;
    }

    public function request(array $endpoint, array $params = []): mixed
    {
        $requestPath = $endpoint['path'];
        $consumedKeys = [];

        foreach ($endpoint['pathParams'] as $pathParam) {
            if (!array_key_exists($pathParam, $params) || $params[$pathParam] === null) {
                throw new RuntimeException("Missing required path parameter: {$pathParam}");
            }

            $requestPath = str_replace(':' . $pathParam, rawurlencode((string) $params[$pathParam]), $requestPath);
            $consumedKeys[$pathParam] = true;
        }

        $remaining = [];
        foreach ($params as $key => $value) {
            if ($value === null || isset($consumedKeys[$key])) {
                continue;
            }
            $remaining[(string) $key] = $value;
        }

        if ($endpoint['hasBody']) {
            $queryPayload = [];
            foreach ($endpoint['queryParams'] as $queryKey) {
                if (array_key_exists($queryKey, $remaining)) {
                    $queryPayload[$queryKey] = $remaining[$queryKey];
                }
            }
        } else {
            $queryPayload = $remaining;
        }

        $url = $this->baseUrl . $requestPath;
        if ($queryPayload !== []) {
            $url .= '?' . http_build_query(
                array_map(fn ($value) => $this->serializeQueryValue($value), $queryPayload)
            );
        }

        $headers = array_merge([
            'Accept: application/json',
            'User-Agent: ' . $this->userAgent,
            'X-DomScan-SDK: ' . $this->userAgent,
        ], array_map(
            fn ($key, $value) => "{$key}: {$value}",
            array_keys($this->defaultHeaders),
            array_values($this->defaultHeaders)
        ));

        if ($this->apiKey !== '') {
            $headers[] = 'Authorization: Bearer ' . $this->apiKey;
            $headers[] = 'X-API-Key: ' . $this->apiKey;
        }

        $body = null;
        if ($endpoint['hasBody']) {
            $bodyPayload = array_diff_key($remaining, array_flip($endpoint['queryParams']));
            $body = json_encode($bodyPayload, JSON_THROW_ON_ERROR);
            $headers[] = 'Content-Type: application/json';
        }

        $handle = curl_init($url);
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $endpoint['method'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADER => true,
        ]);

        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        $rawResponse = curl_exec($handle);
        if ($rawResponse === false) {
            $message = curl_error($handle);
            if (PHP_VERSION_ID < 80500) {
                curl_close($handle);
            }
            throw new RuntimeException($message);
        }

        $headerSize = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $headerText = substr($rawResponse, 0, $headerSize);
        $bodyText = substr($rawResponse, $headerSize);
        if (PHP_VERSION_ID < 80500) {
            curl_close($handle);
        }

        $payload = $this->decodePayload($bodyText);
        if ($status < 400) {
            return $payload;
        }

        $requestId = null;
        foreach (explode("\r\n", $headerText) as $headerLine) {
            if (stripos($headerLine, 'x-request-id:') === 0) {
                $requestId = trim(substr($headerLine, 13));
                break;
            }
        }

        $errorPayload = is_array($payload) && isset($payload['error']) && is_array($payload['error'])
            ? $payload['error']
            : [];

        throw new ApiException(
            (string) ($errorPayload['message'] ?? "DomScan request failed with status {$status}"),
            $status,
            isset($errorPayload['code']) ? (string) $errorPayload['code'] : null,
            $payload,
            $requestId
        );
    }

    private function decodePayload(string $body): mixed
    {
        if ($body === '') {
            return '';
        }

        try {
            return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $body;
        }
    }

    private function serializeQueryValue(mixed $value): string
    {
        if (is_array($value)) {
            return implode(',', array_map(fn ($item) => $this->serializeQueryValue($item), $value));
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if ($value instanceof \DateTimeInterface) {
            return $value->format(DATE_ATOM);
        }

        if (is_object($value)) {
            return json_encode($value, JSON_THROW_ON_ERROR);
        }

        return (string) $value;
    }
}

final class AvailabilityService extends AbstractService
{
    /**
     * Check availability of multiple complete domain names at once.
     */
    public function bulkCheckDomains(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/status/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
     */
    public function checkDomainAvailability(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/status",
            'pathParams' => [],
            'queryParams' => ["name", "tlds", "domain", "prefer_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Create a resumable asynchronous search over a curated English single-word corpus sourced from iannuttall/unclaimed under the MIT License. Check each selected word across 1 to 5 supported TLDs, with a hard limit of 100 word-TLD checks per job. Available, registered, and unknown remain distinct outcomes. Jobs use the existing batch status, results, and cancellation lifecycle.
     */
    public function createDomainDiscoveryJob(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/domain-discovery/jobs",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Get information about which TLDs are supported and their RDAP server status.
     */
    public function getCoverage(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/coverage",
            'pathParams' => [],
            'queryParams' => ["live"],
            'hasBody' => false,
        ], $params);
    }
}

final class DnsService extends AbstractService
{
    /**
     * Build a DMARC record with policy, reporting, and alignment options.
     */
    public function buildDmarc(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/tools/dmarc/build",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Build an SPF record from configuration options with validation and recommendations.
     */
    public function buildSpf(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/tools/spf/build",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
     */
    public function bulkDnsPropagation(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/dns/propagation/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Check a specific DKIM selector for a domain and validate the public key.
     */
    public function checkDkim(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tools/dkim/check",
            'pathParams' => [],
            'queryParams' => ["domain", "selector"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Discover DKIM selectors for a domain by checking common selector names.
     */
    public function discoverDkim(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tools/dkim/discover",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
     */
    public function flattenSpf(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/tools/spf/flatten",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
     */
    public function getAllDnsRecords(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/all",
            'pathParams' => [],
            'queryParams' => ["domain", "wildcard_probe"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
     */
    public function getDnsHistory(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/history",
            'pathParams' => [],
            'queryParams' => ["domain", "type", "from", "to", "limit"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Compare answers from DomScan's configured public recursive resolvers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
     */
    public function getDnsPropagation(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/propagation",
            'pathParams' => [],
            'queryParams' => ["domain", "type", "expected"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
     */
    public function getDnsRecords(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns",
            'pathParams' => [],
            'queryParams' => ["domain", "type"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
     */
    public function getDnsSecurity(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/security",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
     */
    public function getDnsServers(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/servers",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Validate a DMARC record for syntax errors and configuration issues.
     */
    public function validateDmarc(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/tools/dmarc/validate",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
     */
    public function validateSpf(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/tools/spf/validate",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }
}

final class DomainService extends AbstractService
{
    /**
     * Get value estimates for multiple domains at once.
     */
    public function bulkDomainValue(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/value/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
     */
    public function bulkGetDomainProfile(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/profile/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Compare up to 50 candidate brand names and return ranked scores.
     */
    public function compareBrandNames(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/score/compare",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Compare two domains side-by-side across multiple metrics and attributes.
     */
    public function compareDomains(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/compare",
            'pathParams' => [],
            'queryParams' => ["domains"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Comprehensive health checks with DNS, SSL, email, extended TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
     */
    public function getDomainHealth(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/health",
            'pathParams' => [],
            'queryParams' => ["domain", "details"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
     */
    public function getDomainOverview(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/overview",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
     */
    public function getDomainPopularity(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/popularity",
            'pathParams' => [],
            'queryParams' => ["domain", "include_history", "history_limit"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
     */
    public function getDomainPopularityHistory(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/popularity/history",
            'pathParams' => [],
            'queryParams' => ["domain", "limit"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
     */
    public function getDomainProfile(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/profile",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Calculate an overall domain quality score based on multiple factors.
     */
    public function getDomainScore(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/score",
            'pathParams' => [],
            'queryParams' => ["name", "domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
     */
    public function getDomainValue(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/value",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Fast health check with essential metrics only.
     */
    public function getQuickHealth(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/health/quick",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Returns scoring dimensions, grade scale, and related scoring endpoints.
     */
    public function getScoreInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/score/info",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get detailed information about a specific TLD.
     */
    public function getTldDetail(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tlds/:tld",
            'pathParams' => ["tld"],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get list of all supported TLDs with metadata.
     */
    public function getTlds(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tlds",
            'pathParams' => [],
            'queryParams' => ["type", "trust_tier", "use_case"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
     */
    public function suggestDomains(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/suggest",
            'pathParams' => [],
            'queryParams' => ["keywords", "tlds", "style", "industry", "language", "limit", "check"],
            'hasBody' => false,
        ], $params);
    }
}

final class IntelligenceService extends AbstractService
{
    /**
     * Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
     */
    public function bulkGetHosting(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/hosting/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
     */
    public function bulkGetUrlIntelligence(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/url-intelligence/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
     */
    public function bulkGetWebsiteIdentityAssets(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/identity-assets/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
     */
    public function bulkResolveInternetIdentity(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/identity-resolution/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Cancel unstarted technology scan work and settle item-level refunds. Work already in progress may finish and remains available in the job results.
     */
    public function cancelTechScanJob(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "DELETE",
            'path' => "/v1/tech/jobs/:job_id",
            'pathParams' => ["job_id"],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
     */
    public function categorizeWebsite(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/categorize",
            'pathParams' => [],
            'queryParams' => ["url", "domain", "skip_cache", "min_confidence"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Categorize up to 10 websites in parallel with caching.
     */
    public function categorizeWebsiteBulk(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/categorize/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Queue 1 to 100 public page scrapes for asynchronous processing. Batch jobs are available to paid accounts, require an idempotency key, allow up to three active jobs and 300 queued items per account, and bill each accepted URL at the selected mode price. CAPTCHA solving and premium proxy selection are not offered.
     */
    public function createScrapeJob(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/scrape/jobs",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
     */
    public function createTechScanJob(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/tech/jobs",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
     */
    public function getCategorizationTaxonomy(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/categorize/taxonomy",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Extract source-backed organization names, descriptions, declared social links, MX-inferred email providers, confidence, and provenance from public website and DNS metadata. Enrichment-only fields can be null.
     */
    public function getCompany(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/company",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Compare domains for similarity. Detect typosquatting with multiple algorithms.
     */
    public function getDomainSimilarity(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/similarity",
            'pathParams' => [],
            'queryParams' => ["domain1", "domain2"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
     */
    public function getHosting(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/hosting",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
     */
    public function getParkingDetection(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/parking",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
     */
    public function getRedirects(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/redirects",
            'pathParams' => [],
            'queryParams' => ["url", "domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get owner-scoped progress, item counts, billing settlement, and expiration details.
     */
    public function getScrapeJob(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/scrape/jobs/:job_id",
            'pathParams' => ["job_id"],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get ordered, paginated results for an owner-scoped scrape job. Full page results expire after 24 hours.
     */
    public function getScrapeJobResults(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/scrape/jobs/:job_id/results",
            'pathParams' => ["job_id"],
            'queryParams' => ["limit", "offset"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
     */
    public function getTechScanJob(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tech/jobs/:job_id",
            'pathParams' => ["job_id"],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
     */
    public function getTechScanJobResults(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tech/jobs/:job_id/results",
            'pathParams' => ["job_id"],
            'queryParams' => ["cursor", "limit"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
     */
    public function getTechStack(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tech",
            'pathParams' => [],
            'queryParams' => ["url", "domain", "mode", "max_pages", "skip_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
     */
    public function getUrlIntelligence(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/url-intelligence",
            'pathParams' => [],
            'queryParams' => ["url", "skip_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
     */
    public function getWebsiteIdentityAssets(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/identity-assets",
            'pathParams' => [],
            'queryParams' => ["domain", "skip_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * List recent short-lived technology scan jobs for the authenticated account.
     */
    public function listTechScanJobs(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tech/jobs",
            'pathParams' => [],
            'queryParams' => ["limit", "cursor"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Run up to 10 ordered fast technology scans in one request. Each attempted target is billed independently, including target-site failures. Verified DomScan service failures are refunded independently.
     */
    public function postTechStackBulk(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/tech/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
     */
    public function resolveInternetIdentity(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/identity-resolution",
            'pathParams' => [],
            'queryParams' => ["domain", "skip_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Retrieve one public web page with bounded redirects and response size. Standard requests use one attempt, resilient requests may use one eligible retry, and rendered modes execute page JavaScript in an isolated browser. Free accounts can use standard mode with lower request, concurrency, daily, monthly, and response-size limits. CAPTCHA solving and premium proxy selection are not offered. Target-site failures remain billable after processing starts; verified platform failures are refunded.
     */
    public function scrapePage(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/scrape",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }
}

final class MetaService extends AbstractService
{
    /**
     * Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
     */
    public function cancelApiBatch(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "DELETE",
            'path' => "/v1/batches/:job_id",
            'pathParams' => ["job_id"],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and refund rules. Target-site outcomes remain billed, while verified service failures are refunded independently.
     */
    public function createApiBatch(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/batches",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Download the full disposable email domain dataset in various formats.
     */
    public function downloadEmailBlacklist(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/blacklist/download",
            'pathParams' => [],
            'queryParams' => ["format"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
     */
    public function getApiBatch(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/batches/:job_id",
            'pathParams' => ["job_id"],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
     */
    public function getApiBatchResults(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/batches/:job_id/results",
            'pathParams' => ["job_id"],
            'queryParams' => ["after", "limit", "format"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Browse the disposable email domain dataset as a paginated data feed.
     */
    public function getEmailBlacklistInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/blacklist",
            'pathParams' => [],
            'queryParams' => ["limit", "offset", "format"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get credit costs per endpoint and API pricing information.
     */
    public function getPricingInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/pricing",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * List unexpired asynchronous API batches for the active customer account.
     */
    public function listApiBatches(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/batches",
            'pathParams' => [],
            'queryParams' => ["limit"],
            'hasBody' => false,
        ], $params);
    }
}

final class OsintService extends AbstractService
{
    /**
     * Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
     */
    public function bulkGetRdap(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/rdap/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Get WHOIS data for multiple domains at once.
     */
    public function bulkWhois(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/whois/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
     */
    public function getDomainLifecycle(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/lifecycle",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
     */
    public function getIpInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ip",
            'pathParams' => [],
            'queryParams' => ["ip", "domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Lookup MAC address vendor information. Identify network device manufacturers.
     */
    public function getMacInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/mac",
            'pathParams' => [],
            'queryParams' => ["mac"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Returns parameter help and an example response for the MAC address lookup endpoint.
     */
    public function getMacLookupInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/mac/info",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get raw RDAP response for a domain, IP address, or autonomous system number.
     */
    public function getRdap(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/rdap",
            'pathParams' => [],
            'queryParams' => ["query", "type", "domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get structured WHOIS/RDAP registration data for a domain.
     */
    public function getWhois(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/whois",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
     */
    public function getWhoisHistory(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/whois/history",
            'pathParams' => [],
            'queryParams' => ["domain", "limit"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Fetch RDAP and traditional WHOIS in parallel, then merge available abuse contacts, registrar WHOIS details, glue addresses, and raw WHOIS evidence into the normalized response.
     */
    public function getWhoisV2(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v2/whois",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }
}

final class PricingService extends AbstractService
{
    /**
     * Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
     */
    public function bulkPricing(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/prices/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
     */
    public function comparePrices(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/prices/compare",
            'pathParams' => [],
            'queryParams' => ["domain", "registrars", "skip_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
     */
    public function getPrices(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/prices",
            'pathParams' => [],
            'queryParams' => ["tlds", "registrars", "skip_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
     */
    public function getRegistrars(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/prices/registrars",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
     */
    public function getTldPricing(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/prices/tld/:tld",
            'pathParams' => ["tld"],
            'queryParams' => ["registrars", "skip_cache"],
            'hasBody' => false,
        ], $params);
    }
}

final class RecipesService extends AbstractService
{
    /**
     * Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
     */
    public function recipeBrandLaunch(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/brand-launch",
            'pathParams' => [],
            'queryParams' => ["domain", "brand_name", "platforms"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
     */
    public function recipeCompetitorIntel(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/competitor-intel",
            'pathParams' => [],
            'queryParams' => ["domain", "discover_subdomains", "analyze_infrastructure", "analyze_email"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
     */
    public function recipeDefensiveRegistration(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/defensive-registration",
            'pathParams' => [],
            'queryParams' => ["brand", "owned_domains", "priority_tlds", "include_typos", "budget"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
     */
    public function recipeDnsMigration(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/dns-migration",
            'pathParams' => [],
            'queryParams' => ["domain", "target_nameservers", "critical_records"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
     */
    public function recipeDomainFinder(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/domain-finder",
            'pathParams' => [],
            'queryParams' => ["keywords", "tlds", "style", "max_length", "language", "limit"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
     */
    public function recipeDueDiligence(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/due-diligence",
            'pathParams' => [],
            'queryParams' => ["domain", "include_competitors"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
     */
    public function recipeEmailDeliverability(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/email-deliverability",
            'pathParams' => [],
            'queryParams' => ["domain", "dkim_selectors", "check_blacklists"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
     */
    public function recipeInfrastructureDiscovery(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/infrastructure-discovery",
            'pathParams' => [],
            'queryParams' => ["domain", "depth", "include_historical"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
     */
    public function recipePhishingInvestigation(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/phishing-investigation",
            'pathParams' => [],
            'queryParams' => ["suspicious_domain", "legitimate_domain", "collect_evidence"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
     */
    public function recipePortfolioAudit(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/portfolio-audit",
            'pathParams' => [],
            'queryParams' => ["domains", "include_valuation", "include_health", "include_pricing", "alert_expiring_days"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Audit domain portfolio via POST for larger domain lists.
     */
    public function recipePortfolioAuditPost(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/recipes/portfolio-audit",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
     */
    public function recipeThreatAssessment(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/threat-assessment",
            'pathParams' => [],
            'queryParams' => ["domain", "analyze_threats", "max_threats", "include_evidence"],
            'hasBody' => false,
        ], $params);
    }
}

final class SecurityService extends AbstractService
{
    /**
     * Check multiple email domains against blacklists at once.
     */
    public function bulkEmailCheck(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/email/check/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
     */
    public function bulkGetCertificates(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/certificates/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
     */
    public function bulkGetEmailAuth(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/email-auth/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
     */
    public function bulkGetSubdomains(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/subdomains/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Check if an email domain is on disposable/temporary email blacklists.
     */
    public function checkEmailBlacklist(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/check",
            'pathParams' => [],
            'queryParams' => ["email", "checks"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
     */
    public function getCertificates(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/certificates",
            'pathParams' => [],
            'queryParams' => ["domain", "include_subdomains", "include_expired", "limit", "cursor"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
     */
    public function getDomainReputation(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/reputation",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
     */
    public function getEmailAuth(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email-auth",
            'pathParams' => [],
            'queryParams' => ["domain", "selectors"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and mail security checks.
     */
    public function getEmailCompliance(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/compliance",
            'pathParams' => [],
            'queryParams' => ["domain", "selectors", "providers"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
     */
    public function getSslAudit(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ssl/audit",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Analyze the certificate chain including issuer, validity, and trust chain verification.
     */
    public function getSslChain(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ssl/chain",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
     */
    public function getSslDeepScan(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ssl/deep-scan",
            'pathParams' => [],
            'queryParams' => ["domain", "refresh", "profile"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Check if an SSL certificate is expiring soon with configurable alert threshold.
     */
    public function getSslExpiring(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ssl/expiring",
            'pathParams' => [],
            'queryParams' => ["domain", "days", "threshold_days"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
     */
    public function getSslGrade(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ssl/grade",
            'pathParams' => [],
            'queryParams' => ["domain"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Return best-effort hostname evidence from public certificate and passive discovery sources. Coverage is incomplete, and results include provenance with optional DNS verification.
     */
    public function getSubdomains(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/subdomains",
            'pathParams' => [],
            'queryParams' => ["domain", "sources", "verify", "include_wildcards", "limit", "prefer_cache"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
     */
    public function getTyposquatting(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/typos",
            'pathParams' => [],
            'queryParams' => ["domain", "check_registered", "limit", "include_tld_swap"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Correlate exposed software versions with authoritative public advisories and exploitation-priority data, and report deterministic web security misconfigurations separately. Results preserve evidence and unknown coverage.
     */
    public function getVulnerabilities(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/vulnerabilities",
            'pathParams' => [],
            'queryParams' => ["url", "domain", "mode"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Validate, normalize, and enrich international phone numbers with maintained offline numbering-plan and public allocation data. Results include coverage, provenance, freshness, and limitations without paid or per-number third-party lookups, and never claim current carrier, reachability, subscriber identity, or individual-number assignment.
     */
    public function validatePhoneNumber(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/phone/validate",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and makes no paid or per-number third-party lookup.
     */
    public function validatePhoneNumbersBulk(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/phone/validate/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
     */
    public function verifyEmail(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/verify",
            'pathParams' => [],
            'queryParams' => ["email", "full"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Verify multiple email addresses at once. Max 100 emails per request.
     */
    public function verifyEmailBulk(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/email/verify/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }
}

final class SocialService extends AbstractService
{
    /**
     * Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
     */
    public function bulkCheckSocialHandles(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "POST",
            'path' => "/v1/social/bulk",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => true,
        ], $params);
    }

    /**
     * Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
     */
    public function checkSocialHandles(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/social",
            'pathParams' => [],
            'queryParams' => ["handle", "platforms", "resources"],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
     */
    public function getSocialInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/social/info",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }
}

final class UserService extends AbstractService
{
    /**
     * Get the active customer account credit balance without exposing transaction history.
     */
    public function getCreditBalance(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/credits",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }
}
