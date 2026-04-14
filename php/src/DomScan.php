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

    public function __construct(
        ?string $apiKey = null,
        string $baseUrl = 'https://domscan.net',
        int $timeout = 10,
        array $headers = [],
        string $userAgent = 'domscan-php/0.1.0'
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
            curl_close($handle);
            throw new RuntimeException($message);
        }

        $headerSize = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $headerText = substr($rawResponse, 0, $headerSize);
        $bodyText = substr($rawResponse, $headerSize);
        curl_close($handle);

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
     * Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
     */
    public function checkDomainAvailability(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/status",
            'pathParams' => [],
            'queryParams' => ["name", "tlds", "prefer_cache"],
            'hasBody' => false,
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
            'queryParams' => [],
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
     * Check a specific DKIM selector for a domain and validate the public key.
     */
    public function checkDkim(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tools/dkim/check",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
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
     * Get all DNS record types for a domain in a single call.
     */
    public function getAllDnsRecords(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/all",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Compare DNS records between two dates to see what changed.
     */
    public function getDnsDiff(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/diff",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Track DNS record changes over time. Data accumulates from API lookups.
     */
    public function getDnsHistory(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/history",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Check DNS propagation across multiple global DNS servers.
     */
    public function getDnsPropagation(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/propagation",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
     */
    public function getDnsRecords(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
     */
    public function getDnsSecurity(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/security",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get list of global DNS servers used for propagation checks.
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
     * Compare two domains side-by-side across multiple metrics and attributes.
     */
    public function compareDomains(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/compare",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
     */
    public function getDomainHealth(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/health",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
     */
    public function getDomainOverview(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/overview",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
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
            'queryParams' => [],
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
            'queryParams' => [],
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
            'queryParams' => [],
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
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }
}

final class IntelligenceService extends AbstractService
{
    /**
     * Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
     */
    public function categorizeWebsite(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/categorize",
            'pathParams' => [],
            'queryParams' => [],
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
     * Extract company information from a domain. Get name, industry, and contact details.
     */
    public function getCompany(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/company",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
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
            'queryParams' => [],
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
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Detect website technologies: CDN, CMS, frameworks, analytics, and more.
     */
    public function getTechStack(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/tech",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }
}

final class MetaService extends AbstractService
{
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
}

final class OsintService extends AbstractService
{
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
     * Find domains that use a specific nameserver.
     */
    public function getDnsReverseNs(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/dns/reverse/ns",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Map domain relationships through shared infrastructure and registrant data.
     */
    public function getDomainGraph(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/graph",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
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
     * Get IP addresses with geolocation, ASN, and hosting provider information.
     */
    public function getIpInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ip",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Find all domains hosted on a specific IP address.
     */
    public function getReverseIp(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/reverse/ip",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Find all domains using a specific mail server for email infrastructure mapping.
     */
    public function getReverseMx(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/reverse/mx",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
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
}

final class PricingService extends AbstractService
{
    /**
     * Get pricing for multiple domains at once.
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
     * Compare domain prices across multiple registrars.
     */
    public function comparePrices(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/prices/compare",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get domain registration and renewal prices across registrars.
     */
    public function getPrices(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/prices",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get list of supported registrars with pricing data.
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
     * Get pricing for a specific TLD across registrars.
     */
    public function getTldPricing(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/prices/tld/:tld",
            'pathParams' => ["tld"],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }
}

final class RecipesService extends AbstractService
{
    /**
     * Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
     */
    public function recipeBrandLaunch(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/brand-launch",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
     */
    public function recipeCompetitorIntel(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/competitor-intel",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
     */
    public function recipeDefensiveRegistration(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/defensive-registration",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
     */
    public function recipeDnsMigration(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/dns-migration",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
     */
    public function recipeDomainFinder(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/domain-finder",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
     */
    public function recipeDueDiligence(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/due-diligence",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
     */
    public function recipeEmailDeliverability(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/email-deliverability",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
     */
    public function recipeInfrastructureDiscovery(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/infrastructure-discovery",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
     */
    public function recipePhishingInvestigation(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/phishing-investigation",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
     */
    public function recipePortfolioAudit(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/portfolio-audit",
            'pathParams' => [],
            'queryParams' => [],
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
     * Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
     */
    public function recipeThreatAssessment(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/recipes/threat-assessment",
            'pathParams' => [],
            'queryParams' => [],
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
     * Check if an email domain is on disposable/temporary email blacklists.
     */
    public function checkEmailBlacklist(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/check",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Download the full email blacklist database in various formats.
     */
    public function downloadEmailBlacklist(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/blacklist/download",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Check domain reputation across security feeds, blacklists, and threat intelligence.
     */
    public function getDomainReputation(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/reputation",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Check DMARC, SPF, and DKIM configurations for email security auditing.
     */
    public function getEmailAuth(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email-auth",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Get information about the email blacklist database.
     */
    public function getEmailBlacklistInfo(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/email/blacklist",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
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
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
     */
    public function getSslGrade(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/ssl/grade",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Discover subdomains using Certificate Transparency and DNS enumeration.
     */
    public function getSubdomains(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/subdomains",
            'pathParams' => [],
            'queryParams' => [],
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
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }

    /**
     * Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
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
     * Check username availability across social platforms like GitHub, Reddit, and more.
     */
    public function checkSocialHandles(array $params = []): mixed
    {
        return $this->client->request([
            'method' => "GET",
            'path' => "/v1/social",
            'pathParams' => [],
            'queryParams' => [],
            'hasBody' => false,
        ], $params);
    }
}
