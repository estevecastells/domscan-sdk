using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace DomScan;

public sealed class DomScanApiException : Exception
{
    public int Status { get; }
    public string? Code { get; }
    public JsonNode? Details { get; }
    public string? RequestId { get; }

    public DomScanApiException(string message, int status, string? code = null, JsonNode? details = null, string? requestId = null)
        : base(message)
    {
        Status = status;
        Code = code;
        Details = details;
        RequestId = requestId;
    }
}

internal sealed record EndpointDefinition(
    string Method,
    string Path,
    IReadOnlyList<string> PathParams,
    IReadOnlyList<string> QueryParams,
    bool HasBody
);

public sealed class DomScanClient : IDisposable
{
    private readonly string? _apiKey;
    private readonly string _baseUrl;
    private readonly string _userAgent;
    private readonly Dictionary<string, string> _headers;
    private readonly HttpClient _httpClient;

    public AvailabilityService Availability { get; }
    public DnsService Dns { get; }
    public DomainService Domain { get; }
    public IntelligenceService Intelligence { get; }
    public MetaService Meta { get; }
    public OsintService Osint { get; }
    public PricingService Pricing { get; }
    public RecipesService Recipes { get; }
    public SecurityService Security { get; }
    public SocialService Social { get; }

    public DomScanClient(
        string? apiKey = null,
        string baseUrl = "https://domscan.net",
        TimeSpan? timeout = null,
        IDictionary<string, string>? headers = null,
        HttpClient? httpClient = null,
        string userAgent = "domscan-csharp/0.2.0"
    )
    {
        _apiKey = string.IsNullOrWhiteSpace(apiKey)
            ? Environment.GetEnvironmentVariable("DOMSCAN_API_KEY")
            : apiKey;
        _baseUrl = baseUrl.TrimEnd('/');
        _userAgent = userAgent;
        _headers = headers != null ? new Dictionary<string, string>(headers) : new Dictionary<string, string>();
        _httpClient = httpClient ?? new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(10) };
        Availability = new AvailabilityService(this);
        Dns = new DnsService(this);
        Domain = new DomainService(this);
        Intelligence = new IntelligenceService(this);
        Meta = new MetaService(this);
        Osint = new OsintService(this);
        Pricing = new PricingService(this);
        Recipes = new RecipesService(this);
        Security = new SecurityService(this);
        Social = new SocialService(this);
    }

    internal async Task<JsonNode?> RequestAsync(
        EndpointDefinition endpoint,
        IDictionary<string, object?>? parameters,
        CancellationToken cancellationToken
    )
    {
        var source = parameters != null
            ? new Dictionary<string, object?>(parameters)
            : new Dictionary<string, object?>();

        var requestPath = endpoint.Path;
        foreach (var pathParam in endpoint.PathParams)
        {
            if (!source.TryGetValue(pathParam, out var rawValue) || rawValue is null)
            {
                throw new ArgumentException($"Missing required path parameter: {pathParam}", nameof(parameters));
            }

            requestPath = requestPath.Replace($":{pathParam}", Uri.EscapeDataString(rawValue.ToString() ?? string.Empty));
            source.Remove(pathParam);
        }

        var queryPayload = endpoint.HasBody
            ? source.Where(item => endpoint.QueryParams.Contains(item.Key) && item.Value is not null)
                .ToDictionary(item => item.Key, item => item.Value)
            : source.Where(item => item.Value is not null)
                .ToDictionary(item => item.Key, item => item.Value);

        var urlBuilder = new StringBuilder(_baseUrl).Append(requestPath);
        if (queryPayload.Count > 0)
        {
            var parts = queryPayload.Select(item => $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(SerializeQueryValue(item.Value))}");
            urlBuilder.Append('?').Append(string.Join("&", parts));
        }

        using var request = new HttpRequestMessage(new HttpMethod(endpoint.Method), urlBuilder.ToString());
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", _userAgent);
        request.Headers.Add("X-DomScan-SDK", _userAgent);

        if (!string.IsNullOrWhiteSpace(_apiKey))
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _apiKey);
            request.Headers.Add("X-API-Key", _apiKey);
        }

        foreach (var header in _headers)
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (endpoint.HasBody)
        {
            var bodyPayload = source
                .Where(item => !endpoint.QueryParams.Contains(item.Key) && item.Value is not null)
                .ToDictionary(item => item.Key, item => item.Value);
            request.Content = new StringContent(JsonSerializer.Serialize(bodyPayload), Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        JsonNode? payload;
        try
        {
            payload = JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            payload = JsonValue.Create(body);
        }

        if (response.IsSuccessStatusCode)
        {
            return payload;
        }

        var errorObject = payload?["error"];
        throw new DomScanApiException(
            errorObject?["message"]?.GetValue<string?>() ?? $"DomScan request failed with status {(int)response.StatusCode}",
            (int)response.StatusCode,
            errorObject?["code"]?.GetValue<string?>(),
            payload,
            response.Headers.TryGetValues("x-request-id", out var values) ? values.FirstOrDefault() : null
        );
    }

    private static string SerializeQueryValue(object? value)
    {
        return value switch
        {
            null => string.Empty,
            string stringValue => stringValue,
            bool boolValue => boolValue ? "true" : "false",
            DateTimeOffset dateTime => dateTime.ToString("O"),
            DateTime dateTime => dateTime.ToString("O"),
            IDictionary dictionary => JsonSerializer.Serialize(dictionary.Cast<DictionaryEntry>().ToDictionary(item => item.Key.ToString()!, item => item.Value)),
            IEnumerable enumerable when value is not string => string.Join(",", enumerable.Cast<object?>().Where(item => item is not null).Select(SerializeQueryValue)),
            _ => value.ToString() ?? string.Empty
        };
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }
}

public sealed class AvailabilityService
{
    private readonly DomScanClient _client;

    internal AvailabilityService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Check availability of multiple complete domain names at once.
        /// </summary>
        public Task<JsonNode?> BulkCheckDomainsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/status/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
        /// </summary>
        public Task<JsonNode?> CheckDomainAvailabilityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/status",
            new string[] {  },
            new string[] { "name", "tlds", "domain", "prefer_cache" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get information about which TLDs are supported and their RDAP server status.
        /// </summary>
        public Task<JsonNode?> GetCoverageAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/coverage",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);
}

public sealed class DnsService
{
    private readonly DomScanClient _client;

    internal DnsService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Build a DMARC record with policy, reporting, and alignment options.
        /// </summary>
        public Task<JsonNode?> BuildDmarcAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/tools/dmarc/build",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Build an SPF record from configuration options with validation and recommendations.
        /// </summary>
        public Task<JsonNode?> BuildSpfAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/tools/spf/build",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
        /// </summary>
        public Task<JsonNode?> BulkDnsPropagationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/dns/propagation/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Check a specific DKIM selector for a domain and validate the public key.
        /// </summary>
        public Task<JsonNode?> CheckDkimAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tools/dkim/check",
            new string[] {  },
            new string[] { "domain", "selector" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Discover DKIM selectors for a domain by checking common selector names.
        /// </summary>
        public Task<JsonNode?> DiscoverDkimAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tools/dkim/discover",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
        /// </summary>
        public Task<JsonNode?> FlattenSpfAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/tools/spf/flatten",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
        /// </summary>
        public Task<JsonNode?> GetAllDnsRecordsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/all",
            new string[] {  },
            new string[] { "domain", "wildcard_probe" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
        /// </summary>
        public Task<JsonNode?> GetDnsHistoryAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/history",
            new string[] {  },
            new string[] { "domain", "type", "from", "to", "limit" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare DNS answers from DomScan's configured Cloudflare and Google public recursive DoH providers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
        /// </summary>
        public Task<JsonNode?> GetDnsPropagationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/propagation",
            new string[] {  },
            new string[] { "domain", "type", "expected" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
        /// </summary>
        public Task<JsonNode?> GetDnsRecordsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns",
            new string[] {  },
            new string[] { "domain", "type" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
        /// </summary>
        public Task<JsonNode?> GetDnsSecurityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/security",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
        /// </summary>
        public Task<JsonNode?> GetDnsServersAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/servers",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Validate a DMARC record for syntax errors and configuration issues.
        /// </summary>
        public Task<JsonNode?> ValidateDmarcAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/tools/dmarc/validate",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
        /// </summary>
        public Task<JsonNode?> ValidateSpfAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/tools/spf/validate",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);
}

public sealed class DomainService
{
    private readonly DomScanClient _client;

    internal DomainService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Get value estimates for multiple domains at once.
        /// </summary>
        public Task<JsonNode?> BulkDomainValueAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/value/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
        /// </summary>
        public Task<JsonNode?> BulkGetDomainProfileAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/profile/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare up to 50 candidate brand names and return ranked scores.
        /// </summary>
        public Task<JsonNode?> CompareBrandNamesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/score/compare",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare two domains side-by-side across multiple metrics and attributes.
        /// </summary>
        public Task<JsonNode?> CompareDomainsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/compare",
            new string[] {  },
            new string[] { "domains" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Comprehensive health checks with DNS, SSL, email, proxy-enriched TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
        /// </summary>
        public Task<JsonNode?> GetDomainHealthAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/health",
            new string[] {  },
            new string[] { "domain", "details" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
        /// </summary>
        public Task<JsonNode?> GetDomainOverviewAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/overview",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
        /// </summary>
        public Task<JsonNode?> GetDomainPopularityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/popularity",
            new string[] {  },
            new string[] { "domain", "include_history", "history_limit" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
        /// </summary>
        public Task<JsonNode?> GetDomainPopularityHistoryAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/popularity/history",
            new string[] {  },
            new string[] { "domain", "limit" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
        /// </summary>
        public Task<JsonNode?> GetDomainProfileAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/profile",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Calculate an overall domain quality score based on multiple factors.
        /// </summary>
        public Task<JsonNode?> GetDomainScoreAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/score",
            new string[] {  },
            new string[] { "name", "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
        /// </summary>
        public Task<JsonNode?> GetDomainValueAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/value",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Fast health check with essential metrics only.
        /// </summary>
        public Task<JsonNode?> GetQuickHealthAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/health/quick",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Returns scoring dimensions, grade scale, and related scoring endpoints.
        /// </summary>
        public Task<JsonNode?> GetScoreInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/score/info",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get detailed information about a specific TLD.
        /// </summary>
        public Task<JsonNode?> GetTldDetailAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tlds/:tld",
            new string[] { "tld" },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get list of all supported TLDs with metadata.
        /// </summary>
        public Task<JsonNode?> GetTldsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tlds",
            new string[] {  },
            new string[] { "type" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
        /// </summary>
        public Task<JsonNode?> SuggestDomainsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/suggest",
            new string[] {  },
            new string[] { "keywords", "tlds", "style", "industry", "language", "limit", "check" },
            false
        ), parameters, cancellationToken);
}

public sealed class IntelligenceService
{
    private readonly DomScanClient _client;

    internal IntelligenceService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
        /// </summary>
        public Task<JsonNode?> BulkGetHostingAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/hosting/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
        /// </summary>
        public Task<JsonNode?> BulkGetUrlIntelligenceAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/url-intelligence/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
        /// </summary>
        public Task<JsonNode?> BulkGetWebsiteIdentityAssetsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/identity-assets/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
        /// </summary>
        public Task<JsonNode?> BulkResolveInternetIdentityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/identity-resolution/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Cancel unstarted technology scan work and settle item-level refunds. An already running browser scan may finish, but its result is discarded.
        /// </summary>
        public Task<JsonNode?> CancelTechScanJobAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "DELETE",
            "/v1/tech/jobs/:job_id",
            new string[] { "job_id" },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
        /// </summary>
        public Task<JsonNode?> CategorizeWebsiteAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/categorize",
            new string[] {  },
            new string[] { "url", "domain", "skip_cache", "min_confidence" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Categorize up to 10 websites in parallel with caching.
        /// </summary>
        public Task<JsonNode?> CategorizeWebsiteBulkAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/categorize/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
        /// </summary>
        public Task<JsonNode?> CreateTechScanJobAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/tech/jobs",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
        /// </summary>
        public Task<JsonNode?> GetCategorizationTaxonomyAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/categorize/taxonomy",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Extract company information from a domain. Get name, industry, and contact details.
        /// </summary>
        public Task<JsonNode?> GetCompanyAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/company",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare domains for similarity. Detect typosquatting with multiple algorithms.
        /// </summary>
        public Task<JsonNode?> GetDomainSimilarityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/similarity",
            new string[] {  },
            new string[] { "domain1", "domain2" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
        /// </summary>
        public Task<JsonNode?> GetHostingAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/hosting",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
        /// </summary>
        public Task<JsonNode?> GetParkingDetectionAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/parking",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
        /// </summary>
        public Task<JsonNode?> GetRedirectsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/redirects",
            new string[] {  },
            new string[] { "url", "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
        /// </summary>
        public Task<JsonNode?> GetTechScanJobAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tech/jobs/:job_id",
            new string[] { "job_id" },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
        /// </summary>
        public Task<JsonNode?> GetTechScanJobResultsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tech/jobs/:job_id/results",
            new string[] { "job_id" },
            new string[] { "cursor", "limit" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
        /// </summary>
        public Task<JsonNode?> GetTechStackAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tech",
            new string[] {  },
            new string[] { "url", "domain", "mode", "max_pages", "skip_cache" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
        /// </summary>
        public Task<JsonNode?> GetUrlIntelligenceAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/url-intelligence",
            new string[] {  },
            new string[] { "url" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
        /// </summary>
        public Task<JsonNode?> GetWebsiteIdentityAssetsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/identity-assets",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// List recent short-lived technology scan jobs for the authenticated account.
        /// </summary>
        public Task<JsonNode?> ListTechScanJobsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tech/jobs",
            new string[] {  },
            new string[] { "limit", "cursor" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Run up to 10 ordered fast technology scans in one request. Each valid target is billed independently, and failed upstream scans are refunded independently.
        /// </summary>
        public Task<JsonNode?> PostTechStackBulkAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/tech/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
        /// </summary>
        public Task<JsonNode?> ResolveInternetIdentityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/identity-resolution",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);
}

public sealed class MetaService
{
    private readonly DomScanClient _client;

    internal MetaService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
        /// </summary>
        public Task<JsonNode?> CancelApiBatchAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "DELETE",
            "/v1/batches/:job_id",
            new string[] { "job_id" },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and failed items are refunded independently.
        /// </summary>
        public Task<JsonNode?> CreateApiBatchAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/batches",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Download the full disposable email domain dataset in various formats.
        /// </summary>
        public Task<JsonNode?> DownloadEmailBlacklistAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/blacklist/download",
            new string[] {  },
            new string[] { "format" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
        /// </summary>
        public Task<JsonNode?> GetApiBatchAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/batches/:job_id",
            new string[] { "job_id" },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
        /// </summary>
        public Task<JsonNode?> GetApiBatchResultsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/batches/:job_id/results",
            new string[] { "job_id" },
            new string[] { "after", "limit", "format" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Browse the disposable email domain dataset as a paginated data feed.
        /// </summary>
        public Task<JsonNode?> GetEmailBlacklistInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/blacklist",
            new string[] {  },
            new string[] { "limit", "offset", "format" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get credit costs per endpoint and API pricing information.
        /// </summary>
        public Task<JsonNode?> GetPricingInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/pricing",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// List unexpired asynchronous API batches for the active customer account.
        /// </summary>
        public Task<JsonNode?> ListApiBatchesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/batches",
            new string[] {  },
            new string[] { "limit" },
            false
        ), parameters, cancellationToken);
}

public sealed class OsintService
{
    private readonly DomScanClient _client;

    internal OsintService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
        /// </summary>
        public Task<JsonNode?> BulkGetRdapAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/rdap/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Get WHOIS data for multiple domains at once.
        /// </summary>
        public Task<JsonNode?> BulkWhoisAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/whois/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
        /// </summary>
        public Task<JsonNode?> GetDomainLifecycleAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/lifecycle",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
        /// </summary>
        public Task<JsonNode?> GetIpInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ip",
            new string[] {  },
            new string[] { "ip", "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Lookup MAC address vendor information. Identify network device manufacturers.
        /// </summary>
        public Task<JsonNode?> GetMacInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/mac",
            new string[] {  },
            new string[] { "mac" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Returns parameter help and an example response for the MAC address lookup endpoint.
        /// </summary>
        public Task<JsonNode?> GetMacLookupInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/mac/info",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get raw RDAP response for a domain, IP address, or autonomous system number.
        /// </summary>
        public Task<JsonNode?> GetRdapAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/rdap",
            new string[] {  },
            new string[] { "query", "type", "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get structured WHOIS/RDAP registration data for a domain.
        /// </summary>
        public Task<JsonNode?> GetWhoisAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/whois",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
        /// </summary>
        public Task<JsonNode?> GetWhoisHistoryAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/whois/history",
            new string[] {  },
            new string[] { "domain", "limit" },
            false
        ), parameters, cancellationToken);
}

public sealed class PricingService
{
    private readonly DomScanClient _client;

    internal PricingService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
        /// </summary>
        public Task<JsonNode?> BulkPricingAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/prices/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
        /// </summary>
        public Task<JsonNode?> ComparePricesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices/compare",
            new string[] {  },
            new string[] { "domain", "registrars", "skip_cache" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
        /// </summary>
        public Task<JsonNode?> GetPricesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices",
            new string[] {  },
            new string[] { "tlds", "registrars", "skip_cache" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
        /// </summary>
        public Task<JsonNode?> GetRegistrarsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices/registrars",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
        /// </summary>
        public Task<JsonNode?> GetTldPricingAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices/tld/:tld",
            new string[] { "tld" },
            new string[] { "registrars", "skip_cache" },
            false
        ), parameters, cancellationToken);
}

public sealed class RecipesService
{
    private readonly DomScanClient _client;

    internal RecipesService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
        /// </summary>
        public Task<JsonNode?> RecipeBrandLaunchAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/brand-launch",
            new string[] {  },
            new string[] { "domain", "brand_name", "platforms" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
        /// </summary>
        public Task<JsonNode?> RecipeCompetitorIntelAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/competitor-intel",
            new string[] {  },
            new string[] { "domain", "discover_subdomains", "analyze_email" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
        /// </summary>
        public Task<JsonNode?> RecipeDefensiveRegistrationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/defensive-registration",
            new string[] {  },
            new string[] { "brand", "owned_domains", "priority_tlds", "include_typos", "budget" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
        /// </summary>
        public Task<JsonNode?> RecipeDnsMigrationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/dns-migration",
            new string[] {  },
            new string[] { "domain", "target_nameservers", "critical_records" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
        /// </summary>
        public Task<JsonNode?> RecipeDomainFinderAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/domain-finder",
            new string[] {  },
            new string[] { "keywords", "tlds", "style", "max_length", "language", "limit" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
        /// </summary>
        public Task<JsonNode?> RecipeDueDiligenceAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/due-diligence",
            new string[] {  },
            new string[] { "domain", "include_competitors" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
        /// </summary>
        public Task<JsonNode?> RecipeEmailDeliverabilityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/email-deliverability",
            new string[] {  },
            new string[] { "domain", "dkim_selectors", "check_blacklists" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
        /// </summary>
        public Task<JsonNode?> RecipeInfrastructureDiscoveryAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/infrastructure-discovery",
            new string[] {  },
            new string[] { "domain", "depth", "include_historical" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
        /// </summary>
        public Task<JsonNode?> RecipePhishingInvestigationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/phishing-investigation",
            new string[] {  },
            new string[] { "suspicious_domain", "legitimate_domain", "collect_evidence" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
        /// </summary>
        public Task<JsonNode?> RecipePortfolioAuditAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/portfolio-audit",
            new string[] {  },
            new string[] { "domains", "include_valuation", "include_health", "alert_expiring_days" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Audit domain portfolio via POST for larger domain lists.
        /// </summary>
        public Task<JsonNode?> RecipePortfolioAuditPostAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/recipes/portfolio-audit",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
        /// </summary>
        public Task<JsonNode?> RecipeThreatAssessmentAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/threat-assessment",
            new string[] {  },
            new string[] { "domain", "max_threats", "include_evidence" },
            false
        ), parameters, cancellationToken);
}

public sealed class SecurityService
{
    private readonly DomScanClient _client;

    internal SecurityService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Check multiple email domains against blacklists at once.
        /// </summary>
        public Task<JsonNode?> BulkEmailCheckAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/email/check/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
        /// </summary>
        public Task<JsonNode?> BulkGetCertificatesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/certificates/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
        /// </summary>
        public Task<JsonNode?> BulkGetEmailAuthAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/email-auth/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
        /// </summary>
        public Task<JsonNode?> BulkGetSubdomainsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/subdomains/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Check if an email domain is on disposable/temporary email blacklists.
        /// </summary>
        public Task<JsonNode?> CheckEmailBlacklistAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/check",
            new string[] {  },
            new string[] { "email", "checks" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
        /// </summary>
        public Task<JsonNode?> GetCertificatesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/certificates",
            new string[] {  },
            new string[] { "domain", "include_subdomains", "include_expired", "limit", "cursor" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
        /// </summary>
        public Task<JsonNode?> GetDomainReputationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/reputation",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
        /// </summary>
        public Task<JsonNode?> GetEmailAuthAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email-auth",
            new string[] {  },
            new string[] { "domain", "selectors" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and proxy-backed mail security checks.
        /// </summary>
        public Task<JsonNode?> GetEmailComplianceAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/compliance",
            new string[] {  },
            new string[] { "domain", "selectors", "providers" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
        /// </summary>
        public Task<JsonNode?> GetSslAuditAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ssl/audit",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Analyze the certificate chain including issuer, validity, and trust chain verification.
        /// </summary>
        public Task<JsonNode?> GetSslChainAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ssl/chain",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
        /// </summary>
        public Task<JsonNode?> GetSslDeepScanAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ssl/deep-scan",
            new string[] {  },
            new string[] { "domain", "refresh", "profile" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Check if an SSL certificate is expiring soon with configurable alert threshold.
        /// </summary>
        public Task<JsonNode?> GetSslExpiringAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ssl/expiring",
            new string[] {  },
            new string[] { "domain", "threshold_days" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
        /// </summary>
        public Task<JsonNode?> GetSslGradeAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ssl/grade",
            new string[] {  },
            new string[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Return best-effort public hostname evidence from a sequential passive pipeline. Discovery tries crt.sh first, then can fall back to HackerTarget, ThreatMiner, the Wayback Machine, and CertSpotter. Results include their evidence source. DomScan does not brute-force names or crawl the target site, so coverage is incomplete.
        /// </summary>
        public Task<JsonNode?> GetSubdomainsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/subdomains",
            new string[] {  },
            new string[] { "domain", "sources", "verify", "include_wildcards", "limit", "prefer_cache" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
        /// </summary>
        public Task<JsonNode?> GetTyposquattingAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/typos",
            new string[] {  },
            new string[] { "domain", "check_registered", "limit", "include_tld_swap" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Find exposed software versions and deterministic web security misconfigurations using verified technology evidence, exact OSV package matching, CISA Known Exploited Vulnerabilities, FIRST EPSS, and isolated Edge Relay rendering. Results separate affected versions from configuration findings and preserve unknown coverage.
        /// </summary>
        public Task<JsonNode?> GetVulnerabilitiesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/vulnerabilities",
            new string[] {  },
            new string[] { "url", "domain", "mode" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Validate, normalize, and enrich international phone numbers with country-specific coverage levels, offline numbering-plan, location, time-zone, original prefix-carrier, portability-support, dialing, short-number, service, and official allocation metadata. US NANPA and Canadian CNA/CNAC snapshots add NPA-NXX central office code status and original code-holder evidence. DomScan uses its own Edge Relay and free local datasets without paid or per-number third-party lookups. Results never claim current carrier, reachability, subscriber identity, or individual-number assignment.
        /// </summary>
        public Task<JsonNode?> ValidatePhoneNumberAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/phone/validate",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and uses one DomScan Edge Relay batch with zero paid or per-number third-party lookups.
        /// </summary>
        public Task<JsonNode?> ValidatePhoneNumbersBulkAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/phone/validate/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
        /// </summary>
        public Task<JsonNode?> VerifyEmailAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/verify",
            new string[] {  },
            new string[] { "email", "full" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Verify multiple email addresses at once. Max 100 emails per request.
        /// </summary>
        public Task<JsonNode?> VerifyEmailBulkAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/email/verify/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);
}

public sealed class SocialService
{
    private readonly DomScanClient _client;

    internal SocialService(DomScanClient client)
    {
        _client = client;
    }

        /// <summary>
        /// Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
        /// </summary>
        public Task<JsonNode?> BulkCheckSocialHandlesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/social/bulk",
            new string[] {  },
            new string[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
        /// </summary>
        public Task<JsonNode?> CheckSocialHandlesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/social",
            new string[] {  },
            new string[] { "handle", "platforms", "resources" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
        /// </summary>
        public Task<JsonNode?> GetSocialInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/social/info",
            new string[] {  },
            new string[] {  },
            false
        ), parameters, cancellationToken);
}
