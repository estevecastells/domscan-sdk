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
        string userAgent = "domscan-csharp/0.1.0"
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
            new[] {  },
            new[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
        /// </summary>
        public Task<JsonNode?> CheckDomainAvailabilityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/status",
            new[] {  },
            new[] { "name", "tlds", "prefer_cache" },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Get all DNS record types for a domain in a single call.
        /// </summary>
        public Task<JsonNode?> GetAllDnsRecordsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/all",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare DNS records between two dates to see what changed.
        /// </summary>
        public Task<JsonNode?> GetDnsDiffAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/diff",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Track DNS record changes over time. Data accumulates from API lookups.
        /// </summary>
        public Task<JsonNode?> GetDnsHistoryAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/history",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Check DNS propagation across multiple global DNS servers.
        /// </summary>
        public Task<JsonNode?> GetDnsPropagationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/propagation",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
        /// </summary>
        public Task<JsonNode?> GetDnsRecordsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
        /// </summary>
        public Task<JsonNode?> GetDnsSecurityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/security",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get list of global DNS servers used for propagation checks.
        /// </summary>
        public Task<JsonNode?> GetDnsServersAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/servers",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
        /// </summary>
        public Task<JsonNode?> GetDomainHealthAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/health",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
        /// </summary>
        public Task<JsonNode?> GetDomainOverviewAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/overview",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] { "tld" },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
        /// Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
        /// </summary>
        public Task<JsonNode?> CategorizeWebsiteAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/categorize",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            true
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] { "domain" },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Detect website technologies: CDN, CMS, frameworks, analytics, and more.
        /// </summary>
        public Task<JsonNode?> GetTechStackAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/tech",
            new[] {  },
            new[] {  },
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
        /// Get credit costs per endpoint and API pricing information.
        /// </summary>
        public Task<JsonNode?> GetPricingInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/pricing",
            new[] {  },
            new[] {  },
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
        /// Get WHOIS data for multiple domains at once.
        /// </summary>
        public Task<JsonNode?> BulkWhoisAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/whois/bulk",
            new[] {  },
            new[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Find domains that use a specific nameserver.
        /// </summary>
        public Task<JsonNode?> GetDnsReverseNsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/dns/reverse/ns",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Map domain relationships through shared infrastructure and registrant data.
        /// </summary>
        public Task<JsonNode?> GetDomainGraphAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/graph",
            new[] {  },
            new[] {  },
            false
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
            new[] {  },
            new[] { "domain" },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get IP addresses with geolocation, ASN, and hosting provider information.
        /// </summary>
        public Task<JsonNode?> GetIpInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ip",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Find all domains hosted on a specific IP address.
        /// </summary>
        public Task<JsonNode?> GetReverseIpAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/reverse/ip",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Find all domains using a specific mail server for email infrastructure mapping.
        /// </summary>
        public Task<JsonNode?> GetReverseMxAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/reverse/mx",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
        /// </summary>
        public Task<JsonNode?> GetWhoisHistoryAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/whois/history",
            new[] {  },
            new[] { "domain", "limit" },
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
        /// Get pricing for multiple domains at once.
        /// </summary>
        public Task<JsonNode?> BulkPricingAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "POST",
            "/v1/prices/bulk",
            new[] {  },
            new[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Compare domain prices across multiple registrars.
        /// </summary>
        public Task<JsonNode?> ComparePricesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices/compare",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get domain registration and renewal prices across registrars.
        /// </summary>
        public Task<JsonNode?> GetPricesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get list of supported registrars with pricing data.
        /// </summary>
        public Task<JsonNode?> GetRegistrarsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices/registrars",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get pricing for a specific TLD across registrars.
        /// </summary>
        public Task<JsonNode?> GetTldPricingAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/prices/tld/:tld",
            new[] { "tld" },
            new[] {  },
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
        /// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
        /// </summary>
        public Task<JsonNode?> RecipeBrandLaunchAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/brand-launch",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
        /// </summary>
        public Task<JsonNode?> RecipeCompetitorIntelAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/competitor-intel",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
        /// </summary>
        public Task<JsonNode?> RecipeDefensiveRegistrationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/defensive-registration",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
        /// </summary>
        public Task<JsonNode?> RecipeDnsMigrationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/dns-migration",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
        /// </summary>
        public Task<JsonNode?> RecipeDomainFinderAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/domain-finder",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
        /// </summary>
        public Task<JsonNode?> RecipeDueDiligenceAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/due-diligence",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
        /// </summary>
        public Task<JsonNode?> RecipeEmailDeliverabilityAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/email-deliverability",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
        /// </summary>
        public Task<JsonNode?> RecipeInfrastructureDiscoveryAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/infrastructure-discovery",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
        /// </summary>
        public Task<JsonNode?> RecipePhishingInvestigationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/phishing-investigation",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
        /// </summary>
        public Task<JsonNode?> RecipePortfolioAuditAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/portfolio-audit",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            true
        ), parameters, cancellationToken);

        /// <summary>
        /// Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
        /// </summary>
        public Task<JsonNode?> RecipeThreatAssessmentAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/recipes/threat-assessment",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Download the full email blacklist database in various formats.
        /// </summary>
        public Task<JsonNode?> DownloadEmailBlacklistAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/blacklist/download",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Check domain reputation across security feeds, blacklists, and threat intelligence.
        /// </summary>
        public Task<JsonNode?> GetDomainReputationAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/reputation",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Check DMARC, SPF, and DKIM configurations for email security auditing.
        /// </summary>
        public Task<JsonNode?> GetEmailAuthAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email-auth",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Get information about the email blacklist database.
        /// </summary>
        public Task<JsonNode?> GetEmailBlacklistInfoAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/blacklist",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
        /// </summary>
        public Task<JsonNode?> GetSslGradeAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/ssl/grade",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Discover subdomains using Certificate Transparency and DNS enumeration.
        /// </summary>
        public Task<JsonNode?> GetSubdomainsAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/subdomains",
            new[] {  },
            new[] {  },
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
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);

        /// <summary>
        /// Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
        /// </summary>
        public Task<JsonNode?> VerifyEmailAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/email/verify",
            new[] {  },
            new[] { "email", "full" },
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
            new[] {  },
            new[] {  },
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
        /// Check username availability across social platforms like GitHub, Reddit, and more.
        /// </summary>
        public Task<JsonNode?> CheckSocialHandlesAsync(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            "GET",
            "/v1/social",
            new[] {  },
            new[] {  },
            false
        ), parameters, cancellationToken);
}
