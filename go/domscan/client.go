package domscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

type Params map[string]any

type Config struct {
	APIKey     string
	BaseURL    string
	Timeout    time.Duration
	Headers    map[string]string
	HTTPClient *http.Client
	UserAgent  string
}

type APIError struct {
	Status    int
	Code      string
	Message   string
	Details   any
	RequestID string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("DomScan request failed with status %d", e.Status)
}

type endpointDefinition struct {
	Method      string
	Path        string
	PathParams  []string
	QueryParams []string
	HasBody     bool
}

type Client struct {
	apiKey         string
	baseURL        string
	timeout        time.Duration
	userAgent      string
	httpClient     *http.Client
	defaultHeaders map[string]string
	Availability *AvailabilityService
	Dns *DnsService
	Domain *DomainService
	Intelligence *IntelligenceService
	Meta *MetaService
	Osint *OsintService
	Pricing *PricingService
	Recipes *RecipesService
	Security *SecurityService
	Social *SocialService
}

func NewClient(config *Config) *Client {
	baseURL := "https://domscan.net"
	timeout := 10 * time.Second
	headers := map[string]string{}
	apiKey := os.Getenv("DOMSCAN_API_KEY")
	userAgent := "domscan-go/0.1.0"
	var httpClient *http.Client

	if config != nil {
		if config.APIKey != "" {
			apiKey = config.APIKey
		}
		if config.BaseURL != "" {
			baseURL = strings.TrimRight(config.BaseURL, "/")
		}
		if config.Timeout > 0 {
			timeout = config.Timeout
		}
		if config.Headers != nil {
			headers = config.Headers
		}
		if config.UserAgent != "" {
			userAgent = config.UserAgent
		}
		httpClient = config.HTTPClient
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	client := &Client{
		apiKey:         apiKey,
		baseURL:        baseURL,
		timeout:        timeout,
		userAgent:      userAgent,
		httpClient:     httpClient,
		defaultHeaders: headers,
	}

	client.Availability = &AvailabilityService{client: client}
	client.Dns = &DnsService{client: client}
	client.Domain = &DomainService{client: client}
	client.Intelligence = &IntelligenceService{client: client}
	client.Meta = &MetaService{client: client}
	client.Osint = &OsintService{client: client}
	client.Pricing = &PricingService{client: client}
	client.Recipes = &RecipesService{client: client}
	client.Security = &SecurityService{client: client}
	client.Social = &SocialService{client: client}
	return client
}

func (c *Client) request(ctx context.Context, endpoint endpointDefinition, params Params) (any, error) {
	requestPath := endpoint.Path
	consumedKeys := map[string]bool{}

	for _, pathParam := range endpoint.PathParams {
		value, ok := params[pathParam]
		if !ok || value == nil {
			return nil, fmt.Errorf("missing required path parameter: %s", pathParam)
		}
		requestPath = strings.ReplaceAll(requestPath, ":"+pathParam, url.PathEscape(fmt.Sprint(value)))
		consumedKeys[pathParam] = true
	}

	remaining := map[string]any{}
	for key, value := range params {
		if consumedKeys[key] || value == nil {
			continue
		}
		remaining[key] = value
	}

	queryPayload := map[string]any{}
	if endpoint.HasBody {
		for _, queryKey := range endpoint.QueryParams {
			if value, ok := remaining[queryKey]; ok {
				queryPayload[queryKey] = value
			}
		}
	} else {
		for key, value := range remaining {
			queryPayload[key] = value
		}
	}

	requestURL, err := url.Parse(c.baseURL + requestPath)
	if err != nil {
		return nil, err
	}

	values := requestURL.Query()
	for key, value := range queryPayload {
		values.Set(key, serializeQueryValue(value))
	}
	requestURL.RawQuery = values.Encode()

	bodyPayload := map[string]any{}
	if endpoint.HasBody {
		queryKeys := map[string]bool{}
		for _, queryKey := range endpoint.QueryParams {
			queryKeys[queryKey] = true
		}
		for key, value := range remaining {
			if !queryKeys[key] {
				bodyPayload[key] = value
			}
		}
	}

	var bodyReader io.Reader
	if endpoint.HasBody {
		encoded, err := json.Marshal(bodyPayload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, requestURL.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-DomScan-SDK", c.userAgent)
	if endpoint.HasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("X-API-Key", c.apiKey)
	}
	for key, value := range c.defaultHeaders {
		req.Header.Set(key, value)
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	payloadBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	payload := decodePayload(payloadBytes, response.Header.Get("Content-Type"))
	if response.StatusCode >= 400 {
		apiError := &APIError{
			Status:    response.StatusCode,
			Details:   payload,
			RequestID: response.Header.Get("X-Request-Id"),
		}
		if parsed, ok := payload.(map[string]any); ok {
			if nested, ok := parsed["error"].(map[string]any); ok {
				if code, ok := nested["code"].(string); ok {
					apiError.Code = code
				}
				if message, ok := nested["message"].(string); ok {
					apiError.Message = message
				}
			}
		}
		return nil, apiError
	}

	return payload, nil
}

func decodePayload(payload []byte, contentType string) any {
	if strings.Contains(contentType, "application/json") {
		var decoded any
		if err := json.Unmarshal(payload, &decoded); err == nil {
			return decoded
		}
	}
	return string(payload)
}

func serializeQueryValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case fmt.Stringer:
		return typed.String()
	case time.Time:
		return typed.Format(time.RFC3339)
	}

	rv := reflect.ValueOf(value)
	if rv.IsValid() && (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) {
		parts := make([]string, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			parts = append(parts, serializeQueryValue(rv.Index(i).Interface()))
		}
		return strings.Join(parts, ",")
	}

	if payload, err := json.Marshal(value); err == nil && (rv.Kind() == reflect.Map || rv.Kind() == reflect.Struct) {
		return string(payload)
	}

	return fmt.Sprint(value)
}

type AvailabilityService struct {
	client *Client
}

// Check availability of multiple complete domain names at once.
func (s *AvailabilityService) BulkCheckDomains(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/status/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
func (s *AvailabilityService) CheckDomainAvailability(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/status",
		PathParams: []string{},
		QueryParams: []string{"name", "tlds", "prefer_cache"},
		HasBody: false,
	}, params)
}

// Get information about which TLDs are supported and their RDAP server status.
func (s *AvailabilityService) GetCoverage(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/coverage",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

type DnsService struct {
	client *Client
}

// Build a DMARC record with policy, reporting, and alignment options.
func (s *DnsService) BuildDmarc(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/tools/dmarc/build",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Build an SPF record from configuration options with validation and recommendations.
func (s *DnsService) BuildSpf(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/tools/spf/build",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Check a specific DKIM selector for a domain and validate the public key.
func (s *DnsService) CheckDkim(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tools/dkim/check",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Discover DKIM selectors for a domain by checking common selector names.
func (s *DnsService) DiscoverDkim(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tools/dkim/discover",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
func (s *DnsService) FlattenSpf(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/tools/spf/flatten",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Get all DNS record types for a domain in a single call.
func (s *DnsService) GetAllDnsRecords(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/all",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Compare DNS records between two dates to see what changed.
func (s *DnsService) GetDnsDiff(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/diff",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Track DNS record changes over time. Data accumulates from API lookups.
func (s *DnsService) GetDnsHistory(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/history",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Check DNS propagation across multiple global DNS servers.
func (s *DnsService) GetDnsPropagation(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/propagation",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
func (s *DnsService) GetDnsRecords(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
func (s *DnsService) GetDnsSecurity(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/security",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get list of global DNS servers used for propagation checks.
func (s *DnsService) GetDnsServers(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/servers",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Validate a DMARC record for syntax errors and configuration issues.
func (s *DnsService) ValidateDmarc(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/tools/dmarc/validate",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
func (s *DnsService) ValidateSpf(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/tools/spf/validate",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

type DomainService struct {
	client *Client
}

// Get value estimates for multiple domains at once.
func (s *DomainService) BulkDomainValue(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/value/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Compare two domains side-by-side across multiple metrics and attributes.
func (s *DomainService) CompareDomains(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/compare",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
func (s *DomainService) GetDomainHealth(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/health",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
func (s *DomainService) GetDomainOverview(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/overview",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
func (s *DomainService) GetDomainProfile(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/profile",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Calculate an overall domain quality score based on multiple factors.
func (s *DomainService) GetDomainScore(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/score",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
func (s *DomainService) GetDomainValue(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/value",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Fast health check with essential metrics only.
func (s *DomainService) GetQuickHealth(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/health/quick",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get detailed information about a specific TLD.
func (s *DomainService) GetTldDetail(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tlds/:tld",
		PathParams: []string{"tld"},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get list of all supported TLDs with metadata.
func (s *DomainService) GetTlds(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tlds",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
func (s *DomainService) SuggestDomains(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/suggest",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

type IntelligenceService struct {
	client *Client
}

// Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
func (s *IntelligenceService) CategorizeWebsite(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/categorize",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Categorize up to 10 websites in parallel with caching.
func (s *IntelligenceService) CategorizeWebsiteBulk(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/categorize/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Extract company information from a domain. Get name, industry, and contact details.
func (s *IntelligenceService) GetCompany(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/company",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Compare domains for similarity. Detect typosquatting with multiple algorithms.
func (s *IntelligenceService) GetDomainSimilarity(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/similarity",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
func (s *IntelligenceService) GetHosting(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/hosting",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
func (s *IntelligenceService) GetParkingDetection(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/parking",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
func (s *IntelligenceService) GetRedirects(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/redirects",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Detect website technologies: CDN, CMS, frameworks, analytics, and more.
func (s *IntelligenceService) GetTechStack(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tech",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

type MetaService struct {
	client *Client
}

// Get credit costs per endpoint and API pricing information.
func (s *MetaService) GetPricingInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/pricing",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

type OsintService struct {
	client *Client
}

// Get WHOIS data for multiple domains at once.
func (s *OsintService) BulkWhois(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/whois/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Find domains that use a specific nameserver.
func (s *OsintService) GetDnsReverseNs(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/reverse/ns",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Map domain relationships through shared infrastructure and registrant data.
func (s *OsintService) GetDomainGraph(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/graph",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
func (s *OsintService) GetDomainLifecycle(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/lifecycle",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Get IP addresses with geolocation, ASN, and hosting provider information.
func (s *OsintService) GetIpInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ip",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Lookup MAC address vendor information. Identify network device manufacturers.
func (s *OsintService) GetMacInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/mac",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Find all domains hosted on a specific IP address.
func (s *OsintService) GetReverseIp(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/reverse/ip",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Find all domains using a specific mail server for email infrastructure mapping.
func (s *OsintService) GetReverseMx(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/reverse/mx",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get structured WHOIS/RDAP registration data for a domain.
func (s *OsintService) GetWhois(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/whois",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
func (s *OsintService) GetWhoisHistory(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/whois/history",
		PathParams: []string{},
		QueryParams: []string{"domain", "limit"},
		HasBody: false,
	}, params)
}

type PricingService struct {
	client *Client
}

// Get pricing for multiple domains at once.
func (s *PricingService) BulkPricing(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/prices/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Compare domain prices across multiple registrars.
func (s *PricingService) ComparePrices(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices/compare",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get domain registration and renewal prices across registrars.
func (s *PricingService) GetPrices(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get list of supported registrars with pricing data.
func (s *PricingService) GetRegistrars(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices/registrars",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get pricing for a specific TLD across registrars.
func (s *PricingService) GetTldPricing(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices/tld/:tld",
		PathParams: []string{"tld"},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

type RecipesService struct {
	client *Client
}

// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
func (s *RecipesService) RecipeBrandLaunch(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/brand-launch",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
func (s *RecipesService) RecipeCompetitorIntel(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/competitor-intel",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
func (s *RecipesService) RecipeDefensiveRegistration(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/defensive-registration",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
func (s *RecipesService) RecipeDnsMigration(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/dns-migration",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
func (s *RecipesService) RecipeDomainFinder(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/domain-finder",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
func (s *RecipesService) RecipeDueDiligence(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/due-diligence",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
func (s *RecipesService) RecipeEmailDeliverability(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/email-deliverability",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
func (s *RecipesService) RecipeInfrastructureDiscovery(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/infrastructure-discovery",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
func (s *RecipesService) RecipePhishingInvestigation(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/phishing-investigation",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
func (s *RecipesService) RecipePortfolioAudit(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/portfolio-audit",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Audit domain portfolio via POST for larger domain lists.
func (s *RecipesService) RecipePortfolioAuditPost(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/recipes/portfolio-audit",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
func (s *RecipesService) RecipeThreatAssessment(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/threat-assessment",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

type SecurityService struct {
	client *Client
}

// Check multiple email domains against blacklists at once.
func (s *SecurityService) BulkEmailCheck(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/email/check/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Check if an email domain is on disposable/temporary email blacklists.
func (s *SecurityService) CheckEmailBlacklist(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email/check",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Download the full email blacklist database in various formats.
func (s *SecurityService) DownloadEmailBlacklist(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email/blacklist/download",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
func (s *SecurityService) GetCertificates(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/certificates",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Check domain reputation across security feeds, blacklists, and threat intelligence.
func (s *SecurityService) GetDomainReputation(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/reputation",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Check DMARC, SPF, and DKIM configurations for email security auditing.
func (s *SecurityService) GetEmailAuth(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email-auth",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get information about the email blacklist database.
func (s *SecurityService) GetEmailBlacklistInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email/blacklist",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Analyze the certificate chain including issuer, validity, and trust chain verification.
func (s *SecurityService) GetSslChain(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/chain",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Check if an SSL certificate is expiring soon with configurable alert threshold.
func (s *SecurityService) GetSslExpiring(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/expiring",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
func (s *SecurityService) GetSslGrade(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/grade",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Discover subdomains using Certificate Transparency and DNS enumeration.
func (s *SecurityService) GetSubdomains(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/subdomains",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
func (s *SecurityService) GetTyposquatting(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/typos",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
func (s *SecurityService) VerifyEmail(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email/verify",
		PathParams: []string{},
		QueryParams: []string{"email", "full"},
		HasBody: false,
	}, params)
}

// Verify multiple email addresses at once. Max 100 emails per request.
func (s *SecurityService) VerifyEmailBulk(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/email/verify/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

type SocialService struct {
	client *Client
}

// Check username availability across social platforms like GitHub, Reddit, and more.
func (s *SocialService) CheckSocialHandles(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/social",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}
