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
	userAgent := "domscan-go/0.2.0"
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

// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
func (s *AvailabilityService) CheckDomainAvailability(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/status",
		PathParams: []string{},
		QueryParams: []string{"name", "tlds", "domain", "prefer_cache"},
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

// Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
func (s *DnsService) BulkDnsPropagation(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/dns/propagation/bulk",
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
		QueryParams: []string{"domain", "selector"},
		HasBody: false,
	}, params)
}

// Discover DKIM selectors for a domain by checking common selector names.
func (s *DnsService) DiscoverDkim(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tools/dkim/discover",
		PathParams: []string{},
		QueryParams: []string{"domain"},
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

// Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
func (s *DnsService) GetAllDnsRecords(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/all",
		PathParams: []string{},
		QueryParams: []string{"domain", "wildcard_probe"},
		HasBody: false,
	}, params)
}

// Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
func (s *DnsService) GetDnsHistory(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/history",
		PathParams: []string{},
		QueryParams: []string{"domain", "type", "from", "to", "limit"},
		HasBody: false,
	}, params)
}

// Compare DNS answers from DomScan's configured Cloudflare and Google public recursive DoH providers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
func (s *DnsService) GetDnsPropagation(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/propagation",
		PathParams: []string{},
		QueryParams: []string{"domain", "type", "expected"},
		HasBody: false,
	}, params)
}

// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
func (s *DnsService) GetDnsRecords(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns",
		PathParams: []string{},
		QueryParams: []string{"domain", "type"},
		HasBody: false,
	}, params)
}

// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
func (s *DnsService) GetDnsSecurity(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/dns/security",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
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

// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
func (s *DomainService) BulkGetDomainProfile(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/profile/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Compare up to 50 candidate brand names and return ranked scores.
func (s *DomainService) CompareBrandNames(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/score/compare",
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
		QueryParams: []string{"domains"},
		HasBody: false,
	}, params)
}

// Comprehensive health checks with DNS, SSL, email, proxy-enriched TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
func (s *DomainService) GetDomainHealth(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/health",
		PathParams: []string{},
		QueryParams: []string{"domain", "details"},
		HasBody: false,
	}, params)
}

// Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
func (s *DomainService) GetDomainOverview(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/overview",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
func (s *DomainService) GetDomainPopularity(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/popularity",
		PathParams: []string{},
		QueryParams: []string{"domain", "include_history", "history_limit"},
		HasBody: false,
	}, params)
}

// Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
func (s *DomainService) GetDomainPopularityHistory(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/popularity/history",
		PathParams: []string{},
		QueryParams: []string{"domain", "limit"},
		HasBody: false,
	}, params)
}

// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
func (s *DomainService) GetDomainProfile(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/profile",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Calculate an overall domain quality score based on multiple factors.
func (s *DomainService) GetDomainScore(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/score",
		PathParams: []string{},
		QueryParams: []string{"name", "domain"},
		HasBody: false,
	}, params)
}

// Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
func (s *DomainService) GetDomainValue(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/value",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Fast health check with essential metrics only.
func (s *DomainService) GetQuickHealth(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/health/quick",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Returns scoring dimensions, grade scale, and related scoring endpoints.
func (s *DomainService) GetScoreInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/score/info",
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
		QueryParams: []string{"type"},
		HasBody: false,
	}, params)
}

// AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
func (s *DomainService) SuggestDomains(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/suggest",
		PathParams: []string{},
		QueryParams: []string{"keywords", "tlds", "style", "industry", "language", "limit", "check"},
		HasBody: false,
	}, params)
}

type IntelligenceService struct {
	client *Client
}

// Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
func (s *IntelligenceService) BulkGetHosting(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/hosting/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
func (s *IntelligenceService) BulkGetUrlIntelligence(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/url-intelligence/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
func (s *IntelligenceService) BulkGetWebsiteIdentityAssets(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/identity-assets/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
func (s *IntelligenceService) BulkResolveInternetIdentity(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/identity-resolution/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Cancel unstarted technology scan work and settle item-level refunds. An already running browser scan may finish, but its result is discarded.
func (s *IntelligenceService) CancelTechScanJob(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "DELETE",
		Path: "/v1/tech/jobs/:job_id",
		PathParams: []string{"job_id"},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
func (s *IntelligenceService) CategorizeWebsite(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/categorize",
		PathParams: []string{},
		QueryParams: []string{"url", "domain", "skip_cache", "min_confidence"},
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

// Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
func (s *IntelligenceService) CreateTechScanJob(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/tech/jobs",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
func (s *IntelligenceService) GetCategorizationTaxonomy(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/categorize/taxonomy",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Extract company information from a domain. Get name, industry, and contact details.
func (s *IntelligenceService) GetCompany(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/company",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Compare domains for similarity. Detect typosquatting with multiple algorithms.
func (s *IntelligenceService) GetDomainSimilarity(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/similarity",
		PathParams: []string{},
		QueryParams: []string{"domain1", "domain2"},
		HasBody: false,
	}, params)
}

// Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
func (s *IntelligenceService) GetHosting(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/hosting",
		PathParams: []string{},
		QueryParams: []string{"domain"},
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
		QueryParams: []string{"url", "domain"},
		HasBody: false,
	}, params)
}

// Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
func (s *IntelligenceService) GetTechScanJob(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tech/jobs/:job_id",
		PathParams: []string{"job_id"},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
func (s *IntelligenceService) GetTechScanJobResults(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tech/jobs/:job_id/results",
		PathParams: []string{"job_id"},
		QueryParams: []string{"cursor", "limit"},
		HasBody: false,
	}, params)
}

// Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
func (s *IntelligenceService) GetTechStack(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tech",
		PathParams: []string{},
		QueryParams: []string{"url", "domain", "mode", "max_pages", "skip_cache"},
		HasBody: false,
	}, params)
}

// Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
func (s *IntelligenceService) GetUrlIntelligence(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/url-intelligence",
		PathParams: []string{},
		QueryParams: []string{"url"},
		HasBody: false,
	}, params)
}

// Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
func (s *IntelligenceService) GetWebsiteIdentityAssets(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/identity-assets",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// List recent short-lived technology scan jobs for the authenticated account.
func (s *IntelligenceService) ListTechScanJobs(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/tech/jobs",
		PathParams: []string{},
		QueryParams: []string{"limit", "cursor"},
		HasBody: false,
	}, params)
}

// Run up to 10 ordered fast technology scans in one request. Each valid target is billed independently, and failed upstream scans are refunded independently.
func (s *IntelligenceService) PostTechStackBulk(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/tech/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
func (s *IntelligenceService) ResolveInternetIdentity(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/identity-resolution",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

type MetaService struct {
	client *Client
}

// Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
func (s *MetaService) CancelApiBatch(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "DELETE",
		Path: "/v1/batches/:job_id",
		PathParams: []string{"job_id"},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and failed items are refunded independently.
func (s *MetaService) CreateApiBatch(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/batches",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Download the full disposable email domain dataset in various formats.
func (s *MetaService) DownloadEmailBlacklist(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email/blacklist/download",
		PathParams: []string{},
		QueryParams: []string{"format"},
		HasBody: false,
	}, params)
}

// Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
func (s *MetaService) GetApiBatch(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/batches/:job_id",
		PathParams: []string{"job_id"},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
func (s *MetaService) GetApiBatchResults(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/batches/:job_id/results",
		PathParams: []string{"job_id"},
		QueryParams: []string{"after", "limit", "format"},
		HasBody: false,
	}, params)
}

// Browse the disposable email domain dataset as a paginated data feed.
func (s *MetaService) GetEmailBlacklistInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email/blacklist",
		PathParams: []string{},
		QueryParams: []string{"limit", "offset", "format"},
		HasBody: false,
	}, params)
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

// List unexpired asynchronous API batches for the active customer account.
func (s *MetaService) ListApiBatches(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/batches",
		PathParams: []string{},
		QueryParams: []string{"limit"},
		HasBody: false,
	}, params)
}

type OsintService struct {
	client *Client
}

// Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
func (s *OsintService) BulkGetRdap(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/rdap/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
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

// Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
func (s *OsintService) GetIpInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ip",
		PathParams: []string{},
		QueryParams: []string{"ip", "domain"},
		HasBody: false,
	}, params)
}

// Lookup MAC address vendor information. Identify network device manufacturers.
func (s *OsintService) GetMacInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/mac",
		PathParams: []string{},
		QueryParams: []string{"mac"},
		HasBody: false,
	}, params)
}

// Returns parameter help and an example response for the MAC address lookup endpoint.
func (s *OsintService) GetMacLookupInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/mac/info",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Get raw RDAP response for a domain, IP address, or autonomous system number.
func (s *OsintService) GetRdap(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/rdap",
		PathParams: []string{},
		QueryParams: []string{"query", "type", "domain"},
		HasBody: false,
	}, params)
}

// Get structured WHOIS/RDAP registration data for a domain.
func (s *OsintService) GetWhois(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/whois",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
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

// Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
func (s *PricingService) BulkPricing(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/prices/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
func (s *PricingService) ComparePrices(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices/compare",
		PathParams: []string{},
		QueryParams: []string{"domain", "registrars", "skip_cache"},
		HasBody: false,
	}, params)
}

// Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
func (s *PricingService) GetPrices(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices",
		PathParams: []string{},
		QueryParams: []string{"tlds", "registrars", "skip_cache"},
		HasBody: false,
	}, params)
}

// List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
func (s *PricingService) GetRegistrars(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices/registrars",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}

// Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
func (s *PricingService) GetTldPricing(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/prices/tld/:tld",
		PathParams: []string{"tld"},
		QueryParams: []string{"registrars", "skip_cache"},
		HasBody: false,
	}, params)
}

type RecipesService struct {
	client *Client
}

// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
func (s *RecipesService) RecipeBrandLaunch(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/brand-launch",
		PathParams: []string{},
		QueryParams: []string{"domain", "brand_name", "platforms"},
		HasBody: false,
	}, params)
}

// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
func (s *RecipesService) RecipeCompetitorIntel(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/competitor-intel",
		PathParams: []string{},
		QueryParams: []string{"domain", "discover_subdomains", "analyze_email"},
		HasBody: false,
	}, params)
}

// Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
func (s *RecipesService) RecipeDefensiveRegistration(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/defensive-registration",
		PathParams: []string{},
		QueryParams: []string{"brand", "owned_domains", "priority_tlds", "include_typos", "budget"},
		HasBody: false,
	}, params)
}

// Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
func (s *RecipesService) RecipeDnsMigration(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/dns-migration",
		PathParams: []string{},
		QueryParams: []string{"domain", "target_nameservers", "critical_records"},
		HasBody: false,
	}, params)
}

// AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
func (s *RecipesService) RecipeDomainFinder(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/domain-finder",
		PathParams: []string{},
		QueryParams: []string{"keywords", "tlds", "style", "max_length", "language", "limit"},
		HasBody: false,
	}, params)
}

// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
func (s *RecipesService) RecipeDueDiligence(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/due-diligence",
		PathParams: []string{},
		QueryParams: []string{"domain", "include_competitors"},
		HasBody: false,
	}, params)
}

// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
func (s *RecipesService) RecipeEmailDeliverability(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/email-deliverability",
		PathParams: []string{},
		QueryParams: []string{"domain", "dkim_selectors", "check_blacklists"},
		HasBody: false,
	}, params)
}

// Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
func (s *RecipesService) RecipeInfrastructureDiscovery(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/infrastructure-discovery",
		PathParams: []string{},
		QueryParams: []string{"domain", "depth", "include_historical"},
		HasBody: false,
	}, params)
}

// Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
func (s *RecipesService) RecipePhishingInvestigation(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/phishing-investigation",
		PathParams: []string{},
		QueryParams: []string{"suspicious_domain", "legitimate_domain", "collect_evidence"},
		HasBody: false,
	}, params)
}

// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
func (s *RecipesService) RecipePortfolioAudit(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/portfolio-audit",
		PathParams: []string{},
		QueryParams: []string{"domains", "include_valuation", "include_health", "alert_expiring_days"},
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

// Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
func (s *RecipesService) RecipeThreatAssessment(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/recipes/threat-assessment",
		PathParams: []string{},
		QueryParams: []string{"domain", "max_threats", "include_evidence"},
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

// Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
func (s *SecurityService) BulkGetCertificates(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/certificates/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
func (s *SecurityService) BulkGetEmailAuth(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/email-auth/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
func (s *SecurityService) BulkGetSubdomains(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/subdomains/bulk",
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
		QueryParams: []string{"email", "checks"},
		HasBody: false,
	}, params)
}

// Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
func (s *SecurityService) GetCertificates(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/certificates",
		PathParams: []string{},
		QueryParams: []string{"domain", "include_subdomains", "include_expired", "limit", "cursor"},
		HasBody: false,
	}, params)
}

// Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
func (s *SecurityService) GetDomainReputation(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/reputation",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
func (s *SecurityService) GetEmailAuth(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email-auth",
		PathParams: []string{},
		QueryParams: []string{"domain", "selectors"},
		HasBody: false,
	}, params)
}

// Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and proxy-backed mail security checks.
func (s *SecurityService) GetEmailCompliance(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/email/compliance",
		PathParams: []string{},
		QueryParams: []string{"domain", "selectors", "providers"},
		HasBody: false,
	}, params)
}

// Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
func (s *SecurityService) GetSslAudit(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/audit",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Analyze the certificate chain including issuer, validity, and trust chain verification.
func (s *SecurityService) GetSslChain(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/chain",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
func (s *SecurityService) GetSslDeepScan(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/deep-scan",
		PathParams: []string{},
		QueryParams: []string{"domain", "refresh", "profile"},
		HasBody: false,
	}, params)
}

// Check if an SSL certificate is expiring soon with configurable alert threshold.
func (s *SecurityService) GetSslExpiring(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/expiring",
		PathParams: []string{},
		QueryParams: []string{"domain", "threshold_days"},
		HasBody: false,
	}, params)
}

// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
func (s *SecurityService) GetSslGrade(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/ssl/grade",
		PathParams: []string{},
		QueryParams: []string{"domain"},
		HasBody: false,
	}, params)
}

// Return best-effort public hostname evidence from a sequential passive pipeline. Discovery tries crt.sh first, then can fall back to HackerTarget, ThreatMiner, the Wayback Machine, and CertSpotter. Results include their evidence source. DomScan does not brute-force names or crawl the target site, so coverage is incomplete.
func (s *SecurityService) GetSubdomains(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/subdomains",
		PathParams: []string{},
		QueryParams: []string{"domain", "sources", "verify", "include_wildcards", "limit", "prefer_cache"},
		HasBody: false,
	}, params)
}

// Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
func (s *SecurityService) GetTyposquatting(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/typos",
		PathParams: []string{},
		QueryParams: []string{"domain", "check_registered", "limit", "include_tld_swap"},
		HasBody: false,
	}, params)
}

// Find exposed software versions and deterministic web security misconfigurations using verified technology evidence, exact OSV package matching, CISA Known Exploited Vulnerabilities, FIRST EPSS, and isolated Edge Relay rendering. Results separate affected versions from configuration findings and preserve unknown coverage.
func (s *SecurityService) GetVulnerabilities(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/vulnerabilities",
		PathParams: []string{},
		QueryParams: []string{"url", "domain", "mode"},
		HasBody: false,
	}, params)
}

// Validate, normalize, and enrich international phone numbers with country-specific coverage levels, offline numbering-plan, location, time-zone, original prefix-carrier, portability-support, dialing, short-number, service, and official allocation metadata. US NANPA and Canadian CNA/CNAC snapshots add NPA-NXX central office code status and original code-holder evidence. DomScan uses its own Edge Relay and free local datasets without paid or per-number third-party lookups. Results never claim current carrier, reachability, subscriber identity, or individual-number assignment.
func (s *SecurityService) ValidatePhoneNumber(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/phone/validate",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and uses one DomScan Edge Relay batch with zero paid or per-number third-party lookups.
func (s *SecurityService) ValidatePhoneNumbersBulk(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/phone/validate/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
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

// Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
func (s *SocialService) BulkCheckSocialHandles(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "POST",
		Path: "/v1/social/bulk",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: true,
	}, params)
}

// Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
func (s *SocialService) CheckSocialHandles(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/social",
		PathParams: []string{},
		QueryParams: []string{"handle", "platforms", "resources"},
		HasBody: false,
	}, params)
}

// Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
func (s *SocialService) GetSocialInfo(ctx context.Context, params Params) (any, error) {
	return s.client.request(ctx, endpointDefinition{
		Method: "GET",
		Path: "/v1/social/info",
		PathParams: []string{},
		QueryParams: []string{},
		HasBody: false,
	}, params)
}
