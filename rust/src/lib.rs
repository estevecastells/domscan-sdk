use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::{Map, Value};
use std::env;
use std::sync::Arc;
use std::time::Duration;

pub type Params = Map<String, Value>;

#[derive(Debug)]
pub struct DomScanError {
    pub status: u16,
    pub code: Option<String>,
    pub message: String,
    pub details: Option<Value>,
    pub request_id: Option<String>,
}

impl std::fmt::Display for DomScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DomScanError {}

#[derive(Clone)]
struct EndpointDefinition {
    method: String,
    path: String,
    path_params: Vec<String>,
    query_params: Vec<String>,
    has_body: bool,
}

#[derive(Clone)]
struct InnerClient {
    api_key: Option<String>,
    base_url: String,
    user_agent: String,
    default_headers: HeaderMap,
    http_client: reqwest::Client,
}

#[derive(Clone)]
pub struct DomScanClient {
    inner: Arc<InnerClient>,
}

impl DomScanClient {
    pub fn new(api_key: Option<String>) -> Self {
        let resolved_api_key = api_key.or_else(|| env::var("DOMSCAN_API_KEY").ok());
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");
        let inner = InnerClient {
            api_key: resolved_api_key,
            base_url: "https://domscan.net".to_string(),
            user_agent: "domscan-rust/0.1.0".to_string(),
            default_headers: HeaderMap::new(),
            http_client,
        };
        Self { inner: Arc::new(inner) }
    }

    pub fn availability(&self) -> AvailabilityService {
        AvailabilityService { client: Arc::clone(&self.inner) }
    }

    pub fn dns(&self) -> DnsService {
        DnsService { client: Arc::clone(&self.inner) }
    }

    pub fn domain(&self) -> DomainService {
        DomainService { client: Arc::clone(&self.inner) }
    }

    pub fn intelligence(&self) -> IntelligenceService {
        IntelligenceService { client: Arc::clone(&self.inner) }
    }

    pub fn meta(&self) -> MetaService {
        MetaService { client: Arc::clone(&self.inner) }
    }

    pub fn osint(&self) -> OsintService {
        OsintService { client: Arc::clone(&self.inner) }
    }

    pub fn pricing(&self) -> PricingService {
        PricingService { client: Arc::clone(&self.inner) }
    }

    pub fn recipes(&self) -> RecipesService {
        RecipesService { client: Arc::clone(&self.inner) }
    }

    pub fn security(&self) -> SecurityService {
        SecurityService { client: Arc::clone(&self.inner) }
    }

    pub fn social(&self) -> SocialService {
        SocialService { client: Arc::clone(&self.inner) }
    }
}

impl InnerClient {
    async fn request(&self, endpoint: EndpointDefinition, params: Params) -> Result<Value, DomScanError> {
        let mut request_path = endpoint.path.clone();
        let mut remaining = params.clone();

        for path_param in endpoint.path_params.iter() {
            let value = remaining
                .remove(path_param)
                .ok_or_else(|| DomScanError {
                    status: 0,
                    code: None,
                    message: format!("Missing required path parameter: {}", path_param),
                    details: None,
                    request_id: None,
                })?;
            let serialized = serialize_query_value(&value);
            let encoded = urlencoding::encode(&serialized);
            request_path = request_path.replace(&format!(":{}", path_param), encoded.as_ref());
        }

        let query_payload = if endpoint.has_body {
            remaining
                .iter()
                .filter(|(key, value)| endpoint.query_params.contains(key) && !value.is_null())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Map<String, Value>>()
        } else {
            remaining
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Map<String, Value>>()
        };

        let mut request = self
            .http_client
            .request(
                endpoint.method.parse().unwrap(),
                format!("{}{}", self.base_url, request_path),
            )
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, self.user_agent.clone())
            .header("X-DomScan-SDK", self.user_agent.clone());

        if let Some(api_key) = &self.api_key {
            request = request.header(AUTHORIZATION, format!("Bearer {}", api_key));
            request = request.header("X-API-Key", api_key);
        }

        for (key, value) in query_payload.iter() {
            request = request.query(&[(key, serialize_query_value(value))]);
        }

        if endpoint.has_body {
            let body_payload = remaining
                .iter()
                .filter(|(key, value)| !endpoint.query_params.contains(key) && !value.is_null())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Map<String, Value>>();
            request = request.header(CONTENT_TYPE, "application/json").json(&body_payload);
        }

        let response = request.send().await.map_err(|error| DomScanError {
            status: 0,
            code: None,
            message: error.to_string(),
            details: None,
            request_id: None,
        })?;

        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let text = response.text().await.map_err(|error| DomScanError {
            status,
            code: None,
            message: error.to_string(),
            details: None,
            request_id: request_id.clone(),
        })?;

        let payload = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| Value::String(text.clone()));
        if status < 400 {
            return Ok(payload);
        }

        let nested = payload.get("error");
        Err(DomScanError {
            status,
            code: nested.and_then(|value| value.get("code")).and_then(Value::as_str).map(|value| value.to_string()),
            message: nested
                .and_then(|value| value.get("message"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| "DomScan request failed")
                .to_string(),
            details: Some(payload),
            request_id,
        })
    }
}

fn serialize_query_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => {
            if *value { "true".to_string() } else { "false".to_string() }
        }
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values.iter().map(serialize_query_value).collect::<Vec<_>>().join(","),
        Value::Object(_) => value.to_string(),
    }
}

#[derive(Clone)]
pub struct AvailabilityService {
    client: Arc<InnerClient>,
}

impl AvailabilityService {
    /// Check availability of multiple complete domain names at once.
    pub async fn bulk_check_domains(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/status/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
    pub async fn check_domain_availability(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/status".to_string(),
            path_params: vec![],
            query_params: vec!["name".to_string(), "tlds".to_string(), "prefer_cache".to_string()],
            has_body: false,
        }, params).await
    }

    /// Get information about which TLDs are supported and their RDAP server status.
    pub async fn get_coverage(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/coverage".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct DnsService {
    client: Arc<InnerClient>,
}

impl DnsService {
    /// Build a DMARC record with policy, reporting, and alignment options.
    pub async fn build_dmarc(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/tools/dmarc/build".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Build an SPF record from configuration options with validation and recommendations.
    pub async fn build_spf(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/tools/spf/build".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Check a specific DKIM selector for a domain and validate the public key.
    pub async fn check_dkim(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tools/dkim/check".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Discover DKIM selectors for a domain by checking common selector names.
    pub async fn discover_dkim(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tools/dkim/discover".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
    pub async fn flatten_spf(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/tools/spf/flatten".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Get all DNS record types for a domain in a single call.
    pub async fn get_all_dns_records(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/all".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Compare DNS records between two dates to see what changed.
    pub async fn get_dns_diff(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/diff".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Track DNS record changes over time. Data accumulates from API lookups.
    pub async fn get_dns_history(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/history".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Check DNS propagation across multiple global DNS servers.
    pub async fn get_dns_propagation(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/propagation".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
    pub async fn get_dns_records(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
    pub async fn get_dns_security(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/security".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get list of global DNS servers used for propagation checks.
    pub async fn get_dns_servers(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/servers".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Validate a DMARC record for syntax errors and configuration issues.
    pub async fn validate_dmarc(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/tools/dmarc/validate".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
    pub async fn validate_spf(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/tools/spf/validate".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }
}

#[derive(Clone)]
pub struct DomainService {
    client: Arc<InnerClient>,
}

impl DomainService {
    /// Get value estimates for multiple domains at once.
    pub async fn bulk_domain_value(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/value/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Compare two domains side-by-side across multiple metrics and attributes.
    pub async fn compare_domains(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/compare".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
    pub async fn get_domain_health(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/health".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
    pub async fn get_domain_overview(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/overview".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    pub async fn get_domain_profile(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/profile".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Calculate an overall domain quality score based on multiple factors.
    pub async fn get_domain_score(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/score".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
    pub async fn get_domain_value(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/value".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Fast health check with essential metrics only.
    pub async fn get_quick_health(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/health/quick".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get detailed information about a specific TLD.
    pub async fn get_tld_detail(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tlds/:tld".to_string(),
            path_params: vec!["tld".to_string()],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get list of all supported TLDs with metadata.
    pub async fn get_tlds(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tlds".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
    pub async fn suggest_domains(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/suggest".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct IntelligenceService {
    client: Arc<InnerClient>,
}

impl IntelligenceService {
    /// Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
    pub async fn categorize_website(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/categorize".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Categorize up to 10 websites in parallel with caching.
    pub async fn categorize_website_bulk(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/categorize/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Extract company information from a domain. Get name, industry, and contact details.
    pub async fn get_company(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/company".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Compare domains for similarity. Detect typosquatting with multiple algorithms.
    pub async fn get_domain_similarity(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/similarity".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
    pub async fn get_hosting(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/hosting".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
    pub async fn get_parking_detection(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/parking".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
    pub async fn get_redirects(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/redirects".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Detect website technologies: CDN, CMS, frameworks, analytics, and more.
    pub async fn get_tech_stack(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tech".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct MetaService {
    client: Arc<InnerClient>,
}

impl MetaService {
    /// Get credit costs per endpoint and API pricing information.
    pub async fn get_pricing_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/pricing".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct OsintService {
    client: Arc<InnerClient>,
}

impl OsintService {
    /// Get WHOIS data for multiple domains at once.
    pub async fn bulk_whois(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/whois/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Find domains that use a specific nameserver.
    pub async fn get_dns_reverse_ns(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/reverse/ns".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Map domain relationships through shared infrastructure and registrant data.
    pub async fn get_domain_graph(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/graph".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
    pub async fn get_domain_lifecycle(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/lifecycle".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Get IP addresses with geolocation, ASN, and hosting provider information.
    pub async fn get_ip_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ip".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Lookup MAC address vendor information. Identify network device manufacturers.
    pub async fn get_mac_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/mac".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Find all domains hosted on a specific IP address.
    pub async fn get_reverse_ip(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/reverse/ip".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Find all domains using a specific mail server for email infrastructure mapping.
    pub async fn get_reverse_mx(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/reverse/mx".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get structured WHOIS/RDAP registration data for a domain.
    pub async fn get_whois(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/whois".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
    pub async fn get_whois_history(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/whois/history".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "limit".to_string()],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct PricingService {
    client: Arc<InnerClient>,
}

impl PricingService {
    /// Get pricing for multiple domains at once.
    pub async fn bulk_pricing(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/prices/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Compare domain prices across multiple registrars.
    pub async fn compare_prices(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices/compare".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get domain registration and renewal prices across registrars.
    pub async fn get_prices(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get list of supported registrars with pricing data.
    pub async fn get_registrars(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices/registrars".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get pricing for a specific TLD across registrars.
    pub async fn get_tld_pricing(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices/tld/:tld".to_string(),
            path_params: vec!["tld".to_string()],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct RecipesService {
    client: Arc<InnerClient>,
}

impl RecipesService {
    /// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
    pub async fn recipe_brand_launch(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/brand-launch".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
    pub async fn recipe_competitor_intel(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/competitor-intel".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
    pub async fn recipe_defensive_registration(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/defensive-registration".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
    pub async fn recipe_dns_migration(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/dns-migration".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
    pub async fn recipe_domain_finder(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/domain-finder".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
    pub async fn recipe_due_diligence(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/due-diligence".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
    pub async fn recipe_email_deliverability(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/email-deliverability".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
    pub async fn recipe_infrastructure_discovery(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/infrastructure-discovery".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
    pub async fn recipe_phishing_investigation(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/phishing-investigation".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
    pub async fn recipe_portfolio_audit(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/portfolio-audit".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Audit domain portfolio via POST for larger domain lists.
    pub async fn recipe_portfolio_audit_post(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/recipes/portfolio-audit".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
    pub async fn recipe_threat_assessment(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/threat-assessment".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct SecurityService {
    client: Arc<InnerClient>,
}

impl SecurityService {
    /// Check multiple email domains against blacklists at once.
    pub async fn bulk_email_check(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/email/check/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Check if an email domain is on disposable/temporary email blacklists.
    pub async fn check_email_blacklist(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email/check".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Download the full email blacklist database in various formats.
    pub async fn download_email_blacklist(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email/blacklist/download".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
    pub async fn get_certificates(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/certificates".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Check domain reputation across security feeds, blacklists, and threat intelligence.
    pub async fn get_domain_reputation(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/reputation".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Check DMARC, SPF, and DKIM configurations for email security auditing.
    pub async fn get_email_auth(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email-auth".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get information about the email blacklist database.
    pub async fn get_email_blacklist_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email/blacklist".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Analyze the certificate chain including issuer, validity, and trust chain verification.
    pub async fn get_ssl_chain(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/chain".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Check if an SSL certificate is expiring soon with configurable alert threshold.
    pub async fn get_ssl_expiring(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/expiring".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
    pub async fn get_ssl_grade(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/grade".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Discover subdomains using Certificate Transparency and DNS enumeration.
    pub async fn get_subdomains(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/subdomains".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
    pub async fn get_typosquatting(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/typos".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
    pub async fn verify_email(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email/verify".to_string(),
            path_params: vec![],
            query_params: vec!["email".to_string(), "full".to_string()],
            has_body: false,
        }, params).await
    }

    /// Verify multiple email addresses at once. Max 100 emails per request.
    pub async fn verify_email_bulk(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/email/verify/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }
}

#[derive(Clone)]
pub struct SocialService {
    client: Arc<InnerClient>,
}

impl SocialService {
    /// Check username availability across social platforms like GitHub, Reddit, and more.
    pub async fn check_social_handles(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/social".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}
