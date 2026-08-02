use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
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
            user_agent: "domscan-rust/0.2.0".to_string(),
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

    /// Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
    pub async fn check_domain_availability(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/status".to_string(),
            path_params: vec![],
            query_params: vec!["name".to_string(), "tlds".to_string(), "domain".to_string(), "prefer_cache".to_string()],
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

    /// Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
    pub async fn bulk_dns_propagation(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/dns/propagation/bulk".to_string(),
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
            query_params: vec!["domain".to_string(), "selector".to_string()],
            has_body: false,
        }, params).await
    }

    /// Discover DKIM selectors for a domain by checking common selector names.
    pub async fn discover_dkim(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tools/dkim/discover".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
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

    /// Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
    pub async fn get_all_dns_records(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/all".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "wildcard_probe".to_string()],
            has_body: false,
        }, params).await
    }

    /// Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
    pub async fn get_dns_history(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/history".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "type".to_string(), "from".to_string(), "to".to_string(), "limit".to_string()],
            has_body: false,
        }, params).await
    }

    /// Compare DNS answers from DomScan's configured Cloudflare and Google public recursive DoH providers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
    pub async fn get_dns_propagation(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/propagation".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "type".to_string(), "expected".to_string()],
            has_body: false,
        }, params).await
    }

    /// Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
    pub async fn get_dns_records(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "type".to_string()],
            has_body: false,
        }, params).await
    }

    /// Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
    pub async fn get_dns_security(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/dns/security".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
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

    /// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    pub async fn bulk_get_domain_profile(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/profile/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Compare up to 50 candidate brand names and return ranked scores.
    pub async fn compare_brand_names(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/score/compare".to_string(),
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
            query_params: vec!["domains".to_string()],
            has_body: false,
        }, params).await
    }

    /// Comprehensive health checks with DNS, SSL, email, proxy-enriched TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
    pub async fn get_domain_health(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/health".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "details".to_string()],
            has_body: false,
        }, params).await
    }

    /// Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
    pub async fn get_domain_overview(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/overview".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
    pub async fn get_domain_popularity(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/popularity".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "include_history".to_string(), "history_limit".to_string()],
            has_body: false,
        }, params).await
    }

    /// Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
    pub async fn get_domain_popularity_history(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/popularity/history".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "limit".to_string()],
            has_body: false,
        }, params).await
    }

    /// Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    pub async fn get_domain_profile(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/profile".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Calculate an overall domain quality score based on multiple factors.
    pub async fn get_domain_score(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/score".to_string(),
            path_params: vec![],
            query_params: vec!["name".to_string(), "domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
    pub async fn get_domain_value(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/value".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Fast health check with essential metrics only.
    pub async fn get_quick_health(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/health/quick".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Returns scoring dimensions, grade scale, and related scoring endpoints.
    pub async fn get_score_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/score/info".to_string(),
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
            query_params: vec!["type".to_string()],
            has_body: false,
        }, params).await
    }

    /// AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
    pub async fn suggest_domains(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/suggest".to_string(),
            path_params: vec![],
            query_params: vec!["keywords".to_string(), "tlds".to_string(), "style".to_string(), "industry".to_string(), "language".to_string(), "limit".to_string(), "check".to_string()],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct IntelligenceService {
    client: Arc<InnerClient>,
}

impl IntelligenceService {
    /// Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
    pub async fn bulk_get_hosting(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/hosting/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
    pub async fn bulk_get_url_intelligence(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/url-intelligence/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
    pub async fn bulk_get_website_identity_assets(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/identity-assets/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
    pub async fn bulk_resolve_internet_identity(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/identity-resolution/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Cancel unstarted technology scan work and settle item-level refunds. An already running browser scan may finish, but its result is discarded.
    pub async fn cancel_tech_scan_job(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "DELETE".to_string(),
            path: "/v1/tech/jobs/:job_id".to_string(),
            path_params: vec!["job_id".to_string()],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
    pub async fn categorize_website(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/categorize".to_string(),
            path_params: vec![],
            query_params: vec!["url".to_string(), "domain".to_string(), "skip_cache".to_string(), "min_confidence".to_string()],
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

    /// Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
    pub async fn create_tech_scan_job(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/tech/jobs".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
    pub async fn get_categorization_taxonomy(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/categorize/taxonomy".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Extract company information from a domain. Get name, industry, and contact details.
    pub async fn get_company(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/company".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Compare domains for similarity. Detect typosquatting with multiple algorithms.
    pub async fn get_domain_similarity(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/similarity".to_string(),
            path_params: vec![],
            query_params: vec!["domain1".to_string(), "domain2".to_string()],
            has_body: false,
        }, params).await
    }

    /// Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
    pub async fn get_hosting(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/hosting".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
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
            query_params: vec!["url".to_string(), "domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
    pub async fn get_tech_scan_job(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tech/jobs/:job_id".to_string(),
            path_params: vec!["job_id".to_string()],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
    pub async fn get_tech_scan_job_results(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tech/jobs/:job_id/results".to_string(),
            path_params: vec!["job_id".to_string()],
            query_params: vec!["cursor".to_string(), "limit".to_string()],
            has_body: false,
        }, params).await
    }

    /// Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
    pub async fn get_tech_stack(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tech".to_string(),
            path_params: vec![],
            query_params: vec!["url".to_string(), "domain".to_string(), "mode".to_string(), "max_pages".to_string(), "skip_cache".to_string()],
            has_body: false,
        }, params).await
    }

    /// Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
    pub async fn get_url_intelligence(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/url-intelligence".to_string(),
            path_params: vec![],
            query_params: vec!["url".to_string()],
            has_body: false,
        }, params).await
    }

    /// Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
    pub async fn get_website_identity_assets(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/identity-assets".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// List recent short-lived technology scan jobs for the authenticated account.
    pub async fn list_tech_scan_jobs(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/tech/jobs".to_string(),
            path_params: vec![],
            query_params: vec!["limit".to_string(), "cursor".to_string()],
            has_body: false,
        }, params).await
    }

    /// Run up to 10 ordered fast technology scans in one request. Each valid target is billed independently, and failed upstream scans are refunded independently.
    pub async fn post_tech_stack_bulk(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/tech/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
    pub async fn resolve_internet_identity(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/identity-resolution".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct MetaService {
    client: Arc<InnerClient>,
}

impl MetaService {
    /// Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
    pub async fn cancel_api_batch(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "DELETE".to_string(),
            path: "/v1/batches/:job_id".to_string(),
            path_params: vec!["job_id".to_string()],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and failed items are refunded independently.
    pub async fn create_api_batch(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/batches".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Download the full disposable email domain dataset in various formats.
    pub async fn download_email_blacklist(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email/blacklist/download".to_string(),
            path_params: vec![],
            query_params: vec!["format".to_string()],
            has_body: false,
        }, params).await
    }

    /// Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
    pub async fn get_api_batch(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/batches/:job_id".to_string(),
            path_params: vec!["job_id".to_string()],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
    pub async fn get_api_batch_results(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/batches/:job_id/results".to_string(),
            path_params: vec!["job_id".to_string()],
            query_params: vec!["after".to_string(), "limit".to_string(), "format".to_string()],
            has_body: false,
        }, params).await
    }

    /// Browse the disposable email domain dataset as a paginated data feed.
    pub async fn get_email_blacklist_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email/blacklist".to_string(),
            path_params: vec![],
            query_params: vec!["limit".to_string(), "offset".to_string(), "format".to_string()],
            has_body: false,
        }, params).await
    }

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

    /// List unexpired asynchronous API batches for the active customer account.
    pub async fn list_api_batches(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/batches".to_string(),
            path_params: vec![],
            query_params: vec!["limit".to_string()],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct OsintService {
    client: Arc<InnerClient>,
}

impl OsintService {
    /// Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
    pub async fn bulk_get_rdap(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/rdap/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

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

    /// Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
    pub async fn get_ip_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ip".to_string(),
            path_params: vec![],
            query_params: vec!["ip".to_string(), "domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Lookup MAC address vendor information. Identify network device manufacturers.
    pub async fn get_mac_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/mac".to_string(),
            path_params: vec![],
            query_params: vec!["mac".to_string()],
            has_body: false,
        }, params).await
    }

    /// Returns parameter help and an example response for the MAC address lookup endpoint.
    pub async fn get_mac_lookup_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/mac/info".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Get raw RDAP response for a domain, IP address, or autonomous system number.
    pub async fn get_rdap(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/rdap".to_string(),
            path_params: vec![],
            query_params: vec!["query".to_string(), "type".to_string(), "domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Get structured WHOIS/RDAP registration data for a domain.
    pub async fn get_whois(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/whois".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
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
    /// Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
    pub async fn bulk_pricing(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/prices/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
    pub async fn compare_prices(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices/compare".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "registrars".to_string(), "skip_cache".to_string()],
            has_body: false,
        }, params).await
    }

    /// Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
    pub async fn get_prices(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices".to_string(),
            path_params: vec![],
            query_params: vec!["tlds".to_string(), "registrars".to_string(), "skip_cache".to_string()],
            has_body: false,
        }, params).await
    }

    /// List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
    pub async fn get_registrars(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices/registrars".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }

    /// Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
    pub async fn get_tld_pricing(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/prices/tld/:tld".to_string(),
            path_params: vec!["tld".to_string()],
            query_params: vec!["registrars".to_string(), "skip_cache".to_string()],
            has_body: false,
        }, params).await
    }
}

#[derive(Clone)]
pub struct RecipesService {
    client: Arc<InnerClient>,
}

impl RecipesService {
    /// Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
    pub async fn recipe_brand_launch(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/brand-launch".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "brand_name".to_string(), "platforms".to_string()],
            has_body: false,
        }, params).await
    }

    /// Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
    pub async fn recipe_competitor_intel(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/competitor-intel".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "discover_subdomains".to_string(), "analyze_email".to_string()],
            has_body: false,
        }, params).await
    }

    /// Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
    pub async fn recipe_defensive_registration(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/defensive-registration".to_string(),
            path_params: vec![],
            query_params: vec!["brand".to_string(), "owned_domains".to_string(), "priority_tlds".to_string(), "include_typos".to_string(), "budget".to_string()],
            has_body: false,
        }, params).await
    }

    /// Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
    pub async fn recipe_dns_migration(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/dns-migration".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "target_nameservers".to_string(), "critical_records".to_string()],
            has_body: false,
        }, params).await
    }

    /// AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
    pub async fn recipe_domain_finder(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/domain-finder".to_string(),
            path_params: vec![],
            query_params: vec!["keywords".to_string(), "tlds".to_string(), "style".to_string(), "max_length".to_string(), "language".to_string(), "limit".to_string()],
            has_body: false,
        }, params).await
    }

    /// Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
    pub async fn recipe_due_diligence(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/due-diligence".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "include_competitors".to_string()],
            has_body: false,
        }, params).await
    }

    /// Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
    pub async fn recipe_email_deliverability(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/email-deliverability".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "dkim_selectors".to_string(), "check_blacklists".to_string()],
            has_body: false,
        }, params).await
    }

    /// Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
    pub async fn recipe_infrastructure_discovery(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/infrastructure-discovery".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "depth".to_string(), "include_historical".to_string()],
            has_body: false,
        }, params).await
    }

    /// Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
    pub async fn recipe_phishing_investigation(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/phishing-investigation".to_string(),
            path_params: vec![],
            query_params: vec!["suspicious_domain".to_string(), "legitimate_domain".to_string(), "collect_evidence".to_string()],
            has_body: false,
        }, params).await
    }

    /// Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
    pub async fn recipe_portfolio_audit(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/portfolio-audit".to_string(),
            path_params: vec![],
            query_params: vec!["domains".to_string(), "include_valuation".to_string(), "include_health".to_string(), "alert_expiring_days".to_string()],
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

    /// Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
    pub async fn recipe_threat_assessment(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/recipes/threat-assessment".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "max_threats".to_string(), "include_evidence".to_string()],
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

    /// Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
    pub async fn bulk_get_certificates(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/certificates/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
    pub async fn bulk_get_email_auth(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/email-auth/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
    pub async fn bulk_get_subdomains(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/subdomains/bulk".to_string(),
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
            query_params: vec!["email".to_string(), "checks".to_string()],
            has_body: false,
        }, params).await
    }

    /// Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
    pub async fn get_certificates(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/certificates".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "include_subdomains".to_string(), "include_expired".to_string(), "limit".to_string(), "cursor".to_string()],
            has_body: false,
        }, params).await
    }

    /// Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
    pub async fn get_domain_reputation(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/reputation".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
    pub async fn get_email_auth(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email-auth".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "selectors".to_string()],
            has_body: false,
        }, params).await
    }

    /// Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and proxy-backed mail security checks.
    pub async fn get_email_compliance(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/email/compliance".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "selectors".to_string(), "providers".to_string()],
            has_body: false,
        }, params).await
    }

    /// Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
    pub async fn get_ssl_audit(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/audit".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Analyze the certificate chain including issuer, validity, and trust chain verification.
    pub async fn get_ssl_chain(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/chain".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
    pub async fn get_ssl_deep_scan(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/deep-scan".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "refresh".to_string(), "profile".to_string()],
            has_body: false,
        }, params).await
    }

    /// Check if an SSL certificate is expiring soon with configurable alert threshold.
    pub async fn get_ssl_expiring(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/expiring".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "threshold_days".to_string()],
            has_body: false,
        }, params).await
    }

    /// Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
    pub async fn get_ssl_grade(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/ssl/grade".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string()],
            has_body: false,
        }, params).await
    }

    /// Return best-effort public hostname evidence from a sequential passive pipeline. Discovery tries crt.sh first, then can fall back to HackerTarget, ThreatMiner, the Wayback Machine, and CertSpotter. Results include their evidence source. DomScan does not brute-force names or crawl the target site, so coverage is incomplete.
    pub async fn get_subdomains(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/subdomains".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "sources".to_string(), "verify".to_string(), "include_wildcards".to_string(), "limit".to_string(), "prefer_cache".to_string()],
            has_body: false,
        }, params).await
    }

    /// Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
    pub async fn get_typosquatting(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/typos".to_string(),
            path_params: vec![],
            query_params: vec!["domain".to_string(), "check_registered".to_string(), "limit".to_string(), "include_tld_swap".to_string()],
            has_body: false,
        }, params).await
    }

    /// Find exposed software versions and deterministic web security misconfigurations using verified technology evidence, exact OSV package matching, CISA Known Exploited Vulnerabilities, FIRST EPSS, and isolated Edge Relay rendering. Results separate affected versions from configuration findings and preserve unknown coverage.
    pub async fn get_vulnerabilities(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/vulnerabilities".to_string(),
            path_params: vec![],
            query_params: vec!["url".to_string(), "domain".to_string(), "mode".to_string()],
            has_body: false,
        }, params).await
    }

    /// Validate, normalize, and enrich international phone numbers with country-specific coverage levels, offline numbering-plan, location, time-zone, original prefix-carrier, portability-support, dialing, short-number, service, and official allocation metadata. US NANPA and Canadian CNA/CNAC snapshots add NPA-NXX central office code status and original code-holder evidence. DomScan uses its own Edge Relay and free local datasets without paid or per-number third-party lookups. Results never claim current carrier, reachability, subscriber identity, or individual-number assignment.
    pub async fn validate_phone_number(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/phone/validate".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and uses one DomScan Edge Relay batch with zero paid or per-number third-party lookups.
    pub async fn validate_phone_numbers_bulk(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/phone/validate/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
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
    /// Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
    pub async fn bulk_check_social_handles(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "POST".to_string(),
            path: "/v1/social/bulk".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: true,
        }, params).await
    }

    /// Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
    pub async fn check_social_handles(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/social".to_string(),
            path_params: vec![],
            query_params: vec!["handle".to_string(), "platforms".to_string(), "resources".to_string()],
            has_body: false,
        }, params).await
    }

    /// Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
    pub async fn get_social_info(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: "GET".to_string(),
            path: "/v1/social/info".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }, params).await
    }
}
