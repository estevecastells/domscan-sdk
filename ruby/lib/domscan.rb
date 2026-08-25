# frozen_string_literal: true

require "json"
require "net/http"
require "uri"
require "time"

module DomScan
  class APIError < StandardError
    attr_reader :status, :code, :details, :request_id

    def initialize(message, status:, code: nil, details: nil, request_id: nil)
      super(message)
      @status = status
      @code = code
      @details = details
      @request_id = request_id
    end
  end

  class Service
    def initialize(client)
      @client = client
    end
  end

  class Client
    attr_reader :availability, :dns, :domain, :intelligence, :meta, :osint, :pricing, :recipes, :security, :social, :user

    def initialize(api_key: ENV["DOMSCAN_API_KEY"], base_url: "https://domscan.net", timeout: 10, headers: {}, user_agent: "domscan-ruby/0.3.0")
      @api_key = api_key
      @base_url = base_url.sub(%r{/+$}, "")
      @timeout = timeout
      @headers = headers
      @user_agent = user_agent
      @availability = AvailabilityService.new(self)
      @dns = DnsService.new(self)
      @domain = DomainService.new(self)
      @intelligence = IntelligenceService.new(self)
      @meta = MetaService.new(self)
      @osint = OsintService.new(self)
      @pricing = PricingService.new(self)
      @recipes = RecipesService.new(self)
      @security = SecurityService.new(self)
      @social = SocialService.new(self)
      @user = UserService.new(self)
    end

    def request(endpoint, params = {})
      endpoint_lookup = lambda do |key|
        endpoint[key] || endpoint[key.to_sym]
      end

      request_path = endpoint_lookup.call("path")
      consumed_keys = []

      endpoint_lookup.call("pathParams").each do |path_param|
        value = params[path_param] || params[path_param.to_sym]
        raise ArgumentError, "Missing required path parameter: #{path_param}" if value.nil?

        request_path = request_path.gsub(":#{path_param}", URI.encode_www_form_component(value.to_s))
        consumed_keys << path_param
        consumed_keys << path_param.to_sym
      end

      remaining = params.each_with_object({}) do |(key, value), memo|
        next if value.nil? || consumed_keys.include?(key)

        memo[key.to_s] = value
      end

      query_payload = if endpoint_lookup.call("hasBody")
        endpoint_lookup.call("queryParams").each_with_object({}) do |query_key, memo|
          memo[query_key] = remaining[query_key] if remaining.key?(query_key)
        end
      else
        remaining.dup
      end

      uri = URI.parse(@base_url + request_path)
      unless query_payload.empty?
        uri.query = URI.encode_www_form(
          query_payload.transform_values { |value| serialize_query_value(value) }
        )
      end

      request_class = case endpoint_lookup.call("method")
      when "GET" then Net::HTTP::Get
      when "POST" then Net::HTTP::Post
      when "PUT" then Net::HTTP::Put
      when "PATCH" then Net::HTTP::Patch
      when "DELETE" then Net::HTTP::Delete
      else
        raise ArgumentError, "Unsupported HTTP method: #{endpoint_lookup.call("method")}"
      end

      request = request_class.new(uri)
      request["Accept"] = "application/json"
      request["User-Agent"] = @user_agent
      request["X-DomScan-SDK"] = @user_agent
      request["Authorization"] = "Bearer #{@api_key}" if @api_key
      request["X-API-Key"] = @api_key if @api_key
      @headers.each { |key, value| request[key] = value }

      if endpoint_lookup.call("hasBody")
        body_payload = remaining.reject { |key, _value| endpoint_lookup.call("queryParams").include?(key) }
        request["Content-Type"] = "application/json"
        request.body = JSON.generate(body_payload)
      end

      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https", read_timeout: @timeout, open_timeout: @timeout) do |http|
        http.request(request)
      end

      payload = decode_payload(response.body.to_s, response["content-type"].to_s)
      return payload if response.code.to_i < 400

      error_payload = payload.is_a?(Hash) && payload["error"].is_a?(Hash) ? payload["error"] : {}
      raise APIError.new(
        error_payload["message"] || "DomScan request failed with status #{response.code}",
        status: response.code.to_i,
        code: error_payload["code"],
        details: payload,
        request_id: response["x-request-id"]
      )
    end

    private

    def decode_payload(body, content_type)
      return body unless content_type.include?("application/json")

      JSON.parse(body)
    rescue JSON::ParserError
      body
    end

    def serialize_query_value(value)
      case value
      when Array
        value.compact.map { |item| serialize_query_value(item) }.join(",")
      when TrueClass then "true"
      when FalseClass then "false"
      when Time, Date, DateTime then value.iso8601
      when Hash then JSON.generate(value)
      else
        value.to_s
      end
    end
  end

  class AvailabilityService < Service
    # Check availability of multiple complete domain names at once.
    def bulk_check_domains(params = {})
      @client.request({"operationId":"bulkCheckDomains","title":"Bulk Domain Check","description":"Check availability of multiple complete domain names at once.","method":"POST","path":"/v1/status/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.
    def check_domain_availability(params = {})
      @client.request({"operationId":"checkDomainAvailability","title":"Domain Availability","description":"Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results. Primary format: name + tlds. Single-domain shortcut: domain=example.com.","method":"GET","path":"/v1/status","pathParams":[],"queryParams":["name","tlds","domain","prefer_cache"],"hasBody":false}, params)
    end

    # Create a resumable asynchronous search over a curated English single-word corpus sourced from iannuttall/unclaimed under the MIT License. Check each selected word across 1 to 5 supported TLDs, with a hard limit of 100 word-TLD checks per job. Available, registered, and unknown remain distinct outcomes. Jobs use the existing batch status, results, and cancellation lifecycle.
    def create_domain_discovery_job(params = {})
      @client.request({"operationId":"createDomainDiscoveryJob","title":"Create Domain Discovery Job","description":"Create a resumable asynchronous search over a curated English single-word corpus sourced from iannuttall/unclaimed under the MIT License. Check each selected word across 1 to 5 supported TLDs, with a hard limit of 100 word-TLD checks per job. Available, registered, and unknown remain distinct outcomes. Jobs use the existing batch status, results, and cancellation lifecycle.","method":"POST","path":"/v1/domain-discovery/jobs","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Get information about which TLDs are supported and their RDAP server status.
    def get_coverage(params = {})
      @client.request({"operationId":"getCoverage","title":"RDAP Coverage","description":"Get information about which TLDs are supported and their RDAP server status.","method":"GET","path":"/v1/coverage","pathParams":[],"queryParams":["live"],"hasBody":false}, params)
    end
  end

  class DnsService < Service
    # Build a DMARC record with policy, reporting, and alignment options.
    def build_dmarc(params = {})
      @client.request({"operationId":"buildDmarc","title":"DMARC Builder","description":"Build a DMARC record with policy, reporting, and alignment options.","method":"POST","path":"/v1/tools/dmarc/build","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Build an SPF record from configuration options with validation and recommendations.
    def build_spf(params = {})
      @client.request({"operationId":"buildSpf","title":"SPF Builder","description":"Build an SPF record from configuration options with validation and recommendations.","method":"POST","path":"/v1/tools/spf/build","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.
    def bulk_dns_propagation(params = {})
      @client.request({"operationId":"bulkDnsPropagation","title":"Bulk DNS Resolver Comparison","description":"Compare answers from the configured public recursive DNS resolvers for up to 10 domains. Results preserve input order and report per-domain errors.","method":"POST","path":"/v1/dns/propagation/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check a specific DKIM selector for a domain and validate the public key.
    def check_dkim(params = {})
      @client.request({"operationId":"checkDkim","title":"DKIM Check","description":"Check a specific DKIM selector for a domain and validate the public key.","method":"GET","path":"/v1/tools/dkim/check","pathParams":[],"queryParams":["domain","selector"],"hasBody":false}, params)
    end

    # Discover DKIM selectors for a domain by checking common selector names.
    def discover_dkim(params = {})
      @client.request({"operationId":"discoverDkim","title":"DKIM Discovery","description":"Discover DKIM selectors for a domain by checking common selector names.","method":"GET","path":"/v1/tools/dkim/discover","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
    def flatten_spf(params = {})
      @client.request({"operationId":"flattenSpf","title":"SPF Flattener","description":"Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.","method":"POST","path":"/v1/tools/spf/flatten","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.
    def get_all_dns_records(params = {})
      @client.request({"operationId":"getAllDnsRecords","title":"DNS All Records","description":"Get all major DNS record types for a domain in a single call with IPv6 parity, TXT classification, wildcard probe, and warning signals.","method":"GET","path":"/v1/dns/all","pathParams":[],"queryParams":["domain","wildcard_probe"],"hasBody":false}, params)
    end

    # Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.
    def get_dns_history(params = {})
      @client.request({"operationId":"getDnsHistory","title":"DNS History","description":"Review day-level DNS record values observed by successful DomScan DNS lookups. This lookup-driven observation log can miss changes between lookups and does not include external passive DNS sources.","method":"GET","path":"/v1/dns/history","pathParams":[],"queryParams":["domain","type","from","to","limit"],"hasBody":false}, params)
    end

    # Compare answers from DomScan's configured public recursive resolvers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.
    def get_dns_propagation(params = {})
      @client.request({"operationId":"getDnsPropagation","title":"DNS Resolver Comparison","description":"Compare answers from DomScan's configured public recursive resolvers. Without expected, the percentage reports the largest resolver-convergence cohort. With expected, it reports providers whose answers match that value. This is not a geographic or worldwide propagation measurement.","method":"GET","path":"/v1/dns/propagation","pathParams":[],"queryParams":["domain","type","expected"],"hasBody":false}, params)
    end

    # Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.
    def get_dns_records(params = {})
      @client.request({"operationId":"getDnsRecords","title":"DNS Lookup","description":"Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically with TXT classification and additive warning signals.","method":"GET","path":"/v1/dns","pathParams":[],"queryParams":["domain","type"],"hasBody":false}, params)
    end

    # Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.
    def get_dns_security(params = {})
      @client.request({"operationId":"getDnsSecurity","title":"DNS Security","description":"Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, resolver latency, and AXFR exposure.","method":"GET","path":"/v1/dns/security","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.
    def get_dns_servers(params = {})
      @client.request({"operationId":"getDnsServers","title":"DNS Resolver Providers","description":"List the public recursive DoH providers used for resolver comparison. These are global anycast services, not geographic probes.","method":"GET","path":"/v1/dns/servers","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Validate a DMARC record for syntax errors and configuration issues.
    def validate_dmarc(params = {})
      @client.request({"operationId":"validateDmarc","title":"DMARC Validator","description":"Validate a DMARC record for syntax errors and configuration issues.","method":"POST","path":"/v1/tools/dmarc/validate","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
    def validate_spf(params = {})
      @client.request({"operationId":"validateSpf","title":"SPF Validator","description":"Validate an SPF record for syntax errors, DNS lookup limits, and best practices.","method":"POST","path":"/v1/tools/spf/validate","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end
  end

  class DomainService < Service
    # Get value estimates for multiple domains at once.
    def bulk_domain_value(params = {})
      @client.request({"operationId":"bulkDomainValue","title":"Bulk Domain Valuation","description":"Get value estimates for multiple domains at once.","method":"POST","path":"/v1/value/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    def bulk_get_domain_profile(params = {})
      @client.request({"operationId":"bulkGetDomainProfile","title":"Domain Profile","description":"Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.","method":"POST","path":"/v1/profile/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Compare up to 50 candidate brand names and return ranked scores.
    def compare_brand_names(params = {})
      @client.request({"operationId":"compareBrandNames","title":"Compare Brand Names","description":"Compare up to 50 candidate brand names and return ranked scores.","method":"POST","path":"/v1/score/compare","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Compare two domains side-by-side across multiple metrics and attributes.
    def compare_domains(params = {})
      @client.request({"operationId":"compareDomains","title":"Domain Compare","description":"Compare two domains side-by-side across multiple metrics and attributes.","method":"GET","path":"/v1/compare","pathParams":[],"queryParams":["domains"],"hasBody":false}, params)
    end

    # Comprehensive health checks with DNS, SSL, email, extended TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.
    def get_domain_health(params = {})
      @client.request({"operationId":"getDomainHealth","title":"Domain Health","description":"Comprehensive health checks with DNS, SSL, email, extended TLS and HTTP versions, HSTS audit, SMTP TLS, and MX FCrDNS signals.","method":"GET","path":"/v1/health","pathParams":[],"queryParams":["domain","details"],"hasBody":false}, params)
    end

    # Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.
    def get_domain_overview(params = {})
      @client.request({"operationId":"getDomainOverview","title":"Domain Overview","description":"Aggregate DNS, RDAP registration, health, reputation, and popularity observations in one response, with null unknowns and per-component freshness.","method":"GET","path":"/v1/overview","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.
    def get_domain_popularity(params = {})
      @client.request({"operationId":"getDomainPopularity","title":"Domain Popularity","description":"Get the current research-grade Tranco rank and bucket for a domain, with explicit ranked, unranked, and unknown states, source date, cache state, and optional lookup-driven history.","method":"GET","path":"/v1/popularity","pathParams":[],"queryParams":["domain","include_history","history_limit"],"hasBody":false}, params)
    end

    # Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.
    def get_domain_popularity_history(params = {})
      @client.request({"operationId":"getDomainPopularityHistory","title":"Domain Popularity History","description":"Read prior Tranco observations recorded by DomScan lookups. This is a lookup-driven history, not a complete daily rank series.","method":"GET","path":"/v1/popularity/history","pathParams":[],"queryParams":["domain","limit"],"hasBody":false}, params)
    end

    # Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    def get_domain_profile(params = {})
      @client.request({"operationId":"getDomainProfile","title":"Domain Profile","description":"Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.","method":"GET","path":"/v1/profile","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Calculate an overall domain quality score based on multiple factors.
    def get_domain_score(params = {})
      @client.request({"operationId":"getDomainScore","title":"Domain Score","description":"Calculate an overall domain quality score based on multiple factors.","method":"GET","path":"/v1/score","pathParams":[],"queryParams":["name","domain"],"hasBody":false}, params)
    end

    # Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
    def get_domain_value(params = {})
      @client.request({"operationId":"getDomainValue","title":"Domain Valuation","description":"Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.","method":"GET","path":"/v1/value","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Fast health check with essential metrics only.
    def get_quick_health(params = {})
      @client.request({"operationId":"getQuickHealth","title":"Quick Health Check","description":"Fast health check with essential metrics only.","method":"GET","path":"/v1/health/quick","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Returns scoring dimensions, grade scale, and related scoring endpoints.
    def get_score_info(params = {})
      @client.request({"operationId":"getScoreInfo","title":"Brand Scoring Reference","description":"Returns scoring dimensions, grade scale, and related scoring endpoints.","method":"GET","path":"/v1/score/info","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get detailed information about a specific TLD.
    def get_tld_detail(params = {})
      @client.request({"operationId":"getTldDetail","title":"TLD Detail","description":"Get detailed information about a specific TLD.","method":"GET","path":"/v1/tlds/:tld","pathParams":["tld"],"queryParams":[],"hasBody":false}, params)
    end

    # Get list of all supported TLDs with metadata.
    def get_tlds(params = {})
      @client.request({"operationId":"getTlds","title":"TLD List","description":"Get list of all supported TLDs with metadata.","method":"GET","path":"/v1/tlds","pathParams":[],"queryParams":["type","trust_tier","use_case"],"hasBody":false}, params)
    end

    # AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
    def suggest_domains(params = {})
      @client.request({"operationId":"suggestDomains","title":"Domain Suggestions","description":"AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.","method":"GET","path":"/v1/suggest","pathParams":[],"queryParams":["keywords","tlds","style","industry","language","limit","check"],"hasBody":false}, params)
    end
  end

  class IntelligenceService < Service
    # Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.
    def bulk_get_hosting(params = {})
      @client.request({"operationId":"bulkGetHosting","title":"Bulk Hosting Detection","description":"Detect hosting, CDN, WAF, DNS, and email infrastructure for up to 10 domains. Results preserve input order and include per-domain errors.","method":"POST","path":"/v1/hosting/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.
    def bulk_get_url_intelligence(params = {})
      @client.request({"operationId":"bulkGetUrlIntelligence","title":"Bulk Unified URL Intelligence","description":"Extract normalized URL intelligence for up to 10 public URLs. Results preserve input order and include per-item errors.","method":"POST","path":"/v1/url-intelligence/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.
    def bulk_get_website_identity_assets(params = {})
      @client.request({"operationId":"bulkGetWebsiteIdentityAssets","title":"Bulk Website Identity Assets","description":"Extract website identity assets for up to 10 domains. Results preserve input order and include per-item errors.","method":"POST","path":"/v1/identity-assets/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.
    def bulk_resolve_internet_identity(params = {})
      @client.request({"operationId":"bulkResolveInternetIdentity","title":"Bulk Internet Identity Resolution","description":"Resolve public identities for up to 10 company domains. Results preserve input order and include per-item errors.","method":"POST","path":"/v1/identity-resolution/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Cancel unstarted technology scan work and settle item-level refunds. Work already in progress may finish and remains available in the job results.
    def cancel_tech_scan_job(params = {})
      @client.request({"operationId":"cancelTechScanJob","title":"Cancel Async Tech Scan Job","description":"Cancel unstarted technology scan work and settle item-level refunds. Work already in progress may finish and remains available in the job results.","method":"DELETE","path":"/v1/tech/jobs/:job_id","pathParams":["job_id"],"queryParams":[],"hasBody":false}, params)
    end

    # Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
    def categorize_website(params = {})
      @client.request({"operationId":"categorizeWebsite","title":"Website Categorization","description":"Classify websites into DomScan IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.","method":"GET","path":"/v1/categorize","pathParams":[],"queryParams":["url","domain","skip_cache","min_confidence"],"hasBody":false}, params)
    end

    # Categorize up to 10 websites in parallel with caching.
    def categorize_website_bulk(params = {})
      @client.request({"operationId":"categorizeWebsiteBulk","title":"Bulk Website Categorization","description":"Categorize up to 10 websites in parallel with caching.","method":"POST","path":"/v1/categorize/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Queue 1 to 100 public page scrapes for asynchronous processing. Batch jobs are available to paid accounts, require an idempotency key, allow up to three active jobs and 300 queued items per account, and bill each accepted URL at the selected mode price. CAPTCHA solving and premium proxy selection are not offered.
    def create_scrape_job(params = {})
      @client.request({"operationId":"createScrapeJob","title":"Create Async Scrape Job","description":"Queue 1 to 100 public page scrapes for asynchronous processing. Batch jobs are available to paid accounts, require an idempotency key, allow up to three active jobs and 300 queued items per account, and bill each accepted URL at the selected mode price. CAPTCHA solving and premium proxy selection are not offered.","method":"POST","path":"/v1/scrape/jobs","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.
    def create_tech_scan_job(params = {})
      @client.request({"operationId":"createTechScanJob","title":"Create Async Tech Scan Job","description":"Create a durable asynchronous technology scan job for up to 100 public targets. Supports fast, JavaScript-rendered, and bounded same-origin deep modes with item-level billing and refunds.","method":"POST","path":"/v1/tech/jobs","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.
    def get_categorization_taxonomy(params = {})
      @client.request({"operationId":"getCategorizationTaxonomy","title":"Categorization Taxonomy","description":"List the DomScan IAB-inspired category IDs, response category names, taxonomy names, and subcategories returned by the Website Categorization API.","method":"GET","path":"/v1/categorize/taxonomy","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Extract source-backed organization names, descriptions, declared social links, MX-inferred email providers, confidence, and provenance from public website and DNS metadata. Enrichment-only fields can be null.
    def get_company(params = {})
      @client.request({"operationId":"getCompany","title":"Company Lookup","description":"Extract source-backed organization names, descriptions, declared social links, MX-inferred email providers, confidence, and provenance from public website and DNS metadata. Enrichment-only fields can be null.","method":"GET","path":"/v1/company","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Compare domains for similarity. Detect typosquatting with multiple algorithms.
    def get_domain_similarity(params = {})
      @client.request({"operationId":"getDomainSimilarity","title":"Domain Similarity","description":"Compare domains for similarity. Detect typosquatting with multiple algorithms.","method":"GET","path":"/v1/similarity","pathParams":[],"queryParams":["domain1","domain2"],"hasBody":false}, params)
    end

    # Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
    def get_hosting(params = {})
      @client.request({"operationId":"getHosting","title":"Hosting Detection","description":"Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.","method":"GET","path":"/v1/hosting","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
    def get_parking_detection(params = {})
      @client.request({"operationId":"getParkingDetection","title":"Parking Detection","description":"Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.","method":"GET","path":"/v1/parking","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
    def get_redirects(params = {})
      @client.request({"operationId":"getRedirects","title":"Redirect Chain","description":"Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.","method":"GET","path":"/v1/redirects","pathParams":[],"queryParams":["url","domain"],"hasBody":false}, params)
    end

    # Get owner-scoped progress, item counts, billing settlement, and expiration details.
    def get_scrape_job(params = {})
      @client.request({"operationId":"getScrapeJob","title":"Get Async Scrape Job","description":"Get owner-scoped progress, item counts, billing settlement, and expiration details.","method":"GET","path":"/v1/scrape/jobs/:job_id","pathParams":["job_id"],"queryParams":[],"hasBody":false}, params)
    end

    # Get ordered, paginated results for an owner-scoped scrape job. Full page results expire after 24 hours.
    def get_scrape_job_results(params = {})
      @client.request({"operationId":"getScrapeJobResults","title":"Get Async Scrape Results","description":"Get ordered, paginated results for an owner-scoped scrape job. Full page results expire after 24 hours.","method":"GET","path":"/v1/scrape/jobs/:job_id/results","pathParams":["job_id"],"queryParams":["limit","offset"],"hasBody":false}, params)
    end

    # Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.
    def get_tech_scan_job(params = {})
      @client.request({"operationId":"getTechScanJob","title":"Get Async Tech Scan Job","description":"Get owner-scoped progress, item counts, billing settlement, and expiration details for a technology scan job.","method":"GET","path":"/v1/tech/jobs/:job_id","pathParams":["job_id"],"queryParams":[],"hasBody":false}, params)
    end

    # Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.
    def get_tech_scan_job_results(params = {})
      @client.request({"operationId":"getTechScanJobResults","title":"Get Async Tech Scan Results","description":"Get ordered, signed-cursor-paginated results for a technology scan job. Full results expire after 48 hours and operational job records expire after seven days.","method":"GET","path":"/v1/tech/jobs/:job_id/results","pathParams":["job_id"],"queryParams":["cursor","limit"],"hasBody":false}, params)
    end

    # Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.
    def get_tech_stack(params = {})
      @client.request({"operationId":"getTechStack","title":"Tech Stack Detection","description":"Detect 500+ verified website technologies across 80+ categories using bounded HTTP signals, rendered JavaScript globals, observed network URLs, and same-origin multi-page analysis. Returns confidence, sanitized evidence scoped to each page, caveats, provenance, explicit limits, and complete or partial coverage.","method":"GET","path":"/v1/tech","pathParams":[],"queryParams":["url","domain","mode","max_pages","skip_cache"],"hasBody":false}, params)
    end

    # Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.
    def get_url_intelligence(params = {})
      @client.request({"operationId":"getUrlIntelligence","title":"Unified URL Intelligence","description":"Extract normalized metadata, link-preview assets, Open Graph and Twitter Card fields, canonical URL, robots directives, structured-data types, security headers, links, contacts, and declared profiles from a public URL.","method":"GET","path":"/v1/url-intelligence","pathParams":[],"queryParams":["url","skip_cache"],"hasBody":false}, params)
    end

    # Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.
    def get_website_identity_assets(params = {})
      @client.request({"operationId":"getWebsiteIdentityAssets","title":"Website Identity Assets","description":"Discover a website organization name, logo candidates, favicons, touch icons, preview image, theme color, manifest, and declared social profiles from public website metadata.","method":"GET","path":"/v1/identity-assets","pathParams":[],"queryParams":["domain","skip_cache"],"hasBody":false}, params)
    end

    # List recent short-lived technology scan jobs for the authenticated account.
    def list_tech_scan_jobs(params = {})
      @client.request({"operationId":"listTechScanJobs","title":"List Async Tech Scan Jobs","description":"List recent short-lived technology scan jobs for the authenticated account.","method":"GET","path":"/v1/tech/jobs","pathParams":[],"queryParams":["limit","cursor"],"hasBody":false}, params)
    end

    # Run up to 10 ordered fast technology scans in one request. Each attempted target is billed independently, including target-site failures. Verified DomScan service failures are refunded independently.
    def post_tech_stack_bulk(params = {})
      @client.request({"operationId":"postTechStackBulk","title":"Bulk Tech Stack Detection","description":"Run up to 10 ordered fast technology scans in one request. Each attempted target is billed independently, including target-site failures. Verified DomScan service failures are refunded independently.","method":"POST","path":"/v1/tech/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.
    def resolve_internet_identity(params = {})
      @client.request({"operationId":"resolveInternetIdentity","title":"Internet Identity Resolution","description":"Resolve a company domain into public social, developer, creator, federated, and app-store identities explicitly declared by its website.","method":"GET","path":"/v1/identity-resolution","pathParams":[],"queryParams":["domain","skip_cache"],"hasBody":false}, params)
    end

    # Retrieve one public web page with bounded redirects and response size. Standard requests use one attempt, resilient requests may use one eligible retry, and rendered modes execute page JavaScript in an isolated browser. Free accounts can use standard mode with lower request, concurrency, daily, monthly, and response-size limits. CAPTCHA solving and premium proxy selection are not offered. Target-site failures remain billable after processing starts; verified platform failures are refunded.
    def scrape_page(params = {})
      @client.request({"operationId":"scrapePage","title":"Single Page Scrape","description":"Retrieve one public web page with bounded redirects and response size. Standard requests use one attempt, resilient requests may use one eligible retry, and rendered modes execute page JavaScript in an isolated browser. Free accounts can use standard mode with lower request, concurrency, daily, monthly, and response-size limits. CAPTCHA solving and premium proxy selection are not offered. Target-site failures remain billable after processing starts; verified platform failures are refunded.","method":"POST","path":"/v1/scrape","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end
  end

  class MetaService < Service
    # Cancel unstarted batch items and refund their item charges. An item already being processed may finish.
    def cancel_api_batch(params = {})
      @client.request({"operationId":"cancelApiBatch","title":"Cancel Async API Batch","description":"Cancel unstarted batch items and refund their item charges. An item already being processed may finish.","method":"DELETE","path":"/v1/batches/:job_id","pathParams":["job_id"],"queryParams":[],"hasBody":false}, params)
    end

    # Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and refund rules. Target-site outcomes remain billed, while verified service failures are refunded independently.
    def create_api_batch(params = {})
      @client.request({"operationId":"createApiBatch","title":"Create Async API Batch","description":"Queue up to 100 supported GET API requests for asynchronous processing. Each item keeps normal endpoint pricing and refund rules. Target-site outcomes remain billed, while verified service failures are refunded independently.","method":"POST","path":"/v1/batches","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Download the full disposable email domain dataset in various formats.
    def download_email_blacklist(params = {})
      @client.request({"operationId":"downloadEmailBlacklist","title":"Download Disposable Email Dataset","description":"Download the full disposable email domain dataset in various formats.","method":"GET","path":"/v1/email/blacklist/download","pathParams":[],"queryParams":["format"],"hasBody":false}, params)
    end

    # Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.
    def get_api_batch(params = {})
      @client.request({"operationId":"getApiBatch","title":"Get Async API Batch","description":"Get progress, item counts, billing settlement, webhook delivery state, and expiration for an account API batch.","method":"GET","path":"/v1/batches/:job_id","pathParams":["job_id"],"queryParams":[],"hasBody":false}, params)
    end

    # Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.
    def get_api_batch_results(params = {})
      @client.request({"operationId":"getApiBatchResults","title":"Get Async API Batch Results","description":"Get ordered JSON results or download all items as RFC 4180 CSV for an account API batch. Results and job metadata expire 24 hours after creation.","method":"GET","path":"/v1/batches/:job_id/results","pathParams":["job_id"],"queryParams":["after","limit","format"],"hasBody":false}, params)
    end

    # Browse the disposable email domain dataset as a paginated data feed.
    def get_email_blacklist_info(params = {})
      @client.request({"operationId":"getEmailBlacklistInfo","title":"Disposable Email Dataset","description":"Browse the disposable email domain dataset as a paginated data feed.","method":"GET","path":"/v1/email/blacklist","pathParams":[],"queryParams":["limit","offset","format"],"hasBody":false}, params)
    end

    # Get credit costs per endpoint and API pricing information.
    def get_pricing_info(params = {})
      @client.request({"operationId":"getPricingInfo","title":"API Pricing Info","description":"Get credit costs per endpoint and API pricing information.","method":"GET","path":"/v1/pricing","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # List unexpired asynchronous API batches for the active customer account.
    def list_api_batches(params = {})
      @client.request({"operationId":"listApiBatches","title":"List Async API Batches","description":"List unexpired asynchronous API batches for the active customer account.","method":"GET","path":"/v1/batches","pathParams":[],"queryParams":["limit"],"hasBody":false}, params)
    end
  end

  class OsintService < Service
    # Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.
    def bulk_get_rdap(params = {})
      @client.request({"operationId":"bulkGetRdap","title":"Bulk RDAP Lookup","description":"Query raw RDAP data for up to 10 domains, IP addresses, CIDR ranges, or autonomous system numbers. One query type applies to the whole batch.","method":"POST","path":"/v1/rdap/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Get WHOIS data for multiple domains at once.
    def bulk_whois(params = {})
      @client.request({"operationId":"bulkWhois","title":"Bulk WHOIS Lookup","description":"Get WHOIS data for multiple domains at once.","method":"POST","path":"/v1/whois/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
    def get_domain_lifecycle(params = {})
      @client.request({"operationId":"getDomainLifecycle","title":"Domain Lifecycle","description":"Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.","method":"GET","path":"/v1/lifecycle","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.
    def get_ip_info(params = {})
      @client.request({"operationId":"getIpInfo","title":"IP Geolocation","description":"Get IP or resolved-domain geolocation and ASN data, provider security flags, coarse hosting classification, and FCrDNS. PTR-based signals are derived from the IP, never the caller hostname.","method":"GET","path":"/v1/ip","pathParams":[],"queryParams":["ip","domain"],"hasBody":false}, params)
    end

    # Lookup MAC address vendor information. Identify network device manufacturers.
    def get_mac_info(params = {})
      @client.request({"operationId":"getMacInfo","title":"MAC Address Lookup","description":"Lookup MAC address vendor information. Identify network device manufacturers.","method":"GET","path":"/v1/mac","pathParams":[],"queryParams":["mac"],"hasBody":false}, params)
    end

    # Returns parameter help and an example response for the MAC address lookup endpoint.
    def get_mac_lookup_info(params = {})
      @client.request({"operationId":"getMacLookupInfo","title":"MAC Lookup Reference","description":"Returns parameter help and an example response for the MAC address lookup endpoint.","method":"GET","path":"/v1/mac/info","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get raw RDAP response for a domain, IP address, or autonomous system number.
    def get_rdap(params = {})
      @client.request({"operationId":"getRdap","title":"RDAP Lookup","description":"Get raw RDAP response for a domain, IP address, or autonomous system number.","method":"GET","path":"/v1/rdap","pathParams":[],"queryParams":["query","type","domain"],"hasBody":false}, params)
    end

    # Get structured WHOIS/RDAP registration data for a domain.
    def get_whois(params = {})
      @client.request({"operationId":"getWhois","title":"WHOIS Lookup","description":"Get structured WHOIS/RDAP registration data for a domain.","method":"GET","path":"/v1/whois","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.
    def get_whois_history(params = {})
      @client.request({"operationId":"getWhoisHistory","title":"WHOIS History","description":"Query the DomScan WHOIS observation log. A qualifying fresh, successful RDAP-backed GET /v1/whois or /v2/whois lookup can record at most one normalized snapshot per domain per UTC day. Cached responses, bulk lookups, history reads, and traditional WHOIS-only fallbacks do not add snapshots. This is not a global historical WHOIS archive and does not provide registrant identity or contact history.","method":"GET","path":"/v1/whois/history","pathParams":[],"queryParams":["domain","limit"],"hasBody":false}, params)
    end

    # Fetch RDAP and traditional WHOIS in parallel, then merge available abuse contacts, registrar WHOIS details, glue addresses, and raw WHOIS evidence into the normalized response.
    def get_whois_v2(params = {})
      @client.request({"operationId":"getWhoisV2","title":"Enhanced WHOIS Lookup","description":"Fetch RDAP and traditional WHOIS in parallel, then merge available abuse contacts, registrar WHOIS details, glue addresses, and raw WHOIS evidence into the normalized response.","method":"GET","path":"/v2/whois","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end
  end

  class PricingService < Service
    # Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.
    def bulk_pricing(params = {})
      @client.request({"operationId":"bulkPricing","title":"Bulk Pricing","description":"Read daily standard-price rows for multiple TLDs. Each unique TLD and selected registrar pair costs one credit.","method":"POST","path":"/v1/prices/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.
    def compare_prices(params = {})
      @client.request({"operationId":"comparePrices","title":"Compare Registrar Prices","description":"Compare daily standard-TLD rows and separate credential-backed exact-domain quotes without inferring missing operation prices.","method":"GET","path":"/v1/prices/compare","pathParams":[],"queryParams":["domain","registrars","skip_cache"],"hasBody":false}, params)
    end

    # Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.
    def get_prices(params = {})
      @client.request({"operationId":"getPrices","title":"Domain Pricing","description":"Read daily standard-TLD price snapshots from verified official registrar sources. One credit is charged per unique TLD and selected registrar pair.","method":"GET","path":"/v1/prices","pathParams":[],"queryParams":["tlds","registrars","skip_cache"],"hasBody":false}, params)
    end

    # List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.
    def get_registrars(params = {})
      @client.request({"operationId":"getRegistrars","title":"List Registrars","description":"List registrar metadata and identify which registrars currently have integrated DomScan pricing sources.","method":"GET","path":"/v1/prices/registrars","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.
    def get_tld_pricing(params = {})
      @client.request({"operationId":"getTldPricing","title":"TLD Pricing","description":"Read daily standard-price rows for one TLD, with registrar filters, provenance, freshness, and pair-based billing.","method":"GET","path":"/v1/prices/tld/:tld","pathParams":["tld"],"queryParams":["registrars","skip_cache"],"hasBody":false}, params)
    end
  end

  class RecipesService < Service
    # Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.
    def recipe_brand_launch(params = {})
      @client.request({"operationId":"recipeBrandLaunch","title":"Brand Launch Readiness","description":"Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 4 credits.","method":"GET","path":"/v1/recipes/brand-launch","pathParams":[],"queryParams":["domain","brand_name","platforms"],"hasBody":false}, params)
    end

    # Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.
    def recipe_competitor_intel(params = {})
      @client.request({"operationId":"recipeCompetitorIntel","title":"Competitor Intelligence","description":"Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 5 credits.","method":"GET","path":"/v1/recipes/competitor-intel","pathParams":[],"queryParams":["domain","discover_subdomains","analyze_infrastructure","analyze_email"],"hasBody":false}, params)
    end

    # Brand protection through strategic domain acquisition recommendations. Saves 8 credits.
    def recipe_defensive_registration(params = {})
      @client.request({"operationId":"recipeDefensiveRegistration","title":"Defensive Registration","description":"Brand protection through strategic domain acquisition recommendations. Saves 8 credits.","method":"GET","path":"/v1/recipes/defensive-registration","pathParams":[],"queryParams":["brand","owned_domains","priority_tlds","include_typos","budget"],"hasBody":false}, params)
    end

    # Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.
    def recipe_dns_migration(params = {})
      @client.request({"operationId":"recipeDnsMigration","title":"DNS Migration Check","description":"Pre-migration checklist and current DNS configuration snapshot. Saves 5 credits.","method":"GET","path":"/v1/recipes/dns-migration","pathParams":[],"queryParams":["domain","target_nameservers","critical_records"],"hasBody":false}, params)
    end

    # AI-powered domain discovery with filtering and availability checking. Saves 13 credits.
    def recipe_domain_finder(params = {})
      @client.request({"operationId":"recipeDomainFinder","title":"Domain Finder","description":"AI-powered domain discovery with filtering and availability checking. Saves 13 credits.","method":"GET","path":"/v1/recipes/domain-finder","pathParams":[],"queryParams":["keywords","tlds","style","max_length","language","limit"],"hasBody":false}, params)
    end

    # Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.
    def recipe_due_diligence(params = {})
      @client.request({"operationId":"recipeDueDiligence","title":"Domain Due Diligence","description":"Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 6 credits vs individual calls.","method":"GET","path":"/v1/recipes/due-diligence","pathParams":[],"queryParams":["domain","include_competitors"],"hasBody":false}, params)
    end

    # Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.
    def recipe_email_deliverability(params = {})
      @client.request({"operationId":"recipeEmailDeliverability","title":"Email Deliverability Audit","description":"Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 5 credits.","method":"GET","path":"/v1/recipes/email-deliverability","pathParams":[],"queryParams":["domain","dkim_selectors","check_blacklists"],"hasBody":false}, params)
    end

    # Complete infrastructure mapping and attack surface analysis. Saves 10 credits.
    def recipe_infrastructure_discovery(params = {})
      @client.request({"operationId":"recipeInfrastructureDiscovery","title":"Infrastructure Discovery","description":"Complete infrastructure mapping and attack surface analysis. Saves 10 credits.","method":"GET","path":"/v1/recipes/infrastructure-discovery","pathParams":[],"queryParams":["domain","depth","include_historical"],"hasBody":false}, params)
    end

    # Evidence collection and analysis for suspected phishing domains. Saves 10 credits.
    def recipe_phishing_investigation(params = {})
      @client.request({"operationId":"recipePhishingInvestigation","title":"Phishing Investigation","description":"Evidence collection and analysis for suspected phishing domains. Saves 10 credits.","method":"GET","path":"/v1/recipes/phishing-investigation","pathParams":[],"queryParams":["suspicious_domain","legitimate_domain","collect_evidence"],"hasBody":false}, params)
    end

    # Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.
    def recipe_portfolio_audit(params = {})
      @client.request({"operationId":"recipePortfolioAudit","title":"Portfolio Audit","description":"Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 275 credits.","method":"GET","path":"/v1/recipes/portfolio-audit","pathParams":[],"queryParams":["domains","include_valuation","include_health","include_pricing","alert_expiring_days"],"hasBody":false}, params)
    end

    # Audit domain portfolio via POST for larger domain lists.
    def recipe_portfolio_audit_post(params = {})
      @client.request({"operationId":"recipePortfolioAuditPost","title":"Portfolio Audit (POST)","description":"Audit domain portfolio via POST for larger domain lists.","method":"POST","path":"/v1/recipes/portfolio-audit","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.
    def recipe_threat_assessment(params = {})
      @client.request({"operationId":"recipeThreatAssessment","title":"Threat Assessment","description":"Comprehensive typosquatting and brand threat analysis for security teams. Saves 22 credits.","method":"GET","path":"/v1/recipes/threat-assessment","pathParams":[],"queryParams":["domain","analyze_threats","max_threats","include_evidence"],"hasBody":false}, params)
    end
  end

  class SecurityService < Service
    # Check multiple email domains against blacklists at once.
    def bulk_email_check(params = {})
      @client.request({"operationId":"bulkEmailCheck","title":"Bulk Email Check","description":"Check multiple email domains against blacklists at once.","method":"POST","path":"/v1/email/check/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
    def bulk_get_certificates(params = {})
      @client.request({"operationId":"bulkGetCertificates","title":"Bulk SSL Certificate Search","description":"Search Certificate Transparency data for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.","method":"POST","path":"/v1/certificates/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.
    def bulk_get_email_auth(params = {})
      @client.request({"operationId":"bulkGetEmailAuth","title":"Bulk Email Authentication","description":"Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and recursive SPF behavior for up to 10 domains. Results preserve input order and include per-domain errors.","method":"POST","path":"/v1/email-auth/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.
    def bulk_get_subdomains(params = {})
      @client.request({"operationId":"bulkGetSubdomains","title":"Bulk Subdomain Discovery","description":"Run the passive subdomain evidence pipeline for up to 10 domains with bounded concurrency. Results preserve input order and include per-domain errors.","method":"POST","path":"/v1/subdomains/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check if an email domain is on disposable/temporary email blacklists.
    def check_email_blacklist(params = {})
      @client.request({"operationId":"checkEmailBlacklist","title":"Email Blacklist Check","description":"Check if an email domain is on disposable/temporary email blacklists.","method":"GET","path":"/v1/email/check","pathParams":[],"queryParams":["email","checks"],"hasBody":false}, params)
    end

    # Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
    def get_certificates(params = {})
      @client.request({"operationId":"getCertificates","title":"SSL Certificates","description":"Query Certificate Transparency logs. Find all SSL certificates issued for a domain.","method":"GET","path":"/v1/certificates","pathParams":[],"queryParams":["domain","include_subdomains","include_expired","limit","cursor"],"hasBody":false}, params)
    end

    # Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.
    def get_domain_reputation(params = {})
      @client.request({"operationId":"getDomainReputation","title":"Domain Reputation","description":"Check domain reputation across DNS, TLS, blacklist, parking, web presence, and email signals with score confidence metadata.","method":"GET","path":"/v1/reputation","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.
    def get_email_auth(params = {})
      @client.request({"operationId":"getEmailAuth","title":"Email Authentication","description":"Check DMARC, SPF, DKIM, MTA-STS, TLS-RPT, and recursive SPF behavior for email security auditing.","method":"GET","path":"/v1/email-auth","pathParams":[],"queryParams":["domain","selectors"],"hasBody":false}, params)
    end

    # Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and mail security checks.
    def get_email_compliance(params = {})
      @client.request({"operationId":"getEmailCompliance","title":"Email Compliance","description":"Provider-oriented sender readiness report for Google/Gmail and Microsoft Outlook.com high-volume requirements, using SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, and mail security checks.","method":"GET","path":"/v1/email/compliance","pathParams":[],"queryParams":["domain","selectors","providers"],"hasBody":false}, params)
    end

    # Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.
    def get_ssl_audit(params = {})
      @client.request({"operationId":"getSslAudit","title":"SSL Audit","description":"Run a comprehensive live SSL/TLS audit for a domain, aggregating certificate, chain, revocation, HSTS, HTTP version, and TLS posture details.","method":"GET","path":"/v1/ssl/audit","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Analyze the certificate chain including issuer, validity, and trust chain verification.
    def get_ssl_chain(params = {})
      @client.request({"operationId":"getSslChain","title":"SSL Chain","description":"Analyze the certificate chain including issuer, validity, and trust chain verification.","method":"GET","path":"/v1/ssl/chain","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.
    def get_ssl_deep_scan(params = {})
      @client.request({"operationId":"getSslDeepScan","title":"SSL Deep Scan","description":"Run a premium cached deep SSL/TLS scan for a domain. Returns a fresh cached result immediately when available, or starts a long-running scan and returns a signed polling token.","method":"GET","path":"/v1/ssl/deep-scan","pathParams":[],"queryParams":["domain","refresh","profile"],"hasBody":false}, params)
    end

    # Check if an SSL certificate is expiring soon with configurable alert threshold.
    def get_ssl_expiring(params = {})
      @client.request({"operationId":"getSslExpiring","title":"SSL Expiry Check","description":"Check if an SSL certificate is expiring soon with configurable alert threshold.","method":"GET","path":"/v1/ssl/expiring","pathParams":[],"queryParams":["domain","days","threshold_days"],"hasBody":false}, params)
    end

    # Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.
    def get_ssl_grade(params = {})
      @client.request({"operationId":"getSslGrade","title":"SSL Grade","description":"Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring plus HSTS preload audit metadata.","method":"GET","path":"/v1/ssl/grade","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Return best-effort hostname evidence from public certificate and passive discovery sources. Coverage is incomplete, and results include provenance with optional DNS verification.
    def get_subdomains(params = {})
      @client.request({"operationId":"getSubdomains","title":"Subdomain Finder","description":"Return best-effort hostname evidence from public certificate and passive discovery sources. Coverage is incomplete, and results include provenance with optional DNS verification.","method":"GET","path":"/v1/subdomains","pathParams":[],"queryParams":["domain","sources","verify","include_wildcards","limit","prefer_cache"],"hasBody":false}, params)
    end

    # Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
    def get_typosquatting(params = {})
      @client.request({"operationId":"getTyposquatting","title":"Typosquatting Detection","description":"Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.","method":"GET","path":"/v1/typos","pathParams":[],"queryParams":["domain","check_registered","limit","include_tld_swap"],"hasBody":false}, params)
    end

    # Correlate exposed software versions with authoritative public advisories and exploitation-priority data, and report deterministic web security misconfigurations separately. Results preserve evidence and unknown coverage.
    def get_vulnerabilities(params = {})
      @client.request({"operationId":"getVulnerabilities","title":"Vulnerability Intelligence","description":"Correlate exposed software versions with authoritative public advisories and exploitation-priority data, and report deterministic web security misconfigurations separately. Results preserve evidence and unknown coverage.","method":"GET","path":"/v1/vulnerabilities","pathParams":[],"queryParams":["url","domain","mode"],"hasBody":false}, params)
    end

    # Validate, normalize, and enrich international phone numbers with maintained offline numbering-plan and public allocation data. Results include coverage, provenance, freshness, and limitations without paid or per-number third-party lookups, and never claim current carrier, reachability, subscriber identity, or individual-number assignment.
    def validate_phone_number(params = {})
      @client.request({"operationId":"validatePhoneNumber","title":"Phone Number Validation","description":"Validate, normalize, and enrich international phone numbers with maintained offline numbering-plan and public allocation data. Results include coverage, provenance, freshness, and limitations without paid or per-number third-party lookups, and never claim current carrier, reachability, subscriber identity, or individual-number assignment.","method":"POST","path":"/v1/phone/validate","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and makes no paid or per-number third-party lookup.
    def validate_phone_numbers_bulk(params = {})
      @client.request({"operationId":"validatePhoneNumbersBulk","title":"Bulk Phone Number Validation","description":"Validate and enrich up to 100 phone numbers in one privacy-first request. Preserves input order and duplicates, supports shared or per-item parsing, dialing-country, and language context, and makes no paid or per-number third-party lookup.","method":"POST","path":"/v1/phone/validate/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.
    def verify_email(params = {})
      @client.request({"operationId":"verifyEmail","title":"Email Verification","description":"Verify email deliverability with syntax validation, MX/null MX lookup, reserved/test-domain detection, provider typo suggestions, MX provider fingerprinting, SPF/DMARC/MTA-STS/TLS-RPT evidence, local-part/domain intelligence, toxic/do-not-mail signals, confidence scoring, and industry-style deliverability status. Mailbox-level SMTP probing is deprecated and is not charged or performed.","method":"GET","path":"/v1/email/verify","pathParams":[],"queryParams":["email","full"],"hasBody":false}, params)
    end

    # Verify multiple email addresses at once. Max 100 emails per request.
    def verify_email_bulk(params = {})
      @client.request({"operationId":"verifyEmailBulk","title":"Bulk Email Verification","description":"Verify multiple email addresses at once. Max 100 emails per request.","method":"POST","path":"/v1/email/verify/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end
  end

  class SocialService < Service
    # Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.
    def bulk_check_social_handles(params = {})
      @client.request({"operationId":"bulkCheckSocialHandles","title":"Bulk Social Handle Check","description":"Check up to 10 social handles or resource identifiers in one request at the normal 2-credit rate per valid item, with no bulk discount. Invalid items return per-item errors and are not billed.","method":"POST","path":"/v1/social/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.
    def check_social_handles(params = {})
      @client.request({"operationId":"checkSocialHandles","title":"Social Handle Checker","description":"Check username availability across social, developer, creator, and community platforms. Optionally resolve repositories, subreddits, Discord invites, Substack profiles, and federated accounts.","method":"GET","path":"/v1/social","pathParams":[],"queryParams":["handle","platforms","resources"],"hasBody":false}, params)
    end

    # Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.
    def get_social_info(params = {})
      @client.request({"operationId":"getSocialInfo","title":"Social Handle Reference","description":"Returns supported username platforms, resource types, parameters, and examples for the social intelligence endpoint.","method":"GET","path":"/v1/social/info","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end

  class UserService < Service
    # Get the active customer account credit balance without exposing transaction history.
    def get_credit_balance(params = {})
      @client.request({"operationId":"getCreditBalance","title":"Get Credit Balance","description":"Get the active customer account credit balance without exposing transaction history.","method":"GET","path":"/v1/credits","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end
end
