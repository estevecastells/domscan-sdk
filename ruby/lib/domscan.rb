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
    attr_reader :availability, :dns, :domain, :intelligence, :meta, :osint, :pricing, :recipes, :security, :social

    def initialize(api_key: ENV["DOMSCAN_API_KEY"], base_url: "https://domscan.net", timeout: 10, headers: {}, user_agent: "domscan-ruby/0.1.0")
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
      @client.request({"title":"Bulk Domain Check","description":"Check availability of multiple complete domain names at once.","method":"POST","path":"/v1/status/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.
    def check_domain_availability(params = {})
      @client.request({"title":"Domain Availability","description":"Check if a domain name is available for registration across multiple TLDs. Uses RDAP for authoritative results.","method":"GET","path":"/v1/status","pathParams":[],"queryParams":["name","tlds","prefer_cache"],"hasBody":false}, params)
    end

    # Get information about which TLDs are supported and their RDAP server status.
    def get_coverage(params = {})
      @client.request({"title":"RDAP Coverage","description":"Get information about which TLDs are supported and their RDAP server status.","method":"GET","path":"/v1/coverage","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end

  class DnsService < Service
    # Build a DMARC record with policy, reporting, and alignment options.
    def build_dmarc(params = {})
      @client.request({"title":"DMARC Builder","description":"Build a DMARC record with policy, reporting, and alignment options.","method":"POST","path":"/v1/tools/dmarc/build","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Build an SPF record from configuration options with validation and recommendations.
    def build_spf(params = {})
      @client.request({"title":"SPF Builder","description":"Build an SPF record from configuration options with validation and recommendations.","method":"POST","path":"/v1/tools/spf/build","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check a specific DKIM selector for a domain and validate the public key.
    def check_dkim(params = {})
      @client.request({"title":"DKIM Check","description":"Check a specific DKIM selector for a domain and validate the public key.","method":"GET","path":"/v1/tools/dkim/check","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Discover DKIM selectors for a domain by checking common selector names.
    def discover_dkim(params = {})
      @client.request({"title":"DKIM Discovery","description":"Discover DKIM selectors for a domain by checking common selector names.","method":"GET","path":"/v1/tools/dkim/discover","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.
    def flatten_spf(params = {})
      @client.request({"title":"SPF Flattener","description":"Flatten SPF record by resolving all includes into IP addresses to reduce DNS lookups.","method":"POST","path":"/v1/tools/spf/flatten","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Get all DNS record types for a domain in a single call.
    def get_all_dns_records(params = {})
      @client.request({"title":"DNS All Records","description":"Get all DNS record types for a domain in a single call.","method":"GET","path":"/v1/dns/all","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Compare DNS records between two dates to see what changed.
    def get_dns_diff(params = {})
      @client.request({"title":"DNS Diff","description":"Compare DNS records between two dates to see what changed.","method":"GET","path":"/v1/dns/diff","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Track DNS record changes over time. Data accumulates from API lookups.
    def get_dns_history(params = {})
      @client.request({"title":"DNS History","description":"Track DNS record changes over time. Data accumulates from API lookups.","method":"GET","path":"/v1/dns/history","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Check DNS propagation across multiple global DNS servers.
    def get_dns_propagation(params = {})
      @client.request({"title":"DNS Propagation","description":"Check DNS propagation across multiple global DNS servers.","method":"GET","path":"/v1/dns/propagation","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.
    def get_dns_records(params = {})
      @client.request({"title":"DNS Lookup","description":"Query A, AAAA, MX, NS, TXT, CAA and other DNS records programmatically.","method":"GET","path":"/v1/dns","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.
    def get_dns_security(params = {})
      @client.request({"title":"DNS Security","description":"Analyze DNS security configuration including SPF, DKIM, DMARC, DNSSEC, and CAA records.","method":"GET","path":"/v1/dns/security","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get list of global DNS servers used for propagation checks.
    def get_dns_servers(params = {})
      @client.request({"title":"DNS Servers","description":"Get list of global DNS servers used for propagation checks.","method":"GET","path":"/v1/dns/servers","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Validate a DMARC record for syntax errors and configuration issues.
    def validate_dmarc(params = {})
      @client.request({"title":"DMARC Validator","description":"Validate a DMARC record for syntax errors and configuration issues.","method":"POST","path":"/v1/tools/dmarc/validate","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Validate an SPF record for syntax errors, DNS lookup limits, and best practices.
    def validate_spf(params = {})
      @client.request({"title":"SPF Validator","description":"Validate an SPF record for syntax errors, DNS lookup limits, and best practices.","method":"POST","path":"/v1/tools/spf/validate","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end
  end

  class DomainService < Service
    # Get value estimates for multiple domains at once.
    def bulk_domain_value(params = {})
      @client.request({"title":"Bulk Domain Valuation","description":"Get value estimates for multiple domains at once.","method":"POST","path":"/v1/value/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Compare two domains side-by-side across multiple metrics and attributes.
    def compare_domains(params = {})
      @client.request({"title":"Domain Compare","description":"Compare two domains side-by-side across multiple metrics and attributes.","method":"GET","path":"/v1/compare","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.
    def get_domain_health(params = {})
      @client.request({"title":"Domain Health","description":"Comprehensive health checks: DNS, SSL, email deliverability, security headers, and more.","method":"GET","path":"/v1/health","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.
    def get_domain_overview(params = {})
      @client.request({"title":"Domain Overview","description":"Comprehensive domain intelligence in one call: DNS, WHOIS, health, and reputation data aggregated into a single response.","method":"GET","path":"/v1/overview","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.
    def get_domain_profile(params = {})
      @client.request({"title":"Domain Profile","description":"Get normalized RDAP registration data: registrar, dates, nameservers, DNSSEC status.","method":"GET","path":"/v1/profile","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Calculate an overall domain quality score based on multiple factors.
    def get_domain_score(params = {})
      @client.request({"title":"Domain Score","description":"Calculate an overall domain quality score based on multiple factors.","method":"GET","path":"/v1/score","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.
    def get_domain_value(params = {})
      @client.request({"title":"Domain Valuation","description":"Algorithmic domain value estimates based on length, TLD tier, dictionary words, and brandability.","method":"GET","path":"/v1/value","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Fast health check with essential metrics only.
    def get_quick_health(params = {})
      @client.request({"title":"Quick Health Check","description":"Fast health check with essential metrics only.","method":"GET","path":"/v1/health/quick","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get detailed information about a specific TLD.
    def get_tld_detail(params = {})
      @client.request({"title":"TLD Detail","description":"Get detailed information about a specific TLD.","method":"GET","path":"/v1/tlds/:tld","pathParams":["tld"],"queryParams":[],"hasBody":false}, params)
    end

    # Get list of all supported TLDs with metadata.
    def get_tlds(params = {})
      @client.request({"title":"TLD List","description":"Get list of all supported TLDs with metadata.","method":"GET","path":"/v1/tlds","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.
    def suggest_domains(params = {})
      @client.request({"title":"Domain Suggestions","description":"AI-powered domain name generator. Get brandable, short, and keyword-rich suggestions based on your keywords.","method":"GET","path":"/v1/suggest","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end

  class IntelligenceService < Service
    # Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.
    def categorize_website(params = {})
      @client.request({"title":"Website Categorization","description":"Classify websites into 350+ IAB-inspired categories using multi-signal analysis: keywords, schema.org, Open Graph, TLD heuristics, URL patterns, and HTML structure.","method":"GET","path":"/v1/categorize","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Categorize up to 10 websites in parallel with caching.
    def categorize_website_bulk(params = {})
      @client.request({"title":"Bulk Website Categorization","description":"Categorize up to 10 websites in parallel with caching.","method":"POST","path":"/v1/categorize/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Extract company information from a domain. Get name, industry, and contact details.
    def get_company(params = {})
      @client.request({"title":"Company Lookup","description":"Extract company information from a domain. Get name, industry, and contact details.","method":"GET","path":"/v1/company","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Compare domains for similarity. Detect typosquatting with multiple algorithms.
    def get_domain_similarity(params = {})
      @client.request({"title":"Domain Similarity","description":"Compare domains for similarity. Detect typosquatting with multiple algorithms.","method":"GET","path":"/v1/similarity","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.
    def get_hosting(params = {})
      @client.request({"title":"Hosting Detection","description":"Detect hosting provider, CDN, WAF, DNS provider, and email infrastructure.","method":"GET","path":"/v1/hosting","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.
    def get_parking_detection(params = {})
      @client.request({"title":"Parking Detection","description":"Detect if a domain is parked or listed for sale on aftermarket platforms. Identifies parking providers via DNS, HTTP redirect, and HTML content analysis.","method":"GET","path":"/v1/parking","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.
    def get_redirects(params = {})
      @client.request({"title":"Redirect Chain","description":"Follow URL redirect chains. Detect HTTPS upgrades, domain changes, and landing pages.","method":"GET","path":"/v1/redirects","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Detect website technologies: CDN, CMS, frameworks, analytics, and more.
    def get_tech_stack(params = {})
      @client.request({"title":"Tech Stack Detection","description":"Detect website technologies: CDN, CMS, frameworks, analytics, and more.","method":"GET","path":"/v1/tech","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end

  class MetaService < Service
    # Get credit costs per endpoint and API pricing information.
    def get_pricing_info(params = {})
      @client.request({"title":"API Pricing Info","description":"Get credit costs per endpoint and API pricing information.","method":"GET","path":"/v1/pricing","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end

  class OsintService < Service
    # Get WHOIS data for multiple domains at once.
    def bulk_whois(params = {})
      @client.request({"title":"Bulk WHOIS Lookup","description":"Get WHOIS data for multiple domains at once.","method":"POST","path":"/v1/whois/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Find domains that use a specific nameserver.
    def get_dns_reverse_ns(params = {})
      @client.request({"title":"Reverse NS Lookup","description":"Find domains that use a specific nameserver.","method":"GET","path":"/v1/dns/reverse/ns","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Map domain relationships through shared infrastructure and registrant data.
    def get_domain_graph(params = {})
      @client.request({"title":"Domain Graph","description":"Map domain relationships through shared infrastructure and registrant data.","method":"GET","path":"/v1/graph","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.
    def get_domain_lifecycle(params = {})
      @client.request({"title":"Domain Lifecycle","description":"Get domain lifecycle information including registration date, expiration date, age, and lifecycle phase. Returns Fastly-style status flags.","method":"GET","path":"/v1/lifecycle","pathParams":[],"queryParams":["domain"],"hasBody":false}, params)
    end

    # Get IP addresses with geolocation, ASN, and hosting provider information.
    def get_ip_info(params = {})
      @client.request({"title":"IP Geolocation","description":"Get IP addresses with geolocation, ASN, and hosting provider information.","method":"GET","path":"/v1/ip","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Lookup MAC address vendor information. Identify network device manufacturers.
    def get_mac_info(params = {})
      @client.request({"title":"MAC Address Lookup","description":"Lookup MAC address vendor information. Identify network device manufacturers.","method":"GET","path":"/v1/mac","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Find all domains hosted on a specific IP address.
    def get_reverse_ip(params = {})
      @client.request({"title":"Reverse IP Lookup","description":"Find all domains hosted on a specific IP address.","method":"GET","path":"/v1/reverse/ip","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Find all domains using a specific mail server for email infrastructure mapping.
    def get_reverse_mx(params = {})
      @client.request({"title":"Reverse MX Lookup","description":"Find all domains using a specific mail server for email infrastructure mapping.","method":"GET","path":"/v1/reverse/mx","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get structured WHOIS/RDAP registration data for a domain.
    def get_whois(params = {})
      @client.request({"title":"WHOIS Lookup","description":"Get structured WHOIS/RDAP registration data for a domain.","method":"GET","path":"/v1/whois","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.
    def get_whois_history(params = {})
      @client.request({"title":"WHOIS History","description":"Track WHOIS record changes over time. Shows registrar transfers, expiry extensions, nameserver changes, and privacy toggles. Data accumulates from API lookups.","method":"GET","path":"/v1/whois/history","pathParams":[],"queryParams":["domain","limit"],"hasBody":false}, params)
    end
  end

  class PricingService < Service
    # Get pricing for multiple domains at once.
    def bulk_pricing(params = {})
      @client.request({"title":"Bulk Pricing","description":"Get pricing for multiple domains at once.","method":"POST","path":"/v1/prices/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Compare domain prices across multiple registrars.
    def compare_prices(params = {})
      @client.request({"title":"Compare Registrar Prices","description":"Compare domain prices across multiple registrars.","method":"GET","path":"/v1/prices/compare","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get domain registration and renewal prices across registrars.
    def get_prices(params = {})
      @client.request({"title":"Domain Pricing","description":"Get domain registration and renewal prices across registrars.","method":"GET","path":"/v1/prices","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get list of supported registrars with pricing data.
    def get_registrars(params = {})
      @client.request({"title":"List Registrars","description":"Get list of supported registrars with pricing data.","method":"GET","path":"/v1/prices/registrars","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get pricing for a specific TLD across registrars.
    def get_tld_pricing(params = {})
      @client.request({"title":"TLD Pricing","description":"Get pricing for a specific TLD across registrars.","method":"GET","path":"/v1/prices/tld/:tld","pathParams":["tld"],"queryParams":[],"hasBody":false}, params)
    end
  end

  class RecipesService < Service
    # Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.
    def recipe_brand_launch(params = {})
      @client.request({"title":"Brand Launch Readiness","description":"Pre-launch checklist for brand domains including DNS, SSL, email auth, and social availability. Saves 6 credits.","method":"GET","path":"/v1/recipes/brand-launch","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.
    def recipe_competitor_intel(params = {})
      @client.request({"title":"Competitor Intelligence","description":"Competitor domain infrastructure analysis including tech stack and DNS configuration. Saves 8 credits.","method":"GET","path":"/v1/recipes/competitor-intel","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Brand protection through strategic domain acquisition recommendations. Saves 10 credits.
    def recipe_defensive_registration(params = {})
      @client.request({"title":"Defensive Registration","description":"Brand protection through strategic domain acquisition recommendations. Saves 10 credits.","method":"GET","path":"/v1/recipes/defensive-registration","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.
    def recipe_dns_migration(params = {})
      @client.request({"title":"DNS Migration Check","description":"Pre-migration checklist and current DNS configuration snapshot. Saves 6 credits.","method":"GET","path":"/v1/recipes/dns-migration","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # AI-powered domain discovery with filtering and availability checking. Saves 15 credits.
    def recipe_domain_finder(params = {})
      @client.request({"title":"Domain Finder","description":"AI-powered domain discovery with filtering and availability checking. Saves 15 credits.","method":"GET","path":"/v1/recipes/domain-finder","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.
    def recipe_due_diligence(params = {})
      @client.request({"title":"Domain Due Diligence","description":"Complete domain acquisition analysis with registration, valuation, health, and brand protection insights. Saves 8 credits vs individual calls.","method":"GET","path":"/v1/recipes/due-diligence","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.
    def recipe_email_deliverability(params = {})
      @client.request({"title":"Email Deliverability Audit","description":"Complete email authentication and deliverability analysis (SPF, DKIM, DMARC). Saves 7 credits.","method":"GET","path":"/v1/recipes/email-deliverability","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Complete infrastructure mapping and attack surface analysis. Saves 13 credits.
    def recipe_infrastructure_discovery(params = {})
      @client.request({"title":"Infrastructure Discovery","description":"Complete infrastructure mapping and attack surface analysis. Saves 13 credits.","method":"GET","path":"/v1/recipes/infrastructure-discovery","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Evidence collection and analysis for suspected phishing domains. Saves 12 credits.
    def recipe_phishing_investigation(params = {})
      @client.request({"title":"Phishing Investigation","description":"Evidence collection and analysis for suspected phishing domains. Saves 12 credits.","method":"GET","path":"/v1/recipes/phishing-investigation","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.
    def recipe_portfolio_audit(params = {})
      @client.request({"title":"Portfolio Audit","description":"Audit entire domain portfolio for health, valuation, and optimization opportunities. Saves up to 280 credits.","method":"GET","path":"/v1/recipes/portfolio-audit","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Audit domain portfolio via POST for larger domain lists.
    def recipe_portfolio_audit_post(params = {})
      @client.request({"title":"Portfolio Audit (POST)","description":"Audit domain portfolio via POST for larger domain lists.","method":"POST","path":"/v1/recipes/portfolio-audit","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.
    def recipe_threat_assessment(params = {})
      @client.request({"title":"Threat Assessment","description":"Comprehensive typosquatting and brand threat analysis for security teams. Saves 25 credits.","method":"GET","path":"/v1/recipes/threat-assessment","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end

  class SecurityService < Service
    # Check multiple email domains against blacklists at once.
    def bulk_email_check(params = {})
      @client.request({"title":"Bulk Email Check","description":"Check multiple email domains against blacklists at once.","method":"POST","path":"/v1/email/check/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end

    # Check if an email domain is on disposable/temporary email blacklists.
    def check_email_blacklist(params = {})
      @client.request({"title":"Email Blacklist Check","description":"Check if an email domain is on disposable/temporary email blacklists.","method":"GET","path":"/v1/email/check","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Download the full email blacklist database in various formats.
    def download_email_blacklist(params = {})
      @client.request({"title":"Download Email Blacklist","description":"Download the full email blacklist database in various formats.","method":"GET","path":"/v1/email/blacklist/download","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Query Certificate Transparency logs. Find all SSL certificates issued for a domain.
    def get_certificates(params = {})
      @client.request({"title":"SSL Certificates","description":"Query Certificate Transparency logs. Find all SSL certificates issued for a domain.","method":"GET","path":"/v1/certificates","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Check domain reputation across security feeds, blacklists, and threat intelligence.
    def get_domain_reputation(params = {})
      @client.request({"title":"Domain Reputation","description":"Check domain reputation across security feeds, blacklists, and threat intelligence.","method":"GET","path":"/v1/reputation","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Check DMARC, SPF, and DKIM configurations for email security auditing.
    def get_email_auth(params = {})
      @client.request({"title":"Email Authentication","description":"Check DMARC, SPF, and DKIM configurations for email security auditing.","method":"GET","path":"/v1/email-auth","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Get information about the email blacklist database.
    def get_email_blacklist_info(params = {})
      @client.request({"title":"Email Blacklist Info","description":"Get information about the email blacklist database.","method":"GET","path":"/v1/email/blacklist","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Analyze the certificate chain including issuer, validity, and trust chain verification.
    def get_ssl_chain(params = {})
      @client.request({"title":"SSL Chain","description":"Analyze the certificate chain including issuer, validity, and trust chain verification.","method":"GET","path":"/v1/ssl/chain","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Check if an SSL certificate is expiring soon with configurable alert threshold.
    def get_ssl_expiring(params = {})
      @client.request({"title":"SSL Expiry Check","description":"Check if an SSL certificate is expiring soon with configurable alert threshold.","method":"GET","path":"/v1/ssl/expiring","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.
    def get_ssl_grade(params = {})
      @client.request({"title":"SSL Grade","description":"Analyze SSL/TLS configuration and get a letter grade (A+ to F) with detailed scoring.","method":"GET","path":"/v1/ssl/grade","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Discover subdomains using Certificate Transparency and DNS enumeration.
    def get_subdomains(params = {})
      @client.request({"title":"Subdomain Finder","description":"Discover subdomains using Certificate Transparency and DNS enumeration.","method":"GET","path":"/v1/subdomains","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.
    def get_typosquatting(params = {})
      @client.request({"title":"Typosquatting Detection","description":"Detect typosquatting threats with analysis of common typos, homoglyphs, and brand impersonation risks.","method":"GET","path":"/v1/typos","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end

    # Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.
    def verify_email(params = {})
      @client.request({"title":"Email Verification","description":"Verify email deliverability with syntax validation, MX lookup, disposable detection, and optional SMTP mailbox verification. Basic check costs 1 credit; full SMTP check costs 5 credits.","method":"GET","path":"/v1/email/verify","pathParams":[],"queryParams":["email","full"],"hasBody":false}, params)
    end

    # Verify multiple email addresses at once. Max 100 emails per request.
    def verify_email_bulk(params = {})
      @client.request({"title":"Bulk Email Verification","description":"Verify multiple email addresses at once. Max 100 emails per request.","method":"POST","path":"/v1/email/verify/bulk","pathParams":[],"queryParams":[],"hasBody":true}, params)
    end
  end

  class SocialService < Service
    # Check username availability across social platforms like GitHub, Reddit, and more.
    def check_social_handles(params = {})
      @client.request({"title":"Social Handle Checker","description":"Check username availability across social platforms like GitHub, Reddit, and more.","method":"GET","path":"/v1/social","pathParams":[],"queryParams":[],"hasBody":false}, params)
    end
  end
end
