"""Generated from DomScan's OpenAPI contract. Do not edit manually."""

from typing import Any, Dict, List, Literal, Optional, Union, TypedDict
from typing_extensions import NotRequired, Required

class ErrorResponse(TypedDict):
  error: NotRequired[Dict[str, Any]]

PhoneCountryCode = str

PhoneLanguageCode = str

class PhoneValidationRequest(TypedDict):
  phone: Required[str]
  default_country: NotRequired[PhoneCountryCode]
  expected_country: NotRequired[PhoneCountryCode]
  dialing_from_country: NotRequired[PhoneCountryCode]
  language: NotRequired[PhoneLanguageCode]

class PhoneValidationBulkRequest(TypedDict):
  phones: Required[List[Union[str, PhoneValidationRequest]]]
  default_country: NotRequired[PhoneCountryCode]
  expected_country: NotRequired[PhoneCountryCode]
  dialing_from_country: NotRequired[PhoneCountryCode]
  language: NotRequired[PhoneLanguageCode]

class PhoneIntelligenceLocation(TypedDict):
  label: Required[Optional[str]]
  country_name: Required[Optional[str]]
  country: Required[Optional[str]]
  language: Required[str]
  granularity: Required[Literal["numbering_plan_area", "country"]]
  current_physical_location: Required[Literal[False]]

class PhoneIntelligenceCoverage(TypedDict):
  country: Required[Optional[str]]
  level: Required[Literal["global_numbering_metadata", "official_snapshot", "official_allocation_match"]]
  global_numbering_metadata: Required[bool]
  official_snapshot_available: Required[bool]
  official_allocation_match: Required[bool]
  official_source_ids: Required[List[str]]
  matching_source_ids: Required[List[str]]
  current_carrier_lookup: Required[Literal[False]]

class PhoneIntelligenceTimeZones(TypedDict):
  values: Required[List[str]]
  current_location: Required[Literal[False]]
  inference: Required[Literal["number_prefix"]]

class PhoneIntelligenceCarrier(TypedDict):
  name: Required[Optional[str]]
  source_id: Required[Optional[str]]
  evidence: Required[Literal["offline_prefix_metadata", "official_allocation_record", "unavailable"]]
  current_carrier: Required[Literal[False]]
  portability_may_change_carrier: Required[bool]

class PhoneIntelligencePortability(TypedDict):
  region_supported: Required[bool]
  current_port_checked: Required[Literal[False]]

class PhoneIntelligenceDialing(TypedDict):
  from_country: Required[Optional[str]]
  international: Required[Optional[str]]
  mobile: Required[Optional[str]]
  internationally_diallable: Required[bool]

class PhoneIntelligenceNumberDetails(TypedDict):
  geographical: Required[bool]
  geographical_area_code: Required[Optional[str]]
  geographical_area_code_length: Required[int]
  national_destination_code: Required[Optional[str]]
  national_destination_code_length: Required[int]
  subscriber_number_length: Required[int]
  mobile_token: Required[Optional[str]]

class PhoneIntelligenceServiceSignals(TypedDict):
  number_type: Required[Literal["fixed_line", "mobile", "fixed_line_or_mobile", "toll_free", "premium_rate", "shared_cost", "voip", "personal_number", "pager", "uan", "voicemail", "unknown"]]
  geographical: Required[bool]
  toll_free: Required[bool]
  premium_rate: Required[bool]
  shared_cost: Required[bool]
  voip: Required[bool]
  personal_number: Required[bool]
  likely_sms_capable: Required[Optional[bool]]

class PhoneIntelligenceShortNumber(TypedDict):
  region: Required[str]
  possible: Required[bool]
  valid: Required[bool]
  emergency: Required[bool]
  connects_to_emergency: Required[bool]
  sms_service: Required[bool]
  carrier_specific: Required[bool]
  expected_cost: Required[Literal["toll_free", "standard_rate", "premium_rate", "unknown"]]

class PhoneRegulatorAllocation(TypedDict):
  authority: Required[str]
  country: Required[str]
  matched_prefix: Required[str]
  matched_range_end: Required[Optional[str]]
  match_kind: Required[Literal["prefix", "range"]]
  category: Required[str]
  status: Required[str]
  original_assignee: Required[Optional[str]]
  operator_code: Required[Optional[str]]
  region: Required[Optional[str]]
  service_description: Required[Optional[str]]
  assigned_on: Required[Optional[str]]
  effective_on: Required[Optional[str]]
  expires_on: Required[Optional[str]]
  current_operator: Required[Literal[False]]
  portability_included: Required[Literal[False]]
  individual_number_assignment_checked: Required[Literal[False]]
  source_id: Required[str]
  source_file: Required[Optional[str]]
  details: Required[Dict[str, Any]]

class PhoneIntelligenceSource(TypedDict):
  id: Required[str]
  name: Required[str]
  type: Required[Literal["offline_metadata", "official_regulator_snapshot"]]
  version: NotRequired[Optional[str]]
  updated_at: NotRequired[Optional[str]]
  retrieved_at: NotRequired[Optional[str]]
  age_days: NotRequired[Optional[int]]
  record_count: NotRequired[Optional[int]]
  license: NotRequired[Optional[str]]
  license_url: NotRequired[Optional[str]]
  url: Required[str]
  attribution: NotRequired[Optional[str]]

class PhoneIntelligenceRelay(TypedDict):
  configured: Required[bool]
  used: Required[bool]
  persisted: Required[Literal[False]]

class PhoneIntelligence(TypedDict):
  status: Required[Literal["available", "partial", "unavailable", "not_applicable"]]
  kind: Required[Literal["phone_number", "short_code"]]
  reason: Required[Optional[str]]
  coverage: Required[Union[PhoneIntelligenceCoverage]]
  location: Required[Union[PhoneIntelligenceLocation]]
  possible_time_zones: Required[Union[PhoneIntelligenceTimeZones]]
  original_prefix_carrier: Required[Union[PhoneIntelligenceCarrier]]
  portability: Required[Union[PhoneIntelligencePortability]]
  dialing: Required[Union[PhoneIntelligenceDialing]]
  number_details: Required[Union[PhoneIntelligenceNumberDetails]]
  service_signals: Required[Union[PhoneIntelligenceServiceSignals]]
  short_number: Required[Union[PhoneIntelligenceShortNumber]]
  regulator_allocations: Required[List[PhoneRegulatorAllocation]]
  sources: Required[List[PhoneIntelligenceSource]]
  warnings: Required[List[str]]
  relay: Required[PhoneIntelligenceRelay]

class PhoneValidationResult(TypedDict):
  input: Required[str]
  normalized_input: Required[str]
  kind: Required[Literal["phone_number", "unparseable"]]
  valid: Required[bool]
  possible: Required[bool]
  status: Required[Literal["valid", "possible", "invalid"]]
  recommendation: Required[Literal["accept", "review", "reject"]]
  validation_level: Required[Literal["numbering_plan"]]
  reason: Required[Literal["DEFAULT_COUNTRY_REQUIRED", "INPUT_TOO_LONG", "NOT_A_NUMBER", "INVALID_COUNTRY_CALLING_CODE", "TOO_SHORT", "TOO_LONG", "INVALID_LENGTH", "INVALID_PATTERN"]]
  warnings: Required[List[Literal["COUNTRY_MISMATCH", "VANITY_NUMBER_CONVERTED"]]]
  number: Required[Optional[Dict[str, Any]]]
  live_checks: Required[Dict[str, Any]]
  privacy: Required[Dict[str, Any]]
  intelligence: Required[PhoneIntelligence]
  limitations: Required[List[str]]
  metadata: Required[Dict[str, Any]]

PhoneValidationResponse = Union[PhoneValidationResult, Dict[str, Any]]

class PhoneValidationBulkResponse(TypedDict):
  total: Required[int]
  valid_count: Required[int]
  possible_only_count: Required[int]
  invalid_count: Required[int]
  validation_level: Required[Literal["numbering_plan"]]
  results: Required[List[PhoneValidationResult]]
  credits_used: Required[int]

class BulkLookupResponse(TypedDict):
  results: Required[List[Union[Dict[str, Any], Dict[str, Any]]]]
  meta: Required[Dict[str, Any]]

class Meta(TypedDict):
  served_by: NotRequired[str]
  duration_ms: NotRequired[int]

class RecipeResponse(TypedDict):
  success: NotRequired[bool]
  data: NotRequired[Any]
  meta: NotRequired[Dict[str, Any]]
  errors: NotRequired[List[Dict[str, Any]]]

class StatusResponse(TypedDict):
  name: NotRequired[str]
  results: NotRequired[List[AvailabilityResult]]
  confidence_summary: NotRequired[AvailabilityConfidenceSummary]
  meta: NotRequired[Dict[str, Any]]

class BulkStatusResponse(TypedDict):
  results: NotRequired[List[AvailabilityResult]]
  confidence_summary: NotRequired[AvailabilityConfidenceSummary]
  meta: NotRequired[Dict[str, Any]]

class AvailabilityConfidenceSummary(TypedDict):
  scope: NotRequired[Literal["precise", "estimate"]]
  requested_count: NotRequired[int]
  result_count: NotRequired[int]
  invalid_count: NotRequired[int]
  available_count: NotRequired[int]
  registered_count: NotRequired[int]
  authoritative_count: NotRequired[int]
  heuristic_count: NotRequired[int]
  cached_count: NotRequired[int]
  error_count: NotRequired[int]
  ambiguous_count: NotRequired[int]
  source_counts: NotRequired[Dict[str, int]]
  primary_source: NotRequired[Optional[str]]
  cache_status: NotRequired[Literal["hit", "miss", "mixed", "none"]]
  rdap_calls: NotRequired[int]
  refreshes: NotRequired[int]
  cache_preference_misses: NotRequired[int]
  fallback_chain: NotRequired[List[str]]
  confidence_level: NotRequired[Literal["high", "medium", "low"]]
  determinacy_rate: NotRequired[float]
  ambiguity_reason: NotRequired[Literal["errors_present", "heuristic_dns_fallback", "unknown_status"]]

class AvailabilityResult(TypedDict):
  domain: NotRequired[str]
  tld: NotRequired[str]
  available: NotRequired[Optional[bool]]
  source: NotRequired[Literal["rdap", "cache", "dns", "whois"]]
  confidence: NotRequired[Literal["authoritative", "heuristic"]]
  checked_at: NotRequired[str]
  latency_ms: NotRequired[int]
  error: NotRequired[str]

class SuggestResponse(TypedDict):
  suggestions: NotRequired[List[Dict[str, Any]]]
  keywords: NotRequired[List[str]]
  tlds: NotRequired[List[str]]
  styles: NotRequired[List[str]]
  industry: NotRequired[Literal["tech", "finance", "health", "ecommerce", "education", "media", "saas", "crypto", "ai", "gaming"]]
  language: NotRequired[str]
  generated_count: NotRequired[int]
  available_count: NotRequired[Optional[int]]
  generation_summary: NotRequired[SuggestGenerationSummary]
  meta: NotRequired[Dict[str, Any]]

class SuggestGenerationSummary(TypedDict):
  requested_limit: NotRequired[int]
  candidate_count: NotRequired[int]
  returned_count: NotRequired[int]
  availability_checked: NotRequired[bool]
  availability_check_count: NotRequired[int]
  available_count: NotRequired[Optional[int]]
  tld_count: NotRequired[int]
  language: NotRequired[str]
  method_counts: NotRequired[Dict[str, int]]
  style_counts: NotRequired[Dict[str, int]]
  top_method: NotRequired[Optional[str]]
  average_score: NotRequired[Optional[int]]

class LifecycleResponse(TypedDict):
  domain: NotRequired[str]
  tld: NotRequired[str]
  registered: NotRequired[str]
  expires: NotRequired[str]
  updated: NotRequired[str]
  age_days: NotRequired[int]
  expires_in_days: NotRequired[int]
  phase: NotRequired[Literal["available", "active", "expiring", "deleting", "reserved", "unknown"]]
  status_flags: NotRequired[List[str]]
  status: NotRequired[str]
  events: NotRequired[List[Dict[str, Any]]]

class HealthResponse(TypedDict):
  domain: NotRequired[str]
  health_score: NotRequired[int]
  grade: NotRequired[Literal["A", "B", "C", "D", "F"]]
  checks: NotRequired[Dict[str, Any]]
  enriched: NotRequired[Dict[str, Any]]
  warnings: NotRequired[List[str]]
  recommendations: NotRequired[List[str]]
  component_summary: NotRequired[HealthComponentSummary]
  details: NotRequired[Any]
  health_checks: NotRequired[List[Dict[str, Any]]]
  checked_at: NotRequired[str]
  meta: NotRequired[Dict[str, Any]]

class HealthComponentSummary(TypedDict):
  score: NotRequired[int]
  grade: NotRequired[Literal["A", "B", "C", "D", "F"]]
  check_count: NotRequired[int]
  passed_count: NotRequired[int]
  failed_count: NotRequired[int]
  warning_count: NotRequired[int]
  recommendation_count: NotRequired[int]
  confidence: NotRequired[Literal["high", "medium", "low"]]
  dns_ok: NotRequired[bool]
  https_ok: NotRequired[bool]
  email_ok: NotRequired[bool]
  blacklist_status: NotRequired[Literal["clean", "listed", "unknown"]]
  dnssec_enabled: NotRequired[bool]
  enriched_section_count: NotRequired[int]
  enriched_sections: NotRequired[List[str]]

class QuickHealthResponse(TypedDict):
  domain: NotRequired[str]
  dns_ok: NotRequired[Optional[bool]]
  https_ok: NotRequired[Optional[bool]]
  dns_complete: NotRequired[bool]
  checked_at: NotRequired[str]
  confidence: NotRequired[QuickHealthConfidence]
  meta: NotRequired[Dict[str, Any]]

class QuickHealthConfidence(TypedDict):
  checks_run: NotRequired[List[Literal["dns", "https"]]]
  passed_count: NotRequired[int]
  failed_count: NotRequired[int]
  unknown_count: NotRequired[int]
  confidence: NotRequired[Literal["high", "medium", "low"]]
  dns_ok: NotRequired[Optional[bool]]
  https_ok: NotRequired[Optional[bool]]

class BulkHealthResponse(TypedDict):
  results: NotRequired[List[Dict[str, Any]]]
  meta: NotRequired[Dict[str, Any]]

class ValuationResponse(TypedDict):
  domain: NotRequired[str]
  label: NotRequired[str]
  tld: NotRequired[str]
  estimate: NotRequired[Dict[str, Any]]
  factors: NotRequired[Dict[str, Any]]
  comparables: NotRequired[List[Dict[str, Any]]]
  confidence: NotRequired[float]
  valuation_summary: NotRequired[ValuationSummary]
  analysis: NotRequired[Dict[str, Any]]
  methodology: NotRequired[str]
  meta: NotRequired[Dict[str, Any]]

class ValuationSummary(TypedDict):
  model_scope: NotRequired[Literal["intrinsic_domain_value"]]
  confidence: NotRequired[float]
  confidence_label: NotRequired[Literal["low", "medium", "high"]]
  range_source: NotRequired[Literal["heuristic", "blended", "anchored"]]
  range_width: NotRequired[Literal["narrow", "moderate", "wide"]]
  comparable_count: NotRequired[int]
  primary_comparable_category: NotRequired[Optional[str]]
  primary_comparable_position: NotRequired[Literal["lower", "mid", "upper"]]
  positive_driver_count: NotRequired[int]
  negative_driver_count: NotRequired[int]
  liquidity_band: NotRequired[Literal["low", "moderate", "high", "very_high"]]
  tld_tier: NotRequired[Literal["premium", "standard", "value", "cctld"]]
  renewal_price_awareness: NotRequired[Dict[str, Any]]
  risk_flags: NotRequired[List[str]]

class TyposResponse(TypedDict):
  domain: NotRequired[str]
  name: NotRequired[str]
  tld: NotRequired[str]
  permutations_generated: NotRequired[int]
  permutations_checked: NotRequired[int]
  registered_typos: NotRequired[List[TypoPermutation]]
  available_typos: NotRequired[int]
  unknown_typos: NotRequired[int]
  risk_summary: NotRequired[Dict[str, Any]]
  threat_level: NotRequired[Literal["none", "low", "medium", "high", "critical"]]
  family_summary: NotRequired[TypoFamilySummary]
  checked_at: NotRequired[str]

class TypoPermutation(TypedDict):
  domain: NotRequired[str]
  type: NotRequired[str]
  risk: NotRequired[Literal["critical", "high", "medium", "low"]]
  registered: NotRequired[bool]
  checked_at: NotRequired[str]

class TypoFamilySummary(TypedDict):
  generated_by_type: NotRequired[Dict[str, int]]
  generated_by_risk: NotRequired[Dict[str, int]]
  registered_by_type: NotRequired[Dict[str, int]]
  registered_by_risk: NotRequired[Dict[str, int]]
  top_generated_family: NotRequired[Optional[str]]
  top_registered_family: NotRequired[Optional[str]]
  critical_or_high_generated_count: NotRequired[int]
  critical_or_high_registered_count: NotRequired[int]
  coverage_ratio: NotRequired[float]
  checked_count: NotRequired[int]
  available_count: NotRequired[int]
  unknown_count: NotRequired[int]
  omitted_count: NotRequired[int]
  include_tld_swap: NotRequired[bool]
  requested_limit: NotRequired[int]

class TyposThreatAnalysisResponse(TypedDict):
  domain: Required[str]
  name: NotRequired[str]
  tld: NotRequired[str]
  scan_summary: Required[Dict[str, Any]]
  threat_level: Required[Literal["none", "low", "medium", "high", "critical"]]
  protection_score: NotRequired[Any]
  threats: Required[List[TyposThreatDomain]]
  defensive_opportunities: NotRequired[List[TypoPermutation]]
  risk_breakdown: NotRequired[Any]
  recommendations: NotRequired[List[str]]
  checked_at: Required[str]
  scan_duration_ms: NotRequired[int]
  meta: NotRequired[Any]

class TyposThreatDomain(TypedDict):
  domain: Required[str]
  type: Required[str]
  risk: Required[Literal["critical", "high", "medium", "low"]]
  description: NotRequired[str]
  dns_active: Required[bool]
  has_website: Required[bool]
  has_mx: NotRequired[bool]
  infrastructure: NotRequired[Any]
  threat_indicators: Required[List[str]]
  threat_score: Required[int]

class BrandProtectionReportResponse(TypedDict):
  domain: Required[str]
  generated_at: Required[str]
  executive_summary: Required[Dict[str, Any]]
  threat_analysis: Required[TyposThreatAnalysisResponse]
  defensive_registration_priority: NotRequired[Any]
  monitoring_recommendations: NotRequired[List[str]]
  estimated_risk_exposure: Required[Literal["minimal", "low", "moderate", "high", "severe"]]
  meta: NotRequired[Any]

class QuickTyposResponse(TypedDict):
  domain: Required[str]
  registered_typos: Required[List[Dict[str, Any]]]
  count: Required[int]
  threat_level: Required[Literal["none", "low", "medium", "high", "critical"]]
  coverage: NotRequired[Dict[str, Any]]
  checked_at: Required[str]
  scan_duration_ms: NotRequired[int]
  meta: NotRequired[Any]

class PermutationsResponse(TypedDict):
  domain: NotRequired[str]
  name: NotRequired[str]
  tld: NotRequired[str]
  permutations_count: NotRequired[int]
  permutations: NotRequired[List[TypoPermutation]]
  by_type: NotRequired[Any]
  family_summary: NotRequired[TypoFamilySummary]
  meta: NotRequired[Dict[str, Any]]

class ProtectionScoreResponse(TypedDict):
  domain: NotRequired[str]
  name: NotRequired[str]
  tld: NotRequired[str]
  protection: NotRequired[Dict[str, Any]]
  protection_gap_summary: NotRequired[ProtectionGapSummary]
  registered_typos_checked: NotRequired[int]
  availability_coverage: NotRequired[Dict[str, Any]]
  checked_at: NotRequired[str]

class ProtectionGapSummary(TypedDict):
  tld_tier: NotRequired[Literal["high_value", "medium_value", "standard"]]
  priority_families: NotRequired[List[Dict[str, Any]]]
  critical_or_high_generated_count: NotRequired[int]
  vulnerability_count: NotRequired[int]
  defensive_tlds: NotRequired[List[str]]
  recommendation_focus: NotRequired[str]

class DnsResponse(TypedDict):
  domain: NotRequired[str]
  record_type: NotRequired[str]
  records: NotRequired[List[DnsRecord]]
  status: NotRequired[Literal["success", "nxdomain", "error"]]
  dnssec_validated: NotRequired[bool]
  query_time_ms: NotRequired[int]
  checked_at: NotRequired[str]
  warnings: NotRequired[List[DnsWarning]]

class BulkDnsResult(TypedDict):
  domain: NotRequired[str]
  record_type: NotRequired[str]
  records: NotRequired[List[DnsRecord]]
  status: NotRequired[Literal["success", "nxdomain", "error"]]
  dnssec_validated: NotRequired[bool]
  query_time_ms: NotRequired[int]
  checked_at: NotRequired[str]
  error: NotRequired[Dict[str, Any]]

class BulkDnsResponse(TypedDict):
  results: NotRequired[List[BulkDnsResult]]
  summary: NotRequired[Dict[str, Any]]
  meta: NotRequired[Dict[str, Any]]

class DnsRecord(TypedDict):
  type: NotRequired[str]
  name: NotRequired[str]
  data: NotRequired[str]
  ttl: NotRequired[int]
  priority: NotRequired[int]
  classification: NotRequired[Literal["spf", "dkim", "dmarc", "verification", "dnssec", "mta_sts", "tls_rpt", "other"]]

class DnsWarning(TypedDict):
  code: NotRequired[str]
  message: NotRequired[str]
  severity: NotRequired[Literal["info", "warning"]]

class DnsAllResponse(TypedDict):
  domain: NotRequired[str]
  records: NotRequired[Dict[str, List[DnsRecord]]]
  summary: NotRequired[Dict[str, Any]]
  warnings: NotRequired[List[DnsWarning]]
  wildcard: NotRequired[Dict[str, Any]]
  query_time_ms: NotRequired[int]
  checked_at: NotRequired[str]

class SpfLookupTree(TypedDict):
  root_domain: NotRequired[str]
  node_count: NotRequired[int]
  max_depth: NotRequired[int]
  cycles_detected: NotRequired[List[str]]
  nodes: NotRequired[List[Dict[str, Any]]]
  edges: NotRequired[List[Dict[str, Any]]]

class DnssecMismatchDetail(TypedDict):
  checked: NotRequired[bool]
  mismatch_detected: NotRequired[bool]
  reason: NotRequired[Optional[str]]
  ds_record_count: NotRequired[int]
  dnskey_record_count: NotRequired[int]
  rrsig_present: NotRequired[Optional[bool]]
  validation_status: NotRequired[Literal["secure", "insecure", "bogus", "indeterminate"]]
  resolver: NotRequired[Optional[str]]

class NameserverDriftSummary(TypedDict):
  checked: NotRequired[bool]
  drift_detected: NotRequired[Optional[bool]]
  public_nameservers: NotRequired[List[str]]
  authoritative_nameservers: NotRequired[List[str]]
  missing_from_authority: NotRequired[List[str]]
  extra_at_authority: NotRequired[List[str]]
  inconsistent_nameservers: NotRequired[List[str]]
  serial_mismatch_detected: NotRequired[Optional[bool]]

class DnsSecurityResponse(TypedDict):
  domain: NotRequired[str]
  security_score: NotRequired[int]
  security_grade: NotRequired[Literal["A+", "A", "B", "C", "D", "F"]]
  spf: NotRequired[Dict[str, Any]]
  dkim: NotRequired[Dict[str, Any]]
  dmarc: NotRequired[Dict[str, Any]]
  bimi: NotRequired[Dict[str, Any]]
  dnssec: NotRequired[Dict[str, Any]]
  caa: NotRequired[Dict[str, Any]]
  issuance_readiness: NotRequired[Dict[str, Any]]
  authoritative_consistency: NotRequired[Dict[str, Any]]
  delegation_health: NotRequired[Dict[str, Any]]
  dns_transport: NotRequired[Dict[str, Any]]
  nameserver_drift: NotRequired[NameserverDriftSummary]
  mta_sts: NotRequired[Dict[str, Any]]
  tls_rpt: NotRequired[Dict[str, Any]]
  resolver_latency: NotRequired[Dict[str, Any]]
  zone_transfer: NotRequired[Dict[str, Any]]
  blacklist: NotRequired[Dict[str, Any]]
  edge_summary: NotRequired[Dict[str, Any]]
  recommendations: NotRequired[List[str]]
  checked_at: NotRequired[str]
  check_duration_ms: NotRequired[int]

class DnsPropagationResponse(TypedDict):
  domain: NotRequired[str]
  record_type: NotRequired[Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]]
  expected_value: NotRequired[Optional[str]]
  measurement_scope: NotRequired[Literal["configured_recursive_resolvers"]]
  percentage_basis: NotRequired[Literal["expected_value_match", "resolver_convergence"]]
  propagation_percentage: NotRequired[float]
  fully_propagated: NotRequired[bool]
  consistent: NotRequired[bool]
  unique_values: NotRequired[List[str]]
  results: NotRequired[List[Dict[str, Any]]]
  checked_at: NotRequired[str]
  total_duration_ms: NotRequired[int]
  summary: NotRequired[Dict[str, Any]]
  propagation_summary: NotRequired[PropagationSummary]

class PropagationSummary(TypedDict):
  measurement_scope: NotRequired[Literal["configured_recursive_resolvers"]]
  percentage_basis: NotRequired[Literal["expected_value_match", "resolver_convergence"]]
  resolver_count: NotRequired[int]
  successful_count: NotRequired[int]
  failed_count: NotRequired[int]
  propagation_percentage: NotRequired[float]
  fully_propagated: NotRequired[bool]
  consistent: NotRequired[bool]
  unique_value_count: NotRequired[int]
  matching_expected_count: NotRequired[int]
  expected_value_present: NotRequired[Optional[bool]]
  countries_checked: NotRequired[int]
  providers_checked: NotRequired[int]
  locations_checked: NotRequired[int]
  slowest_resolver: NotRequired[Optional[str]]
  slowest_response_ms: NotRequired[Optional[int]]
  fastest_response_ms: NotRequired[Optional[int]]
  disagreement_count: NotRequired[int]
  confidence: NotRequired[Literal["high", "medium", "low"]]

class DnsServersResponse(TypedDict):
  measurement_scope: NotRequired[Literal["configured_recursive_resolvers"]]
  geographic_vantage: NotRequired[Literal[False]]
  servers: NotRequired[List[Dict[str, Any]]]
  total: NotRequired[int]

class WhoisContact(TypedDict):
  name: NotRequired[Optional[str]]
  organization: NotRequired[Optional[str]]
  email: NotRequired[Optional[str]]
  phone: NotRequired[Optional[str]]
  fax: NotRequired[Optional[str]]
  address: NotRequired[Dict[str, Any]]
  role: NotRequired[str]

class WhoisPrivacyInfo(TypedDict):
  is_private: NotRequired[bool]
  privacy_service: NotRequired[Optional[str]]
  detected_patterns: NotRequired[List[str]]

class WhoisResponse(TypedDict):
  domain: NotRequired[str]
  registered: NotRequired[Optional[bool]]
  available: NotRequired[Optional[bool]]
  registrar: NotRequired[Optional[str]]
  registrar_url: NotRequired[Optional[str]]
  registrar_iana_id: NotRequired[Optional[str]]
  created_date: NotRequired[Optional[str]]
  updated_date: NotRequired[Optional[str]]
  expiry_date: NotRequired[Optional[str]]
  domain_age_days: NotRequired[Optional[int]]
  domain_age_years: NotRequired[Optional[int]]
  is_newly_registered: NotRequired[bool]
  days_until_expiry: NotRequired[Optional[int]]
  transfer_locked: NotRequired[bool]
  nameservers: NotRequired[List[str]]
  status: NotRequired[List[str]]
  dnssec: NotRequired[bool]
  contacts: NotRequired[Dict[str, Any]]
  privacy: NotRequired[WhoisPrivacyInfo]
  raw_rdap_link: NotRequired[Optional[str]]
  raw_whois: NotRequired[Optional[str]]
  abuse_contact: NotRequired[Optional[Dict[str, Any]]]
  registry_domain_id: NotRequired[Optional[str]]
  registrar_whois_server: NotRequired[Optional[str]]
  traditional_contacts: NotRequired[Dict[str, Any]]
  nameserver_ips: NotRequired[List[Dict[str, Any]]]
  checked_at: NotRequired[str]
  query_time_ms: NotRequired[int]
  summary: NotRequired[Dict[str, Any]]
  edge_summary: NotRequired[WhoisEdgeSummary]
  meta: NotRequired[Dict[str, Any]]

class WhoisEdgeSummary(TypedDict):
  relay_configured: NotRequired[bool]
  data_sources: NotRequired[List[Literal["rdap", "whois", "dns", "cache"]]]
  authoritative_source: NotRequired[Literal["rdap", "whois", "dns", "cache", "unknown"]]
  relay_whois_used: NotRequired[bool]
  raw_whois_available: NotRequired[bool]
  parse_error_count: NotRequired[Optional[int]]
  registered: NotRequired[Optional[bool]]
  available: NotRequired[Optional[bool]]
  registration_age_days: NotRequired[Optional[int]]
  days_until_expiry: NotRequired[Optional[int]]
  expires_within_30_days: NotRequired[Optional[bool]]
  transfer_locked: NotRequired[Optional[bool]]
  privacy_protected: NotRequired[Optional[bool]]
  dnssec: NotRequired[Optional[bool]]
  nameserver_count: NotRequired[int]
  contact_roles_available: NotRequired[List[str]]
  abuse_contact_available: NotRequired[bool]
  registrar_whois_server: NotRequired[Optional[str]]

class BulkWhoisResponse(TypedDict):
  results: NotRequired[List[WhoisResponse]]
  meta: NotRequired[Dict[str, Any]]

class RdapResponse(TypedDict):
  query: NotRequired[str]
  type: NotRequired[Literal["domain", "ip", "autnum"]]
  status: NotRequired[Literal["registered", "available", "found", "not_found"]]
  rdap: NotRequired[Optional[Dict[str, Any]]]
  entity_summary: NotRequired[RdapEntitySummary]
  dns_status: NotRequired[Dict[str, Any]]
  lookup_summary: NotRequired[RdapLookupSummary]
  meta: NotRequired[Dict[str, Any]]

class RdapLookupSummary(TypedDict):
  relay_configured: NotRequired[bool]
  query_type: NotRequired[Literal["domain", "ip", "autnum"]]
  status: NotRequired[str]
  data_source: NotRequired[Literal["rdap", "whois", "dns_fallback"]]
  relay_whois_used: NotRequired[bool]
  dns_fallback_used: NotRequired[bool]
  rdap_object_class: NotRequired[Optional[str]]
  event_count: NotRequired[Optional[int]]
  entity_count: NotRequired[Optional[int]]
  nameserver_count: NotRequired[Optional[int]]
  port43_available: NotRequired[Optional[bool]]

class RdapEntitySummary(TypedDict):
  roles_present: NotRequired[List[str]]
  abuse_contact: NotRequired[RdapEntityContact]
  registrar: NotRequired[RdapEntityContact]
  registrant: NotRequired[RdapEntityContact]
  admin: NotRequired[RdapEntityContact]
  tech: NotRequired[RdapEntityContact]
  entity_count: NotRequired[int]
  redacted_role_count: NotRequired[int]

class RdapEntityContact(TypedDict):
  handle: NotRequired[Optional[str]]
  name: NotRequired[Optional[str]]
  email: NotRequired[Optional[str]]
  roles: NotRequired[List[str]]
  public_field_count: NotRequired[int]

class DomainProfileResponse(TypedDict):
  domain: NotRequired[str]
  registered: NotRequired[Optional[bool]]
  registrar: NotRequired[Optional[str]]
  registrar_url: NotRequired[Optional[str]]
  registrar_iana_id: NotRequired[Optional[str]]
  created_date: NotRequired[Optional[str]]
  updated_date: NotRequired[Optional[str]]
  expiry_date: NotRequired[Optional[str]]
  age_days: NotRequired[int]
  days_until_expiry: NotRequired[int]
  nameservers: NotRequired[List[str]]
  status: NotRequired[List[str]]
  dnssec: NotRequired[bool]
  events: NotRequired[List[Dict[str, Any]]]
  contacts: NotRequired[Dict[str, Any]]
  privacy: NotRequired[Dict[str, Any]]
  raw_rdap_link: NotRequired[Optional[str]]
  source_summary: NotRequired[DomainProfileSourceSummary]
  checked_at: NotRequired[str]
  query_time_ms: NotRequired[int]
  meta: NotRequired[Dict[str, Any]]

class DomainProfileSourceSummary(TypedDict):
  source: NotRequired[Literal["rdap", "whois", "dns", "cache", "unknown"]]
  authoritative_source: NotRequired[Literal["rdap", "whois", "dns", "unknown"]]
  cache_status: NotRequired[Literal["hit", "miss"]]
  fallback_used: NotRequired[bool]
  relay_configured: NotRequired[bool]
  registered: NotRequired[Optional[bool]]
  status_count: NotRequired[int]
  nameserver_count: NotRequired[int]
  event_count: NotRequired[int]
  date_fields_present: NotRequired[List[str]]
  contact_field_count: NotRequired[int]
  privacy_detected: NotRequired[bool]

class OverviewComponentFreshness(TypedDict):
  cache_status: NotRequired[Literal["hit", "miss"]]
  checked_at: NotRequired[str]
  component_count: NotRequired[int]
  fresh_component_count: NotRequired[int]
  degraded_component_count: NotRequired[int]
  components: NotRequired[Dict[str, Any]]

class OverviewComponentFreshnessEntry(TypedDict):
  source: NotRequired[str]
  state: NotRequired[Literal["fresh", "degraded"]]
  checked_at: NotRequired[str]
  evidence_count: NotRequired[int]
  reason: NotRequired[Literal["upstream_unavailable", "partial_upstream_failure", "unsupported_tld", "legacy_cache_without_provenance"]]

class SocialResponse(TypedDict):
  handle: NotRequired[str]
  checked_at: NotRequired[str]
  availability: NotRequired[Dict[str, Dict[str, Any]]]
  resources: NotRequired[Dict[str, SocialResourceResult]]
  resource_summary: NotRequired[SocialResourceSummary]
  summary: NotRequired[Dict[str, Any]]
  summary_v2: NotRequired[Dict[str, Any]]
  platform_summary: NotRequired[SocialPlatformSummary]
  beta_notice: NotRequired[str]
  meta: NotRequired[Dict[str, Any]]

class SocialBulkResponse(TypedDict):
  results: Required[List[Union[SocialResponse, Dict[str, Any]]]]
  summary: Required[Dict[str, Any]]
  beta_notice: Required[str]
  meta: Required[Dict[str, Any]]

class SocialPlatformSummary(TypedDict):
  requested_count: NotRequired[int]
  checked_count: NotRequired[int]
  available_count: NotRequired[int]
  unavailable_count: NotRequired[int]
  unknown_count: NotRequired[int]
  not_supported_count: NotRequired[int]
  cached_count: NotRequired[int]
  high_confidence_count: NotRequired[int]
  live_platform_count: NotRequired[int]
  experimental_count: NotRequired[int]
  blocked_count: NotRequired[int]
  beta_limited_count: NotRequired[int]
  determinacy_rate: NotRequired[float]
  method_counts: NotRequired[Dict[str, int]]
  source_counts: NotRequired[Dict[str, int]]

class SocialResourceResult(TypedDict):
  identifier: Required[str]
  network: Required[str]
  resource_type: Required[str]
  exists: Required[Optional[bool]]
  claimability: Required[Literal["available", "taken", "unknown", "not_applicable"]]
  checked: Required[bool]
  canonical_url: Required[Optional[str]]
  canonical_id: NotRequired[str]
  canonical_handle: NotRequired[str]
  entity_type: NotRequired[str]
  visibility: NotRequired[Literal["public", "unknown"]]
  reason: NotRequired[Literal["error", "invalid_identifier", "rate_limited", "timeout"]]
  method: Required[Literal["official_api", "public_endpoint", "public_profile", "not_available"]]
  confidence: Required[Literal["high", "medium", "low", "none"]]
  latency_ms: Required[int]
  evidence: Required[Dict[str, Any]]
  cached: NotRequired[bool]
  cache_age_s: NotRequired[int]
  metadata: NotRequired[Dict[str, Any]]

class SocialResourceSummary(TypedDict):
  requested_count: Required[int]
  checked_count: Required[int]
  present_count: Required[int]
  absent_count: Required[int]
  unknown_count: Required[int]
  cached_count: Required[int]
  determinacy_rate: Required[float]

class ScoreResponse(TypedDict):
  name: NotRequired[str]
  input: NotRequired[str]
  scored_label: NotRequired[str]
  tld: NotRequired[str]
  overall_score: NotRequired[int]
  grade: NotRequired[str]
  scores: NotRequired[Dict[str, Any]]
  score_explanation: NotRequired[ScoreExplanation]
  feedback: NotRequired[List[str]]

class ScoreExplanation(TypedDict):
  score_band: NotRequired[Literal["excellent", "strong", "usable", "weak"]]
  top_strengths: NotRequired[List[ScoreDimensionDriver]]
  top_blockers: NotRequired[List[ScoreDimensionDriver]]
  weighted_dimensions: NotRequired[Any]
  most_sensitive_dimension: NotRequired[str]
  points_to_next_grade: NotRequired[Optional[int]]

class ScoreDimensionDriver(TypedDict):
  dimension: NotRequired[str]
  score: NotRequired[float]
  weight: NotRequired[float]

class ScoreCompareDecisionSummary(TypedDict):
  compared_count: NotRequired[int]
  best: NotRequired[Optional[str]]
  runner_up: NotRequired[Optional[str]]
  score_margin: NotRequired[Optional[int]]
  score_spread: NotRequired[int]
  tie_breaker: NotRequired[Optional[str]]
  winning_dimension: NotRequired[Optional[str]]

class CoverageResponse(TypedDict):
  gtlds: Required[List[str]]
  cctlds: Required[List[str]]
  total_tlds: Required[int]
  all_tlds: Required[List[str]]
  rdap_health: Required[List[Dict[str, Any]]]
  bootstrap_source: Required[Literal["iana", "fallback"]]
  bootstrap_last_updated: Required[str]
  meta: Required[Dict[str, Any]]

class PricesResponse(TypedDict):
  success: NotRequired[bool]
  data: NotRequired[Dict[str, Any]]
  meta: NotRequired[PricingMeta]

class TldPricingResponse(TypedDict):
  success: NotRequired[bool]
  data: NotRequired[TldPricing]
  meta: NotRequired[PricingMeta]

class TldPricing(TypedDict):
  tld: NotRequired[str]
  prices: NotRequired[List[Dict[str, Any]]]
  cheapest: NotRequired[Dict[str, Any]]
  averagePrice: NotRequired[Dict[str, Any]]
  priceRange: NotRequired[Dict[str, Any]]
  lastUpdated: NotRequired[Optional[str]]
  dataQuality: NotRequired[Dict[str, Any]]
  price_summary: NotRequired[PriceSummary]
  checkAccounting: NotRequired[PricingCheckAccounting]

class PriceSummary(TypedDict):
  registrar_count: NotRequired[int]
  registrar_coverage_ratio: NotRequired[float]
  price_points: NotRequired[Dict[str, Any]]
  source_counts: NotRequired[Dict[str, int]]
  confidence_counts: NotRequired[Dict[str, int]]
  freshness: NotRequired[Dict[str, Any]]
  spread: NotRequired[Dict[str, Any]]
  outlier_count: NotRequired[int]
  recommendation_eligible_registrar_count: NotRequired[int]
  quality_status: NotRequired[Literal["healthy", "degraded", "insufficient"]]
  cheapest_register: NotRequired[Optional[Any]]
  cheapest_renew: NotRequired[Optional[Any]]
  cheapest_transfer: NotRequired[Optional[Any]]

class PricingMarketSummary(TypedDict):
  tlds_requested: NotRequired[int]
  tlds_with_data: NotRequired[int]
  quote_count: NotRequired[int]
  integrated_source_count: NotRequired[int]
  total_price_points: NotRequired[int]
  average_registrar_coverage_ratio: NotRequired[float]
  stale_tld_count: NotRequired[int]
  fallback_tld_count: NotRequired[int]
  outlier_tld_count: NotRequired[int]
  widest_register_spread_tld: NotRequired[Optional[str]]
  max_register_spread_usd: NotRequired[Optional[float]]
  freshest_price_at: NotRequired[Optional[str]]
  oldest_price_at: NotRequired[Optional[str]]
  checkAccounting: NotRequired[PricingCheckAccounting]

class PricingCheckAccounting(TypedDict):
  plannedChecks: Required[int]
  actualChecks: Required[int]
  successfulRows: Required[int]
  creditsCharged: Required[int]
  creditsPerCheck: Required[Literal[1]]
  selectedRegistrars: Required[List[str]]

class BulkPricingResponse(TypedDict):
  success: NotRequired[bool]
  data: NotRequired[Dict[str, Any]]
  meta: NotRequired[PricingMeta]

class RegistrarsResponse(TypedDict):
  success: NotRequired[bool]
  data: NotRequired[Dict[str, Any]]
  meta: NotRequired[PricingMeta]

class PriceCompareResponse(TypedDict):
  success: NotRequired[bool]
  data: NotRequired[Dict[str, Any]]
  meta: NotRequired[PricingMeta]

class PriceComparisonSummary(TypedDict):
  first_year_registrar: NotRequired[Optional[str]]
  renewal_registrar: NotRequired[Optional[str]]
  transfer_registrar: NotRequired[Optional[str]]
  first_year_price: NotRequired[Optional[float]]
  renewal_price: NotRequired[Optional[float]]
  transfer_price: NotRequired[Optional[float]]
  first_year_vs_renewal_delta_usd: NotRequired[Optional[float]]
  first_year_vs_renewal_delta_pct: NotRequired[Optional[float]]
  cheapest_register_renews_higher: NotRequired[bool]
  renewal_trap_warning: NotRequired[bool]
  transfer_savings_usd: NotRequired[Optional[float]]
  cloudflare_live_status: NotRequired[Literal["registrable", "unavailable", "unsupported", "not_checked", "error"]]
  recommendation_basis: NotRequired[Literal["lowest_register", "renewal_savings", "transfer_savings", "no_price_data", "domain_unavailable", "insufficient_coverage"]]

class CloudflareCompareResult(TypedDict):
  source: NotRequired[Literal["registrar_api_beta"]]
  checked: NotRequired[bool]
  status: NotRequired[Literal["registrable", "unavailable", "unsupported", "not_checked", "error"]]
  supported: NotRequired[Optional[bool]]
  registrable: NotRequired[Optional[bool]]
  reason: NotRequired[Optional[str]]
  pricing: NotRequired[Optional[Dict[str, Any]]]
  checkedAt: NotRequired[Optional[str]]

class ExactDomainQuote(TypedDict):
  registrar: NotRequired[str]
  sourceType: NotRequired[Literal["official_api"]]
  sourceName: NotRequired[str]
  sourceUrl: NotRequired[str]
  quoteScope: NotRequired[Literal["exact_domain"]]
  checked: NotRequired[bool]
  configured: NotRequired[bool]
  status: NotRequired[Literal["registrable", "unavailable", "unsupported", "priced", "not_checked", "error"]]
  available: NotRequired[Optional[bool]]
  definitive: NotRequired[Optional[bool]]
  premium: NotRequired[Optional[bool]]
  minimumRegistrationYears: NotRequired[Optional[int]]
  currency: NotRequired[Optional[str]]
  register: NotRequired[Optional[float]]
  renew: NotRequired[Optional[float]]
  transfer: NotRequired[Optional[float]]
  checkedAt: NotRequired[Optional[str]]
  errorCode: NotRequired[Optional[str]]

class PricingMeta(TypedDict):
  requestId: NotRequired[str]
  servedBy: NotRequired[str]
  durationMs: NotRequired[int]
  cacheStatus: NotRequired[Literal["hit", "miss", "stale", "bypass"]]

class WatchlistResponse(TypedDict):
  watchlist: NotRequired[List[WatchedDomain]]
  total: NotRequired[int]
  updated_at: NotRequired[str]

class WatchedDomain(TypedDict):
  domain: NotRequired[str]
  added_at: NotRequired[str]
  status: NotRequired[Literal["registered", "available", "expiring_soon", "unknown"]]
  last_checked: NotRequired[str]
  expiry_date: NotRequired[str]
  days_until_expiry: NotRequired[int]
  notify_email: NotRequired[str]

class WatchlistAddResponse(TypedDict):
  success: NotRequired[bool]
  message: NotRequired[str]
  watchlist: NotRequired[List[WatchedDomain]]
  total: NotRequired[int]

class WatchlistCheckResponse(TypedDict):
  results: NotRequired[List[WatchedDomain]]
  summary: NotRequired[Dict[str, Any]]
  alerts: NotRequired[Dict[str, Any]]
  checked_at: NotRequired[str]

class ExpiringDomainsResponse(TypedDict):
  expiring_domains: NotRequired[List[WatchedDomain]]
  total: NotRequired[int]
  threshold_days: NotRequired[int]

class AvailableDomainsResponse(TypedDict):
  available_domains: NotRequired[List[WatchedDomain]]
  total: NotRequired[int]
  message: NotRequired[str]

class SuccessResponse(TypedDict):
  success: Required[bool]

class CustomerAccountSummary(TypedDict):
  id: Required[str]
  name: Required[str]
  role: Required[Literal["owner", "guest"]]
  owner_user_id: NotRequired[str]
  member_count: NotRequired[int]

class CustomerAccountMember(TypedDict):
  user_id: Required[str]
  email: Required[str]
  name: NotRequired[Optional[str]]
  picture: NotRequired[Optional[str]]
  role: Required[Literal["owner", "guest"]]
  joined_at: Required[str]
  is_current_user: Required[bool]

class AccountInvitation(TypedDict):
  id: Required[str]
  email: Required[str]
  status: Required[Literal["pending", "accepted", "cancelled", "expired"]]
  expires_at: Required[str]
  created_at: Required[str]

class CustomerAccountResponse(TypedDict):
  account: Required[CustomerAccountSummary]
  members: Required[List[CustomerAccountMember]]
  invitations: Required[List[AccountInvitation]]

class CustomerAccountSummaryResponse(TypedDict):
  success: NotRequired[bool]
  account: Required[CustomerAccountSummary]

class AccountInvitationCreateResponse(TypedDict):
  invitation: Required[AccountInvitation]

class ApiRequestLogSummary(TypedDict):
  id: Required[str]
  requestId: Required[str]
  userId: NotRequired[Optional[str]]
  apiKeyId: NotRequired[Optional[str]]
  authMode: Required[Literal["api_key", "session"]]
  source: Required[str]
  method: Required[str]
  path: Required[str]
  statusCode: Required[int]
  outcome: Required[Literal["success", "client_error", "server_error"]]
  errorCode: NotRequired[Optional[str]]
  requestBytes: Required[int]
  responseBytes: Required[int]
  creditsCharged: Required[int]
  creditsRefunded: Required[int]
  durationMs: Required[int]
  createdAt: Required[str]
  expiresAt: Required[str]

ApiRequestLogDetail = Union[ApiRequestLogSummary, Dict[str, Any]]

class ApiKeysResponse(TypedDict):
  keys: NotRequired[List[Dict[str, Any]]]
  account: NotRequired[Dict[str, Any]]

class ApiKeyCreateResponse(TypedDict):
  id: NotRequired[str]
  key: NotRequired[str]
  prefix: NotRequired[str]
  name: NotRequired[str]
  account_credits: NotRequired[int]
  created_at: NotRequired[str]
  message: NotRequired[str]

class CreditBalanceResponse(TypedDict):
  credits: Required[int]
  free_credits: Required[int]
  paid_credits: Required[int]
  free_cycle_month: Required[Optional[str]]

class CreditsResponse(TypedDict):
  credits: NotRequired[int]
  free_credits: NotRequired[int]
  paid_credits: NotRequired[int]
  free_cycle_month: NotRequired[Optional[str]]
  transactions: NotRequired[List[Dict[str, Any]]]

class EmailPreferenceCategories(TypedDict):
  required_transactional: Required[Literal[True]]
  requested_alerts: Required[bool]
  onboarding: Required[bool]
  lifecycle: Required[bool]
  digest: Required[bool]
  product_updates: Required[bool]
  reactivation: Required[bool]

class EmailConsentState(TypedDict):
  enabled: Required[bool]
  source: Required[Literal["dashboard", "signup", "email_unsubscribe", "admin", "import", "system"]]
  policy_version: Required[str]
  occurred_at: Required[str]

class EmailPreferences(TypedDict):
  policy_version: Required[str]
  categories: Required[EmailPreferenceCategories]
  marketing_suppressed: Required[bool]
  preferred_locale: Required[Literal["en", "es", "de", "fr", "pt", "ja", "zh", "ar", "it", "ko", "ru", "nl", "tr", "pl", "sv"]]
  frequency: Required[Dict[str, Any]]
  consent: Required[Dict[str, Any]]

class EmailPreferencesUpdate(TypedDict):
  categories: NotRequired[Dict[str, Any]]
  marketing_suppressed: NotRequired[bool]
  preferred_locale: NotRequired[Literal["en", "es", "de", "fr", "pt", "ja", "zh", "ar", "it", "ko", "ru", "nl", "tr", "pl", "sv"]]
  frequency: NotRequired[Dict[str, Any]]

class UsageResponse(TypedDict):
  period_days: NotRequired[int]
  by_endpoint: NotRequired[List[Dict[str, Any]]]
  by_date: NotRequired[List[Dict[str, Any]]]
  total_requests: NotRequired[int]
  total_credits_spent: NotRequired[int]
  previous_period: NotRequired[Dict[str, Any]]
  trends: NotRequired[Dict[str, Any]]

class ApiPricingResponse(TypedDict):
  currency: NotRequired[str]
  signup_bonus: NotRequired[int]
  monthly_refresh: NotRequired[str]
  endpoints: NotRequired[List[Dict[str, Any]]]
  free_endpoints: NotRequired[List[str]]
  note: NotRequired[str]

class BulkValuationResponse(TypedDict):
  results: NotRequired[List[ValuationResponse]]
  meta: NotRequired[Dict[str, Any]]

class CertificatesResponse(TypedDict):
  domain: NotRequired[str]
  certificates: NotRequired[List[Dict[str, Any]]]
  summary: NotRequired[Dict[str, Any]]
  pagination: NotRequired[CertificatePagination]
  intelligence_summary: NotRequired[CertificateIntelligenceSummary]
  meta: NotRequired[Dict[str, Any]]

class CertificatePagination(TypedDict):
  limit: NotRequired[int]
  offset: NotRequired[int]
  returned: NotRequired[int]
  total: NotRequired[int]
  has_more: NotRequired[bool]
  next_cursor: NotRequired[Optional[str]]

class CertificateIntelligenceSummary(TypedDict):
  data_source: NotRequired[str]
  ct_log_sources: NotRequired[List[str]]
  source_count: NotRequired[int]
  cache_status: NotRequired[Literal["live", "fresh_cache", "stale_cache", "partial_unavailable"]]
  returned_count: NotRequired[int]
  total_found: NotRequired[int]
  truncated: NotRequired[bool]
  limit: NotRequired[int]
  include_subdomains: NotRequired[bool]
  include_expired: NotRequired[bool]
  unique_name_count: NotRequired[int]
  unique_subdomains: NotRequired[int]
  issuer_count: NotRequired[int]
  wildcard_cert_count: NotRequired[int]
  active_cert_count: NotRequired[int]
  expired_cert_count: NotRequired[int]
  expiring_within_30_days_count: NotRequired[int]
  earliest_cert: NotRequired[Optional[str]]
  latest_cert: NotRequired[Optional[str]]
  latest_expiry: NotRequired[Optional[str]]
  has_more: NotRequired[bool]
  next_cursor: NotRequired[Optional[str]]
  warning_code: NotRequired[Optional[str]]

class SubdomainsResponse(TypedDict):
  domain: Required[str]
  subdomains: Required[List[Dict[str, Any]]]
  wildcards: NotRequired[List[Dict[str, Any]]]
  summary: Required[Dict[str, Any]]
  intelligence_summary: Required[SubdomainIntelligenceSummary]
  warnings: NotRequired[List[str]]
  meta: Required[Dict[str, Any]]

class SubdomainIntelligenceSummary(TypedDict):
  data_sources: NotRequired[List[Literal["ct", "crtsh", "crtname", "hackertarget", "threatminer", "wayback", "certspotter"]]]
  source_count: NotRequired[int]
  cache_status: NotRequired[Literal["live", "fresh_cache", "stale_cache"]]
  returned_count: NotRequired[int]
  total_found: NotRequired[int]
  truncated: NotRequired[bool]
  limit: NotRequired[int]
  verification_requested: NotRequired[bool]
  include_wildcards: NotRequired[bool]
  verified_count: NotRequired[int]
  verified_ratio: NotRequired[Optional[float]]
  live_dns_record_count: NotRequired[int]
  apex_included: NotRequired[bool]
  wildcard_suppressed_count: NotRequired[int]
  wildcard_returned_count: NotRequired[int]
  first_seen_oldest: NotRequired[Optional[str]]
  first_seen_newest: NotRequired[Optional[str]]
  warning_count: NotRequired[int]

class IpIntelligenceSummary(TypedDict):
  query_type: NotRequired[Literal["ip", "domain"]]
  domain_resolved: NotRequired[bool]
  cache_status: NotRequired[Literal["hit", "miss"]]
  data_source: NotRequired[str]
  confidence: NotRequired[Literal["high", "medium", "low"]]
  confidence_score: NotRequired[int]
  asn_present: NotRequired[bool]
  organization_present: NotRequired[bool]
  country_present: NotRequired[bool]
  security_signal_count: NotRequired[int]
  risk_flags: NotRequired[List[str]]
  hosting_category: NotRequired[Literal["cloud", "datacenter", "residential", "unknown"]]

class ReverseCoverageSummary(TypedDict):
  source: NotRequired[Literal["passive_dns", "passive_dns_unavailable"]]
  cache_status: NotRequired[Literal["passive_cache_only"]]
  passive_index: NotRequired[bool]
  result_count: NotRequired[int]
  returned_count: NotRequired[int]
  apex_deduped_count: NotRequired[int]
  warning_count: NotRequired[int]
  warnings: NotRequired[List[str]]
  last_seen_span_days: NotRequired[Optional[int]]

class ReverseMxFreshnessSummary(TypedDict):
  source: NotRequired[Literal["passive_dns", "passive_dns_unavailable"]]
  cache_status: NotRequired[Literal["passive_cache_only"]]
  result_count: NotRequired[int]
  returned_count: NotRequired[int]
  apex_domain_count: NotRequired[int]
  apex_deduped_count: NotRequired[int]
  warning_count: NotRequired[int]
  warnings: NotRequired[List[str]]
  last_seen_span_days: NotRequired[Optional[int]]

class IpInfoResponse(TypedDict):
  ip: NotRequired[str]
  domain: NotRequired[Optional[str]]
  geolocation: NotRequired[Dict[str, Any]]
  network: NotRequired[Dict[str, Any]]
  security: NotRequired[Dict[str, Any]]
  intelligence_summary: NotRequired[IpIntelligenceSummary]
  meta: NotRequired[Dict[str, Any]]

class ReverseIpResponse(TypedDict):
  query: NotRequired[Dict[str, Any]]
  deprecated: NotRequired[bool]
  deprecation_notice: NotRequired[str]
  ip_context: NotRequired[Optional[Dict[str, Any]]]
  results: NotRequired[List[Dict[str, Any]]]
  summary: NotRequired[Dict[str, Any]]
  coverage_summary: NotRequired[ReverseCoverageSummary]
  page: NotRequired[Dict[str, Any]]
  meta: NotRequired[Dict[str, Any]]
  cache: NotRequired[Dict[str, Any]]

class ReverseMxResponse(TypedDict):
  query: NotRequired[Dict[str, Any]]
  deprecated: NotRequired[bool]
  deprecation_notice: NotRequired[str]
  results: NotRequired[List[Dict[str, Any]]]
  summary: NotRequired[Dict[str, Any]]
  freshness_summary: NotRequired[ReverseMxFreshnessSummary]
  page: NotRequired[Dict[str, Any]]
  meta: NotRequired[Dict[str, Any]]
  cache: NotRequired[Dict[str, Any]]

TechScanTarget = Union[str, Dict[str, Any]]

class DomainPopularityObservation(TypedDict):
  domain: Required[str]
  rank: Required[Optional[int]]
  bucket: Required[Literal["top-100", "top-1k", "top-10k", "top-100k", "top-1m", "unranked"]]
  status: Required[Literal["ranked", "unranked"]]
  source: Required[Literal["tranco"]]
  list_date: Required[Optional[str]]
  observed_on: Required[str]
  checked_at: Required[str]

class DomainPopularityResponse(TypedDict):
  domain: Required[str]
  status: Required[Literal["ranked", "unranked", "unknown"]]
  rank: Required[Optional[int]]
  bucket: Required[Literal["top-100", "top-1k", "top-10k", "top-100k", "top-1m", "unranked", "unknown"]]
  source: Required[Dict[str, Any]]
  freshness: Required[Dict[str, Any]]
  checked_at: Required[str]
  result_count: Required[Literal[0, 1]]
  empty_result: Required[bool]
  history: Required[Dict[str, Any]]

class DomainPopularityHistoryResponse(TypedDict):
  domain: Required[str]
  collection: Required[Literal["lookup_driven"]]
  complete_daily_series: Required[Literal[False]]
  result_count: Required[int]
  empty_result: Required[bool]
  observations: Required[List[DomainPopularityObservation]]

class TechBulkResponse(TypedDict):
  results: Required[List[Dict[str, Any]]]
  meta: Required[Dict[str, Any]]

class ApiBatchRequestItem(TypedDict):
  method: NotRequired[Literal["GET"]]
  path: Required[str]
  query: NotRequired[Dict[str, Union[str, float, bool, List[Union[str, float, bool]]]]]
  reference: NotRequired[str]

class DomainDiscoveryJobResponse(TypedDict):
  job: Required[ApiBatchJob]
  discovery: Required[Dict[str, Any]]

class ApiBatchJob(TypedDict):
  id: Required[str]
  status: Required[Literal["queued", "running", "cancelling", "completed", "completed_with_errors", "cancelled"]]
  total: Required[int]
  counts: Required[Dict[str, Any]]
  billing: Required[Dict[str, Any]]
  webhook: Required[Dict[str, Any]]
  status_url: Required[str]
  results_url: Required[str]
  results_csv_url: Required[str]
  poll_after_ms: NotRequired[Optional[int]]
  created_at: Required[str]
  started_at: NotRequired[Optional[str]]
  completed_at: NotRequired[Optional[str]]
  cancelled_at: NotRequired[Optional[str]]
  updated_at: Required[str]
  processing_deadline_at: Required[str]
  results_expires_at: Required[str]

class ApiBatchResultsResponse(TypedDict):
  job: Required[ApiBatchJob]
  results: Required[List[Dict[str, Any]]]
  next_after: Required[Optional[int]]

class TechScanJob(TypedDict):
  id: Required[str]
  status: Required[Literal["queued", "running", "completed", "completed_with_errors", "cancelling", "cancelled", "expired"]]
  mode: Required[Literal["fast", "rendered", "deep"]]
  max_pages: Required[int]
  total: Required[int]
  counts: Required[Dict[str, Any]]
  billing: Required[Dict[str, Any]]
  status_url: Required[str]
  results_url: Required[str]
  poll_after_ms: NotRequired[Optional[int]]
  created_at: Required[str]
  started_at: NotRequired[Optional[str]]
  completed_at: NotRequired[Optional[str]]
  cancelled_at: NotRequired[Optional[str]]
  updated_at: Required[str]
  processing_deadline_at: Required[str]
  results_expires_at: Required[str]

class TechJobResultsResponse(TypedDict):
  job: Required[TechScanJob]
  results: Required[List[Dict[str, Any]]]
  pagination: Required[Dict[str, Any]]

class ScrapeResult(TypedDict):
  url: Required[str]
  final_url: Required[str]
  status: Required[Optional[int]]
  outcome: Required[Literal["success", "blocked", "rate_limited", "http_error", "network_error", "unsupported_content", "empty"]]
  content_type: Required[Optional[str]]
  content: Required[str]
  bytes: Required[int]
  truncated: Required[bool]
  redirect_count: Required[int]
  attempt_count: Required[int]
  duration_ms: Required[int]
  fetched_at: Required[str]
  headers: Required[Dict[str, str]]
  rendered: Required[bool]

class ScrapeBilling(TypedDict):
  credits_charged: Required[int]
  credits_refunded: Required[int]
  credits_per_item: NotRequired[Literal[1, 2, 10, 20]]
  credits_net: NotRequired[int]
  policy: NotRequired[Literal["effort_based"]]

class ScrapeJob(TypedDict):
  id: Required[str]
  status: Required[Literal["queued", "running", "completed", "completed_with_errors"]]
  mode: Required[Literal["standard", "resilient", "rendered", "rendered_resilient"]]
  output: Required[Literal["html", "text", "markdown"]]
  total: Required[int]
  counts: Required[Dict[str, Any]]
  billing: Required[ScrapeBilling]
  status_url: NotRequired[str]
  results_url: NotRequired[str]
  poll_after_ms: NotRequired[Optional[int]]
  created_at: NotRequired[str]
  started_at: NotRequired[Optional[str]]
  completed_at: NotRequired[Optional[str]]
  updated_at: NotRequired[str]
  processing_deadline_at: NotRequired[str]
  results_expires_at: NotRequired[str]

class TechStackResponse(TypedDict):
  url: Required[str]
  technologies: Required[List[Dict[str, Any]]]
  detection_summary: Required[TechDetectionSummary]
  summary: Required[Dict[str, Any]]
  headers: Required[Dict[str, str]]
  meta: Required[Dict[str, Any]]
  ssl: Required[Dict[str, Any]]
  analysis: Required[Dict[str, Any]]
  total_time_ms: Required[int]
  checked_at: Required[str]
  _meta: Required[Dict[str, Any]]

class TechDetectionSummary(TypedDict):
  detected_count: Required[int]
  category_count: Required[int]
  categories: Required[List[str]]
  high_confidence_count: Required[int]
  medium_confidence_count: Required[int]
  low_confidence_count: Required[int]
  versioned_count: Required[int]
  evidence_sources: Required[Dict[str, Any]]
  catalog_size: Required[int]
  catalog_category_count: Required[int]
  summary_field_count: Required[int]

class CategorizeResponse(TypedDict):
  url: NotRequired[str]
  primary_category: NotRequired[Optional[str]]
  primary_category_id: NotRequired[Optional[str]]
  categories: NotRequired[List[Dict[str, Any]]]
  primary_category_confidence: NotRequired[Literal["high", "medium", "low", "none"]]
  title: NotRequired[Optional[str]]
  description: NotRequired[Optional[str]]
  language: NotRequired[Optional[str]]
  language_confidence: NotRequired[Literal["high", "medium", "low", "none"]]
  adult_content: NotRequired[bool]
  signals_used: NotRequired[int]
  cached: NotRequired[bool]
  total_time_ms: NotRequired[int]
  checked_at: NotRequired[str]
  evidence_summary: NotRequired[CategorizeEvidenceSummary]
  meta: NotRequired[Dict[str, Any]]

class CategorizeEvidenceSummary(TypedDict):
  analysis_status: Required[Literal["complete", "partial"]]
  content_observed: Required[bool]
  content_source: Required[Literal["live_html", "known_domain"]]
  cache_status: Required[Literal["miss", "hit", "stale"]]
  stale: Required[bool]
  fetch_transport: Required[Literal["direct", "relay"]]
  response_status: Required[Optional[int]]
  final_url: Required[str]
  redirect_count: Required[int]
  body_truncated: Required[bool]
  unavailable_reason: NotRequired[str]

class CategorizeTaxonomyResponse(TypedDict):
  taxonomy: NotRequired[str]
  version: NotRequired[str]
  official_iab_taxonomy: NotRequired[bool]
  inspired_by: NotRequired[str]
  category_count: NotRequired[int]
  subcategory_count: NotRequired[int]
  notes: NotRequired[List[str]]
  categories: NotRequired[List[Dict[str, Any]]]
  meta: NotRequired[Dict[str, Any]]

class RedirectsResponse(TypedDict):
  original_url: NotRequired[str]
  final_url: NotRequired[str]
  redirect_count: NotRequired[int]
  hops: NotRequired[List[Dict[str, Any]]]
  https_upgrade: NotRequired[bool]
  domain_changed: NotRequired[bool]
  final_status: NotRequired[int]
  final_title: NotRequired[str]
  risk_summary: NotRequired[RedirectRiskSummary]
  total_time_ms: NotRequired[int]
  checked_at: NotRequired[str]

class RedirectRiskSummary(TypedDict):
  risk_level: NotRequired[Literal["low", "medium", "high"]]
  risk_flags: NotRequired[List[str]]
  hop_count: NotRequired[int]
  redirect_count: NotRequired[int]
  https_upgrade: NotRequired[bool]
  https_downgrade: NotRequired[bool]
  domain_changed: NotRequired[bool]
  final_status: NotRequired[int]
  error_present: NotRequired[bool]
  tracking_parameter_hops: NotRequired[int]

class PublicIdentity(TypedDict):
  platform: Required[str]
  type: Required[Literal["social", "developer", "creator", "app_store", "federated", "other"]]
  handle: NotRequired[Optional[str]]
  url: Required[str]
  source: Required[Literal["same_as", "rel_me", "homepage_link"]]
  confidence: Required[Literal["high", "medium"]]

class WebDataMeta(TypedDict):
  checked_at: Required[str]
  cached: Required[bool]
  fetch_transport: Required[Literal["worker", "edge_relay"]]

class UrlIntelligenceResponse(TypedDict):
  requested_url: Required[str]
  final_url: Required[str]
  status: Required[int]
  fetch_state: Required[Literal["ok", "blocked", "http_error", "non_html", "empty"]]
  content_type: NotRequired[Optional[str]]
  redirects: NotRequired[int]
  title: NotRequired[Optional[str]]
  description: NotRequired[Optional[str]]
  canonical_url: NotRequired[Optional[str]]
  language: NotRequired[Optional[str]]
  favicon_url: NotRequired[Optional[str]]
  preview_image_url: NotRequired[Optional[str]]
  manifest_url: NotRequired[Optional[str]]
  theme_color: NotRequired[Optional[str]]
  open_graph: Required[Dict[str, str]]
  twitter_card: Required[Dict[str, str]]
  structured_data: Required[Dict[str, Any]]
  robots: Required[Dict[str, Any]]
  security_headers: NotRequired[Dict[str, Optional[str]]]
  links: Required[Dict[str, Any]]
  social_profiles: Required[List[PublicIdentity]]
  contacts: Required[Dict[str, Any]]
  meta: Required[WebDataMeta]

class IdentityAssetsResponse(TypedDict):
  domain: Required[str]
  website_url: Required[str]
  fetch_state: Required[Literal["ok", "blocked", "http_error", "non_html", "empty"]]
  organization_name: NotRequired[Optional[str]]
  assets: Required[Dict[str, Any]]
  social_profiles: Required[List[PublicIdentity]]
  confidence: Required[float]
  evidence: Required[List[str]]
  meta: Required[WebDataMeta]

class IdentityResolutionResponse(TypedDict):
  query: Required[str]
  canonical_domain: Required[str]
  website_url: Required[str]
  fetch_state: Required[Literal["ok", "blocked", "http_error", "non_html", "empty"]]
  organization: Required[Dict[str, Any]]
  identities: Required[List[PublicIdentity]]
  contacts: Required[Dict[str, Any]]
  confidence: Required[float]
  evidence: Required[Dict[str, Any]]
  meta: Required[WebDataMeta]

class BulkWebDataResponse(TypedDict):
  results: Required[List[Dict[str, Any]]]
  meta: Required[Dict[str, Any]]

class CompanyResponse(TypedDict):
  domain: NotRequired[str]
  company: NotRequired[Dict[str, Any]]
  location: NotRequired[Any]
  social: NotRequired[Dict[str, Any]]
  tech: NotRequired[Dict[str, Any]]
  confidence: NotRequired[float]
  evidence_summary: NotRequired[CompanyEvidenceSummary]
  meta: NotRequired[Any]

class CompanyEvidenceSummary(TypedDict):
  sources: NotRequired[List[str]]
  source_count: NotRequired[int]
  confidence: NotRequired[float]
  confidence_label: NotRequired[Literal["high", "medium", "low"]]
  company_field_count: NotRequired[int]
  social_profile_count: NotRequired[int]
  email_provider_detected: NotRequired[bool]
  website_technology_count: NotRequired[int]
  cache_status: NotRequired[Literal["hit", "miss"]]

class ReputationResponse(TypedDict):
  domain: NotRequired[str]
  reputation_score: NotRequired[int]
  grade: NotRequired[str]
  risk_level: NotRequired[Literal["low", "medium", "high", "critical"]]
  reputation_score_confidence: NotRequired[Literal["high", "medium", "low"]]
  grade_capped_by_parking: NotRequired[bool]
  factors: NotRequired[Dict[str, Any]]
  recommendations: NotRequired[List[Dict[str, Any]]]
  evidence_summary: NotRequired[ReputationEvidenceSummary]
  meta: NotRequired[Dict[str, Any]]

class BulkReputationResult(TypedDict):
  domain: NotRequired[str]
  reputation_score: NotRequired[int]
  grade: NotRequired[str]
  risk_level: NotRequired[Literal["low", "medium", "high", "critical"]]
  reputation_score_confidence: NotRequired[Literal["high", "medium", "low"]]
  grade_capped_by_parking: NotRequired[bool]
  factors: NotRequired[Dict[str, Any]]
  evidence_summary: NotRequired[ReputationEvidenceSummary]
  recommendations: NotRequired[List[Dict[str, Any]]]
  meta: NotRequired[Dict[str, Any]]
  error: NotRequired[Dict[str, Any]]

class ReputationEvidenceSummary(TypedDict):
  checks_performed: NotRequired[int]
  cache_status: NotRequired[Literal["hit", "miss"]]
  confidence: NotRequired[Literal["high", "medium", "low"]]
  risk_level: NotRequired[Literal["low", "medium", "high", "critical"]]
  factor_count: NotRequired[int]
  scored_factor_count: NotRequired[int]
  passing_factor_count: NotRequired[int]
  warning_factor_count: NotRequired[int]
  failing_factor_count: NotRequired[int]
  lowest_scoring_factors: NotRequired[List[Dict[str, Any]]]
  blacklist_listed_count: NotRequired[int]
  recommendation_count: NotRequired[int]
  high_priority_recommendation_count: NotRequired[int]
  grade_capped_by_parking: NotRequired[bool]

class BulkReputationResponse(TypedDict):
  results: NotRequired[List[BulkReputationResult]]
  summary: NotRequired[Dict[str, Any]]
  meta: NotRequired[Dict[str, Any]]

class TldsListResponse(TypedDict):
  tlds: NotRequired[List[Dict[str, Any]]]
  total: NotRequired[int]
  by_type: NotRequired[Dict[str, Any]]
  by_trust_tier: NotRequired[Dict[str, Any]]
  use_case: NotRequired[str]
  meta: NotRequired[Dict[str, Any]]

class TldDetailResponse(TypedDict):
  tld: NotRequired[str]
  type: NotRequired[Literal["gTLD", "ccTLD", "newTLD", "idn"]]
  name: NotRequired[str]
  description: NotRequired[str]
  introduced: NotRequired[int]
  operator: NotRequired[Optional[str]]
  country: NotRequired[Optional[str]]
  restrictions: NotRequired[str]
  rdap_supported: NotRequired[bool]
  rdap_endpoint: NotRequired[Optional[str]]
  idn_supported: NotRequired[bool]
  dnssec_supported: NotRequired[bool]
  pricing: NotRequired[Dict[str, Any]]
  popularity: NotRequired[Dict[str, Any]]
  trust: NotRequired[Dict[str, Any]]
  meta: NotRequired[Dict[str, Any]]

class CompareDomainsResponse(TypedDict):
  domains: NotRequired[List[Dict[str, Any]]]
  recommendation: NotRequired[Dict[str, Any]]
  decision_summary: NotRequired[CompareDecisionSummary]
  meta: NotRequired[Dict[str, Any]]

class CompareDecisionSummary(TypedDict):
  compared_count: NotRequired[int]
  best_overall: NotRequired[Optional[str]]
  best_available: NotRequired[Optional[str]]
  runner_up: NotRequired[Optional[str]]
  rank_margin: NotRequired[Optional[int]]
  score_margin: NotRequired[Optional[int]]
  value_margin_usd: NotRequired[Optional[float]]
  availability_used: NotRequired[bool]
  winning_factor: NotRequired[Literal["availability", "brand_score", "valuation", "tld_trust", "overall_rank"]]
  tie_breaker: NotRequired[Optional[str]]

class EmailComplianceResponse(TypedDict):
  domain: NotRequired[str]
  status: NotRequired[Literal["pass", "warn", "fail"]]
  score: NotRequired[int]
  grade: NotRequired[Literal["A+", "A", "B", "C", "D", "F"]]
  provider_readiness: NotRequired[Dict[str, Any]]
  summary: NotRequired[Dict[str, Any]]
  action_items: NotRequired[List[EmailComplianceActionItem]]
  evidence: NotRequired[Dict[str, Any]]
  proxy: NotRequired[Dict[str, Any]]
  limitations: NotRequired[List[str]]
  checked_at: NotRequired[str]
  check_duration_ms: NotRequired[int]

class EmailProviderReadiness(TypedDict):
  provider: NotRequired[Literal["google", "microsoft"]]
  display_name: NotRequired[str]
  status: NotRequired[Literal["pass", "warn", "fail"]]
  dns_visible_status: NotRequired[Literal["pass", "warn", "fail"]]
  requirements: NotRequired[List[EmailComplianceRequirement]]
  verification_required: NotRequired[List[str]]
  notes: NotRequired[List[str]]

class EmailComplianceRequirement(TypedDict):
  id: NotRequired[str]
  label: NotRequired[str]
  status: NotRequired[Literal["pass", "warn", "fail", "unknown"]]
  severity: NotRequired[Literal["critical", "high", "medium", "low", "info"]]
  category: NotRequired[Literal["dns", "message", "transport", "reputation", "content"]]
  evidence: NotRequired[str]
  recommendation: NotRequired[str]

class EmailComplianceActionItem(TypedDict):
  priority: NotRequired[Literal["critical", "high", "medium", "low", "info"]]
  category: NotRequired[Literal["authentication", "transport", "dns", "brand", "reputation"]]
  title: NotRequired[str]
  detail: NotRequired[str]
  fix: NotRequired[str]

class EmailAuthResponse(TypedDict):
  domain: NotRequired[str]
  spf: NotRequired[Dict[str, Any]]
  dkim: NotRequired[List[Dict[str, Any]]]
  dkim_audit: NotRequired[Dict[str, Any]]
  bimi: NotRequired[Dict[str, Any]]
  dmarc: NotRequired[Dict[str, Any]]
  mta_sts: NotRequired[Dict[str, Any]]
  tls_rpt: NotRequired[Dict[str, Any]]
  client_access: NotRequired[Dict[str, Any]]
  autodiscover: NotRequired[Dict[str, Any]]
  edge_summary: NotRequired[Dict[str, Any]]
  provider_selector_recommendations: NotRequired[List[Dict[str, Any]]]
  grade: NotRequired[str]
  notes: NotRequired[List[str]]

class SimilarityResponse(TypedDict):
  domain1: NotRequired[str]
  domain2: NotRequired[str]
  overall_similarity: NotRequired[float]
  risk_level: NotRequired[Literal["none", "low", "medium", "high", "critical"]]
  analysis: NotRequired[Dict[str, Any]]
  matching_methods: NotRequired[List[str]]
  is_potential_typosquat: NotRequired[bool]
  checked_at: NotRequired[str]
  meta: NotRequired[Dict[str, Any]]

class MacInfoResponse(TypedDict):
  mac: NotRequired[str]
  input: NotRequired[str]
  type: NotRequired[Literal["eui-48", "eui-64"]]
  oui: NotRequired[str]
  device_id: NotRequired[str]
  flags: NotRequired[Dict[str, Any]]
  vendor: NotRequired[Dict[str, Any]]
  meta: NotRequired[Dict[str, Any]]

class FullReportResponse(TypedDict):
  domain: NotRequired[str]
  generated_at: NotRequired[str]
  availability: NotRequired[Any]
  dns: NotRequired[Any]
  whois: NotRequired[Any]
  ssl: NotRequired[Any]
  tech_stack: NotRequired[Any]
  reputation: NotRequired[Any]
  email_auth: NotRequired[Any]
  valuation: NotRequired[Any]
  summary: NotRequired[Dict[str, Any]]

class BuildDmarcParams(TypedDict):
  policy: Required[Literal["none", "quarantine", "reject"]]
  subdomain_policy: NotRequired[Literal["none", "quarantine", "reject"]]
  percentage: NotRequired[int]
  rua: NotRequired[List[str]]
  ruf: NotRequired[List[str]]
  adkim: NotRequired[Literal["relaxed", "strict"]]
  aspf: NotRequired[Literal["relaxed", "strict"]]

BuildDmarcResponse = Dict[str, Any]

class BuildSpfParams(TypedDict):
  include: NotRequired[List[str]]
  ip4: NotRequired[List[str]]
  ip6: NotRequired[List[str]]
  a: NotRequired[bool]
  mx: NotRequired[bool]
  redirect: NotRequired[str]
  all: Required[Literal["pass", "fail", "softfail", "neutral"]]

BuildSpfResponse = Dict[str, Any]

class BulkCheckDomainsParams(TypedDict):
  domains: Required[List[str]]
  prefer_cache: NotRequired[bool]

BulkCheckDomainsResponse = BulkStatusResponse

class BulkCheckSocialHandlesParams(TypedDict):
  handles: Required[List[str]]
  platforms: NotRequired[List[str]]
  resources: NotRequired[List[str]]

BulkCheckSocialHandlesResponse = SocialBulkResponse

class BulkDnsPropagationParams(TypedDict):
  domains: Required[List[str]]
  type: NotRequired[Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]]
  expected: NotRequired[str]

BulkDnsPropagationResponse = BulkLookupResponse

class BulkDomainValueParams(TypedDict):
  domains: Required[List[str]]

BulkDomainValueResponse = BulkValuationResponse

class BulkEmailCheckParams(TypedDict):
  emails: Required[List[str]]
  checks: NotRequired[List[Literal["disposable", "role", "free", "mx", "dnsbl"]]]

BulkEmailCheckResponse = Dict[str, Any]

class BulkGetCertificatesParams(TypedDict):
  domains: Required[List[str]]
  include_subdomains: NotRequired[bool]
  include_expired: NotRequired[bool]
  limit: NotRequired[int]

BulkGetCertificatesResponse = BulkLookupResponse

class BulkGetDomainProfileParams(TypedDict):
  domains: Required[List[str]]

BulkGetDomainProfileResponse = BulkLookupResponse

class BulkGetEmailAuthParams(TypedDict):
  domains: Required[List[str]]
  selectors: NotRequired[List[str]]

BulkGetEmailAuthResponse = BulkLookupResponse

class BulkGetHostingParams(TypedDict):
  domains: Required[List[str]]

BulkGetHostingResponse = BulkLookupResponse

class BulkGetRdapParams(TypedDict):
  queries: Required[List[str]]
  type: NotRequired[Literal["domain", "ip", "autnum"]]

BulkGetRdapResponse = BulkLookupResponse

class BulkGetSubdomainsParams(TypedDict):
  domains: Required[List[str]]
  verify: NotRequired[bool]
  include_wildcards: NotRequired[bool]
  limit: NotRequired[int]

BulkGetSubdomainsResponse = BulkLookupResponse

class BulkGetUrlIntelligenceParams(TypedDict):
  urls: Required[List[str]]

BulkGetUrlIntelligenceResponse = BulkWebDataResponse

class BulkGetWebsiteIdentityAssetsParams(TypedDict):
  domains: Required[List[str]]

BulkGetWebsiteIdentityAssetsResponse = BulkWebDataResponse

class BulkPricingParams(TypedDict):
  tlds: Required[List[str]]
  registrars: NotRequired[List[str]]
  options: NotRequired[Dict[str, Any]]

BulkPricingResponse = BulkPricingResponse

class BulkResolveInternetIdentityParams(TypedDict):
  domains: Required[List[str]]

BulkResolveInternetIdentityResponse = BulkWebDataResponse

class BulkWhoisParams(TypedDict):
  domains: Required[List[str]]

BulkWhoisResponse = BulkWhoisResponse

class CancelApiBatchParams(TypedDict):
  job_id: Required[str]

CancelApiBatchResponse = Dict[str, Any]

class CancelTechScanJobParams(TypedDict):
  job_id: Required[str]

CancelTechScanJobResponse = Dict[str, Any]

class CategorizeWebsiteParams(TypedDict):
  url: NotRequired[str]
  domain: NotRequired[str]
  skip_cache: NotRequired[Literal["0", "1"]]
  min_confidence: NotRequired[int]

CategorizeWebsiteResponse = CategorizeResponse

class CategorizeWebsiteBulkParams(TypedDict):
  urls: Required[List[str]]

CategorizeWebsiteBulkResponse = Dict[str, Any]

class CheckDkimParams(TypedDict):
  domain: Required[str]
  selector: Required[str]

CheckDkimResponse = Dict[str, Any]

class CheckDomainAvailabilityParams(TypedDict):
  name: NotRequired[str]
  tlds: NotRequired[str]
  domain: NotRequired[str]
  prefer_cache: NotRequired[bool]

CheckDomainAvailabilityResponse = StatusResponse

class CheckEmailBlacklistParams(TypedDict):
  email: Required[str]
  checks: NotRequired[str]

CheckEmailBlacklistResponse = Dict[str, Any]

class CheckSocialHandlesParams(TypedDict):
  handle: Required[str]
  platforms: NotRequired[str]
  resources: NotRequired[str]

CheckSocialHandlesResponse = SocialResponse

class CompareBrandNamesParams(TypedDict):
  names: Required[List[str]]

CompareBrandNamesResponse = Dict[str, Any]

class CompareDomainsParams(TypedDict):
  domains: Required[str]

CompareDomainsResponse = CompareDomainsResponse

class ComparePricesParams(TypedDict):
  domain: Required[str]
  registrars: NotRequired[str]
  skip_cache: NotRequired[bool]

ComparePricesResponse = PriceCompareResponse

class CreateApiBatchParams(TypedDict):
  requests: Required[List[Dict[str, Any]]]
  webhook: NotRequired[Dict[str, Any]]

CreateApiBatchResponse = Any

class CreateDomainDiscoveryJobParams(TypedDict):
  tlds: Required[List[str]]
  limit: NotRequired[int]
  cursor: NotRequired[str]
  min_length: NotRequired[int]
  max_length: NotRequired[int]
  singular_only: NotRequired[bool]

CreateDomainDiscoveryJobResponse = DomainDiscoveryJobResponse

class CreateScrapeJobParams(TypedDict):
  mode: NotRequired[Literal["standard", "resilient", "rendered", "rendered_resilient"]]
  output: NotRequired[Literal["html", "text", "markdown"]]
  urls: Required[List[Union[str, Dict[str, Any]]]]

CreateScrapeJobResponse = Dict[str, Any]

class CreateTechScanJobParams(TypedDict):
  mode: NotRequired[Literal["fast", "rendered", "deep"]]
  max_pages: NotRequired[int]
  targets: Required[List[Union[str, Dict[str, Any]]]]

CreateTechScanJobResponse = Dict[str, Any]

class DiscoverDkimParams(TypedDict):
  domain: Required[str]

DiscoverDkimResponse = Dict[str, Any]

class DownloadEmailBlacklistParams(TypedDict):
  format: NotRequired[Literal["json", "txt"]]

DownloadEmailBlacklistResponse = Dict[str, Any]

class FlattenSpfParams(TypedDict):
  domain: Required[str]

FlattenSpfResponse = Dict[str, Any]

class GetAllDnsRecordsParams(TypedDict):
  domain: Required[str]
  wildcard_probe: NotRequired[Literal["1"]]

GetAllDnsRecordsResponse = DnsAllResponse

class GetApiBatchParams(TypedDict):
  job_id: Required[str]

GetApiBatchResponse = Dict[str, Any]

class GetApiBatchResultsParams(TypedDict):
  job_id: Required[str]
  after: NotRequired[int]
  limit: NotRequired[int]
  format: NotRequired[Literal["json", "csv"]]

GetApiBatchResultsResponse = ApiBatchResultsResponse

class GetCategorizationTaxonomyParams(TypedDict):
  pass

GetCategorizationTaxonomyResponse = CategorizeTaxonomyResponse

class GetCertificatesParams(TypedDict):
  domain: Required[str]
  include_subdomains: NotRequired[bool]
  include_expired: NotRequired[bool]
  limit: NotRequired[int]
  cursor: NotRequired[str]

GetCertificatesResponse = CertificatesResponse

class GetCompanyParams(TypedDict):
  domain: Required[str]

GetCompanyResponse = CompanyResponse

class GetCoverageParams(TypedDict):
  live: NotRequired[Literal["1"]]

GetCoverageResponse = CoverageResponse

class GetCreditBalanceParams(TypedDict):
  pass

GetCreditBalanceResponse = CreditBalanceResponse

GetDnsHistoryParams = TypedDict("GetDnsHistoryParams", { "domain": Required[str], "type": NotRequired[str], "from": NotRequired[str], "to": NotRequired[str], "limit": NotRequired[int] })

GetDnsHistoryResponse = Dict[str, Any]

class GetDnsPropagationParams(TypedDict):
  domain: Required[str]
  type: NotRequired[Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]]
  expected: NotRequired[str]

GetDnsPropagationResponse = DnsPropagationResponse

class GetDnsRecordsParams(TypedDict):
  domain: Required[str]
  type: NotRequired[Literal["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "PTR", "SRV"]]

GetDnsRecordsResponse = DnsResponse

class GetDnsSecurityParams(TypedDict):
  domain: Required[str]

GetDnsSecurityResponse = DnsSecurityResponse

class GetDnsServersParams(TypedDict):
  pass

GetDnsServersResponse = DnsServersResponse

class GetDomainHealthParams(TypedDict):
  domain: Required[str]
  details: NotRequired[bool]

GetDomainHealthResponse = HealthResponse

class GetDomainLifecycleParams(TypedDict):
  domain: Required[str]

GetDomainLifecycleResponse = LifecycleResponse

class GetDomainOverviewParams(TypedDict):
  domain: Required[str]

GetDomainOverviewResponse = Dict[str, Any]

class GetDomainPopularityParams(TypedDict):
  domain: Required[str]
  include_history: NotRequired[bool]
  history_limit: NotRequired[int]

GetDomainPopularityResponse = DomainPopularityResponse

class GetDomainPopularityHistoryParams(TypedDict):
  domain: Required[str]
  limit: NotRequired[int]

GetDomainPopularityHistoryResponse = DomainPopularityHistoryResponse

class GetDomainProfileParams(TypedDict):
  domain: Required[str]

GetDomainProfileResponse = DomainProfileResponse

class GetDomainReputationParams(TypedDict):
  domain: Required[str]

GetDomainReputationResponse = ReputationResponse

class GetDomainScoreParams(TypedDict):
  name: NotRequired[str]
  domain: NotRequired[str]

GetDomainScoreResponse = ScoreResponse

class GetDomainSimilarityParams(TypedDict):
  domain1: Required[str]
  domain2: Required[str]

GetDomainSimilarityResponse = SimilarityResponse

class GetDomainValueParams(TypedDict):
  domain: Required[str]

GetDomainValueResponse = ValuationResponse

class GetEmailAuthParams(TypedDict):
  domain: Required[str]
  selectors: NotRequired[str]

GetEmailAuthResponse = EmailAuthResponse

class GetEmailBlacklistInfoParams(TypedDict):
  limit: NotRequired[int]
  offset: NotRequired[int]
  format: NotRequired[Literal["json", "txt"]]

GetEmailBlacklistInfoResponse = Dict[str, Any]

class GetEmailComplianceParams(TypedDict):
  domain: Required[str]
  selectors: NotRequired[str]
  providers: NotRequired[str]

GetEmailComplianceResponse = EmailComplianceResponse

class GetHostingParams(TypedDict):
  domain: Required[str]

GetHostingResponse = Dict[str, Any]

class GetIpInfoParams(TypedDict):
  ip: NotRequired[str]
  domain: NotRequired[str]

GetIpInfoResponse = IpInfoResponse

class GetMacInfoParams(TypedDict):
  mac: Required[str]

GetMacInfoResponse = MacInfoResponse

class GetMacLookupInfoParams(TypedDict):
  pass

GetMacLookupInfoResponse = Dict[str, Any]

class GetParkingDetectionParams(TypedDict):
  domain: Required[str]

GetParkingDetectionResponse = Dict[str, Any]

class GetPricesParams(TypedDict):
  tlds: NotRequired[str]
  registrars: NotRequired[str]
  skip_cache: NotRequired[bool]

GetPricesResponse = PricesResponse

class GetPricingInfoParams(TypedDict):
  pass

GetPricingInfoResponse = ApiPricingResponse

class GetQuickHealthParams(TypedDict):
  domain: Required[str]

GetQuickHealthResponse = QuickHealthResponse

class GetRdapParams(TypedDict):
  query: NotRequired[str]
  type: NotRequired[Literal["domain", "ip", "autnum"]]
  domain: NotRequired[str]

GetRdapResponse = RdapResponse

class GetRedirectsParams(TypedDict):
  url: NotRequired[str]
  domain: NotRequired[str]

GetRedirectsResponse = RedirectsResponse

class GetRegistrarsParams(TypedDict):
  pass

GetRegistrarsResponse = RegistrarsResponse

class GetScoreInfoParams(TypedDict):
  pass

GetScoreInfoResponse = Dict[str, Any]

class GetScrapeJobParams(TypedDict):
  job_id: Required[str]

GetScrapeJobResponse = Dict[str, Any]

class GetScrapeJobResultsParams(TypedDict):
  job_id: Required[str]
  limit: NotRequired[int]
  offset: NotRequired[int]

GetScrapeJobResultsResponse = Dict[str, Any]

class GetSocialInfoParams(TypedDict):
  pass

GetSocialInfoResponse = Dict[str, Any]

class GetSslAuditParams(TypedDict):
  domain: Required[str]

GetSslAuditResponse = Dict[str, Any]

class GetSslChainParams(TypedDict):
  domain: Required[str]

GetSslChainResponse = Dict[str, Any]

class GetSslDeepScanParams(TypedDict):
  domain: Required[str]
  refresh: NotRequired[bool]
  profile: NotRequired[Literal["standard", "full"]]

GetSslDeepScanResponse = Dict[str, Any]

class GetSslExpiringParams(TypedDict):
  domain: Required[str]
  days: NotRequired[int]
  threshold_days: NotRequired[int]

GetSslExpiringResponse = Dict[str, Any]

class GetSslGradeParams(TypedDict):
  domain: Required[str]

GetSslGradeResponse = Dict[str, Any]

class GetSubdomainsParams(TypedDict):
  domain: Required[str]
  sources: NotRequired[Literal["ct"]]
  verify: NotRequired[Literal["true", "false", "1", "0", "yes", "no"]]
  include_wildcards: NotRequired[Literal["true", "false", "1", "0", "yes", "no"]]
  limit: NotRequired[int]
  prefer_cache: NotRequired[Literal["true", "false", "1", "0", "yes", "no"]]

GetSubdomainsResponse = SubdomainsResponse

class GetTechScanJobParams(TypedDict):
  job_id: Required[str]

GetTechScanJobResponse = Dict[str, Any]

class GetTechScanJobResultsParams(TypedDict):
  job_id: Required[str]
  cursor: NotRequired[str]
  limit: NotRequired[int]

GetTechScanJobResultsResponse = TechJobResultsResponse

class GetTechStackParams(TypedDict):
  url: NotRequired[str]
  domain: NotRequired[str]
  mode: NotRequired[Literal["fast", "rendered", "deep"]]
  max_pages: NotRequired[int]
  skip_cache: NotRequired[Literal["0", "1"]]

GetTechStackResponse = TechStackResponse

class GetTldDetailParams(TypedDict):
  tld: Required[str]

GetTldDetailResponse = TldDetailResponse

class GetTldPricingParams(TypedDict):
  tld: Required[str]
  registrars: NotRequired[str]
  skip_cache: NotRequired[bool]

GetTldPricingResponse = TldPricingResponse

class GetTldsParams(TypedDict):
  type: NotRequired[Literal["gtld", "cctld", "new-gtld", "idn"]]
  trust_tier: NotRequired[Literal["premium", "standard", "economy", "suspicious"]]
  use_case: NotRequired[str]

GetTldsResponse = TldsListResponse

class GetTyposquattingParams(TypedDict):
  domain: Required[str]
  check_registered: NotRequired[bool]
  limit: NotRequired[int]
  include_tld_swap: NotRequired[bool]

GetTyposquattingResponse = TyposResponse

class GetUrlIntelligenceParams(TypedDict):
  url: Required[str]
  skip_cache: NotRequired[Literal["1"]]

GetUrlIntelligenceResponse = UrlIntelligenceResponse

class GetVulnerabilitiesParams(TypedDict):
  url: NotRequired[str]
  domain: NotRequired[str]
  mode: NotRequired[Literal["standard", "deep"]]

GetVulnerabilitiesResponse = Dict[str, Any]

class GetWebsiteIdentityAssetsParams(TypedDict):
  domain: Required[str]
  skip_cache: NotRequired[Literal["1"]]

GetWebsiteIdentityAssetsResponse = IdentityAssetsResponse

class GetWhoisParams(TypedDict):
  domain: Required[str]

GetWhoisResponse = WhoisResponse

class GetWhoisHistoryParams(TypedDict):
  domain: Required[str]
  limit: NotRequired[int]

GetWhoisHistoryResponse = Dict[str, Any]

class GetWhoisV2Params(TypedDict):
  domain: Required[str]

GetWhoisV2Response = WhoisResponse

class ListApiBatchesParams(TypedDict):
  limit: NotRequired[int]

ListApiBatchesResponse = Dict[str, Any]

class ListTechScanJobsParams(TypedDict):
  limit: NotRequired[int]
  cursor: NotRequired[str]

ListTechScanJobsResponse = Dict[str, Any]

class PostTechStackBulkParams(TypedDict):
  mode: NotRequired[Literal["fast"]]
  targets: Required[List[Union[str, Dict[str, Any]]]]

PostTechStackBulkResponse = TechBulkResponse

class RecipeBrandLaunchParams(TypedDict):
  domain: Required[str]
  brand_name: NotRequired[str]
  platforms: NotRequired[str]

RecipeBrandLaunchResponse = RecipeResponse

class RecipeCompetitorIntelParams(TypedDict):
  domain: Required[str]
  discover_subdomains: NotRequired[bool]
  analyze_infrastructure: NotRequired[bool]
  analyze_email: NotRequired[bool]

RecipeCompetitorIntelResponse = RecipeResponse

class RecipeDefensiveRegistrationParams(TypedDict):
  brand: Required[str]
  owned_domains: Required[str]
  priority_tlds: NotRequired[str]
  include_typos: NotRequired[bool]
  budget: NotRequired[float]

RecipeDefensiveRegistrationResponse = RecipeResponse

class RecipeDnsMigrationParams(TypedDict):
  domain: Required[str]
  target_nameservers: NotRequired[str]
  critical_records: NotRequired[str]

RecipeDnsMigrationResponse = RecipeResponse

class RecipeDomainFinderParams(TypedDict):
  keywords: Required[str]
  tlds: NotRequired[str]
  style: NotRequired[Literal["brandable", "keyword-rich", "short"]]
  max_length: NotRequired[int]
  language: NotRequired[Literal["en", "zh", "es", "ja", "de", "fr", "pt", "it", "ko", "ru", "ar", "hi", "bn", "id", "ms", "th", "vi", "tr", "pl", "nl", "sv", "da", "no", "fi", "el", "cs", "hu", "ro", "uk", "he"]]
  limit: NotRequired[int]

RecipeDomainFinderResponse = RecipeResponse

class RecipeDueDiligenceParams(TypedDict):
  domain: Required[str]
  include_competitors: NotRequired[bool]

RecipeDueDiligenceResponse = RecipeResponse

class RecipeEmailDeliverabilityParams(TypedDict):
  domain: Required[str]
  dkim_selectors: NotRequired[str]
  check_blacklists: NotRequired[bool]

RecipeEmailDeliverabilityResponse = RecipeResponse

class RecipeInfrastructureDiscoveryParams(TypedDict):
  domain: Required[str]
  depth: NotRequired[Literal["quick", "standard", "deep"]]
  include_historical: NotRequired[bool]

RecipeInfrastructureDiscoveryResponse = RecipeResponse

class RecipePhishingInvestigationParams(TypedDict):
  suspicious_domain: Required[str]
  legitimate_domain: NotRequired[str]
  collect_evidence: NotRequired[bool]

RecipePhishingInvestigationResponse = RecipeResponse

class RecipePortfolioAuditParams(TypedDict):
  domains: Required[str]
  include_valuation: NotRequired[bool]
  include_health: NotRequired[bool]
  include_pricing: NotRequired[bool]
  alert_expiring_days: NotRequired[int]

RecipePortfolioAuditResponse = RecipeResponse

class RecipePortfolioAuditPostParams(TypedDict):
  domains: Required[List[str]]
  include_valuation: NotRequired[bool]
  include_health: NotRequired[bool]
  include_pricing: NotRequired[bool]
  alert_expiring_days: NotRequired[int]

RecipePortfolioAuditPostResponse = RecipeResponse

class RecipeThreatAssessmentParams(TypedDict):
  domain: Required[str]
  analyze_threats: NotRequired[bool]
  max_threats: NotRequired[int]
  include_evidence: NotRequired[bool]

RecipeThreatAssessmentResponse = RecipeResponse

class ResolveInternetIdentityParams(TypedDict):
  domain: Required[str]
  skip_cache: NotRequired[Literal["1"]]

ResolveInternetIdentityResponse = IdentityResolutionResponse

class ScrapePageParams(TypedDict):
  url: Required[str]
  mode: NotRequired[Literal["standard", "resilient", "rendered", "rendered_resilient"]]
  output: NotRequired[Literal["html", "text", "markdown"]]

ScrapePageResponse = Dict[str, Any]

class SuggestDomainsParams(TypedDict):
  keywords: Required[str]
  tlds: NotRequired[str]
  style: NotRequired[Literal["brandable", "keyword-rich", "short", "pronounceable", "techy", "playful", "professional", "minimal"]]
  industry: NotRequired[Literal["tech", "finance", "health", "ecommerce", "education", "media", "saas", "crypto", "ai", "gaming"]]
  language: NotRequired[Literal["en", "zh", "es", "ja", "de", "fr", "pt", "it", "ko", "ru", "ar", "hi", "bn", "id", "ms", "th", "vi", "tr", "pl", "nl", "sv", "da", "no", "fi", "el", "cs", "hu", "ro", "uk", "he"]]
  limit: NotRequired[int]
  check: NotRequired[bool]

SuggestDomainsResponse = SuggestResponse

class ValidateDmarcParams(TypedDict):
  record: NotRequired[str]
  domain: NotRequired[str]

ValidateDmarcResponse = Dict[str, Any]

class ValidatePhoneNumberParams(TypedDict):
  phone: Required[str]
  default_country: NotRequired[str]
  expected_country: NotRequired[str]
  dialing_from_country: NotRequired[str]
  language: NotRequired[str]

ValidatePhoneNumberResponse = PhoneValidationResponse

class ValidatePhoneNumbersBulkParams(TypedDict):
  phones: Required[List[Union[str, Dict[str, Any]]]]
  default_country: NotRequired[str]
  expected_country: NotRequired[str]
  dialing_from_country: NotRequired[str]
  language: NotRequired[str]

ValidatePhoneNumbersBulkResponse = PhoneValidationBulkResponse

class ValidateSpfParams(TypedDict):
  record: NotRequired[str]
  domain: NotRequired[str]

ValidateSpfResponse = Dict[str, Any]

class VerifyEmailParams(TypedDict):
  email: Required[str]
  full: NotRequired[bool]

VerifyEmailResponse = Dict[str, Any]

class VerifyEmailBulkParams(TypedDict):
  emails: Required[List[str]]
  full: NotRequired[bool]

VerifyEmailBulkResponse = Dict[str, Any]
