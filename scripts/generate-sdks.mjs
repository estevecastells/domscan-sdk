import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const manifest = JSON.parse(
  await BunLikeReadFile(path.join(root, 'manifest', 'endpoints.json'))
);

function BunLikeReadFile(file) {
  return import('node:fs/promises').then(({ readFile }) => readFile(file, 'utf8'));
}

const namespaces = Object.entries(manifest);
const namespaceClassNames = {
  availability: 'Availability',
  domain: 'Domain',
  dns: 'Dns',
  security: 'Security',
  intelligence: 'Intelligence',
  social: 'Social',
  osint: 'Osint',
  pricing: 'Pricing',
  recipes: 'Recipes',
  meta: 'Meta',
};

function toSnakeCase(value) {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function toPascalCase(value) {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[^a-zA-Z0-9]+/g, ' ')
    .trim()
    .split(/\s+/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

function toCamelCase(value) {
  const pascal = toPascalCase(value);
  return pascal.charAt(0).toLowerCase() + pascal.slice(1);
}

function endpointLiteral(endpoint) {
  return JSON.stringify(endpoint);
}

function renderRootReadme() {
  return `# DomScan SDKs

Public home for the official DomScan API client libraries.

## Official SDKs

- [Node.js / TypeScript SDK](./node)
- [Python SDK](./python)
- [Go SDK](./go)
- [Ruby SDK](./ruby)
- [PHP SDK](./php)
- [Java SDK](./java)
- [C# SDK](./csharp)
- [Kotlin SDK](./kotlin)
- [Swift SDK](./swift)
- [Rust SDK](./rust)

## Package Names

- Node.js / TypeScript: \`@domscan/sdk\`
- Python: \`domscan-sdk\`
- Go module: \`github.com/estevecastells/domscan-sdk/go\`
- Ruby gem: \`domscan-sdk\`
- PHP package: \`estevecastells/domscan-sdk\`
- Java artifact: \`net.domscan:domscan-sdk-java\`
- C# package: \`DomScan.Sdk\`
- Kotlin artifact: \`net.domscan:domscan-sdk-kotlin\`
- Swift package: \`DomScan\`
- Rust crate: \`domscan-sdk\`

## Included Resources

- [API Docs](https://domscan.net/docs)
- [OpenAPI spec](https://domscan.net/v1/openapi.json)
- [Swagger spec](https://domscan.net/v1/swagger.json)
- [Postman collection](https://domscan.net/v1/postman.json)
- [MCP integration](https://domscan.net/mcp-domain-checker)

## Notes

- These SDKs are generated from DomScan's internal API registry and synced into this public repository.
- The public packages currently cover 79 public non-session endpoints across availability, DNS, WHOIS, security, pricing, recipes, and intelligence workflows.
- The committed \`manifest/endpoints.json\` file is the public endpoint source used to render the generated SDK packages in this repository.
`;
}

function renderLanguageReadme(language, install, example, notes = []) {
  return `# DomScan ${language} SDK

Official ${language} client for the [DomScan API](https://domscan.net/docs).

This SDK is generated from the shared endpoint manifest in this repository and covers the same 79 public non-session endpoints as the other official DomScan SDKs.

## Installation

\`\`\`bash
${install}
\`\`\`

## Quick Start

\`\`\`${example.lang}
${example.code}
\`\`\`

## Resources

- Docs: [https://domscan.net/docs](https://domscan.net/docs)
- OpenAPI: [https://domscan.net/v1/openapi.json](https://domscan.net/v1/openapi.json)
- SDK hub: [../README.md](../README.md)
${notes.length ? `\n## Notes\n\n${notes.map((note) => `- ${note}`).join('\n')}\n` : ''}`;
}

function renderGoClient() {
  const services = namespaces
    .map(([namespace, methods]) => {
      const serviceName = `${namespaceClassNames[namespace]}Service`;
      const methodLines = Object.entries(methods)
        .map(([name, endpoint]) => `// ${endpoint.description}
func (s *${serviceName}) ${toPascalCase(name)}(ctx context.Context, params Params) (any, error) {
\treturn s.client.request(ctx, endpointDefinition{
\t\tMethod: ${JSON.stringify(endpoint.method)},
\t\tPath: ${JSON.stringify(endpoint.path)},
\t\tPathParams: []string{${endpoint.pathParams.map((param) => JSON.stringify(param)).join(', ')}},
\t\tQueryParams: []string{${endpoint.queryParams.map((param) => JSON.stringify(param)).join(', ')}},
\t\tHasBody: ${endpoint.hasBody},
\t}, params)
}`).join('\n\n');

      return `type ${serviceName} struct {
\tclient *Client
}

${methodLines}`;
    })
    .join('\n\n');

  const serviceFields = namespaces
    .map(([namespace]) => `\t${namespaceClassNames[namespace]} *${namespaceClassNames[namespace]}Service`)
    .join('\n');

  const serviceInit = namespaces
    .map(([namespace]) => `\tclient.${namespaceClassNames[namespace]} = &${namespaceClassNames[namespace]}Service{client: client}`)
    .join('\n');

  return `package domscan

import (
\t"bytes"
\t"context"
\t"encoding/json"
\t"fmt"
\t"io"
\t"net/http"
\t"net/url"
\t"os"
\t"reflect"
\t"strings"
\t"time"
)

type Params map[string]any

type Config struct {
\tAPIKey     string
\tBaseURL    string
\tTimeout    time.Duration
\tHeaders    map[string]string
\tHTTPClient *http.Client
\tUserAgent  string
}

type APIError struct {
\tStatus    int
\tCode      string
\tMessage   string
\tDetails   any
\tRequestID string
}

func (e *APIError) Error() string {
\tif e.Message != "" {
\t\treturn e.Message
\t}
\treturn fmt.Sprintf("DomScan request failed with status %d", e.Status)
}

type endpointDefinition struct {
\tMethod      string
\tPath        string
\tPathParams  []string
\tQueryParams []string
\tHasBody     bool
}

type Client struct {
\tapiKey         string
\tbaseURL        string
\ttimeout        time.Duration
\tuserAgent      string
\thttpClient     *http.Client
\tdefaultHeaders map[string]string
${serviceFields}
}

func NewClient(config *Config) *Client {
\tbaseURL := "https://domscan.net"
\ttimeout := 10 * time.Second
\theaders := map[string]string{}
\tapiKey := os.Getenv("DOMSCAN_API_KEY")
\tuserAgent := "domscan-go/0.1.0"
\tvar httpClient *http.Client

\tif config != nil {
\t\tif config.APIKey != "" {
\t\t\tapiKey = config.APIKey
\t\t}
\t\tif config.BaseURL != "" {
\t\t\tbaseURL = strings.TrimRight(config.BaseURL, "/")
\t\t}
\t\tif config.Timeout > 0 {
\t\t\ttimeout = config.Timeout
\t\t}
\t\tif config.Headers != nil {
\t\t\theaders = config.Headers
\t\t}
\t\tif config.UserAgent != "" {
\t\t\tuserAgent = config.UserAgent
\t\t}
\t\thttpClient = config.HTTPClient
\t}

\tif httpClient == nil {
\t\thttpClient = &http.Client{Timeout: timeout}
\t}

\tclient := &Client{
\t\tapiKey:         apiKey,
\t\tbaseURL:        baseURL,
\t\ttimeout:        timeout,
\t\tuserAgent:      userAgent,
\t\thttpClient:     httpClient,
\t\tdefaultHeaders: headers,
\t}

${serviceInit}
\treturn client
}

func (c *Client) request(ctx context.Context, endpoint endpointDefinition, params Params) (any, error) {
\trequestPath := endpoint.Path
\tconsumedKeys := map[string]bool{}

\tfor _, pathParam := range endpoint.PathParams {
\t\tvalue, ok := params[pathParam]
\t\tif !ok || value == nil {
\t\t\treturn nil, fmt.Errorf("missing required path parameter: %s", pathParam)
\t\t}
\t\trequestPath = strings.ReplaceAll(requestPath, ":"+pathParam, url.PathEscape(fmt.Sprint(value)))
\t\tconsumedKeys[pathParam] = true
\t}

\tremaining := map[string]any{}
\tfor key, value := range params {
\t\tif consumedKeys[key] || value == nil {
\t\t\tcontinue
\t\t}
\t\tremaining[key] = value
\t}

\tqueryPayload := map[string]any{}
\tif endpoint.HasBody {
\t\tfor _, queryKey := range endpoint.QueryParams {
\t\t\tif value, ok := remaining[queryKey]; ok {
\t\t\t\tqueryPayload[queryKey] = value
\t\t\t}
\t\t}
\t} else {
\t\tfor key, value := range remaining {
\t\t\tqueryPayload[key] = value
\t\t}
\t}

\trequestURL, err := url.Parse(c.baseURL + requestPath)
\tif err != nil {
\t\treturn nil, err
\t}

\tvalues := requestURL.Query()
\tfor key, value := range queryPayload {
\t\tvalues.Set(key, serializeQueryValue(value))
\t}
\trequestURL.RawQuery = values.Encode()

\tbodyPayload := map[string]any{}
\tif endpoint.HasBody {
\t\tqueryKeys := map[string]bool{}
\t\tfor _, queryKey := range endpoint.QueryParams {
\t\t\tqueryKeys[queryKey] = true
\t\t}
\t\tfor key, value := range remaining {
\t\t\tif !queryKeys[key] {
\t\t\t\tbodyPayload[key] = value
\t\t\t}
\t\t}
\t}

\tvar bodyReader io.Reader
\tif endpoint.HasBody {
\t\tencoded, err := json.Marshal(bodyPayload)
\t\tif err != nil {
\t\t\treturn nil, err
\t\t}
\t\tbodyReader = bytes.NewReader(encoded)
\t}

\treq, err := http.NewRequestWithContext(ctx, endpoint.Method, requestURL.String(), bodyReader)
\tif err != nil {
\t\treturn nil, err
\t}

\treq.Header.Set("Accept", "application/json")
\treq.Header.Set("X-DomScan-SDK", c.userAgent)
\tif endpoint.HasBody {
\t\treq.Header.Set("Content-Type", "application/json")
\t}
\tif c.apiKey != "" {
\t\treq.Header.Set("Authorization", "Bearer "+c.apiKey)
\t\treq.Header.Set("X-API-Key", c.apiKey)
\t}
\tfor key, value := range c.defaultHeaders {
\t\treq.Header.Set(key, value)
\t}

\tresponse, err := c.httpClient.Do(req)
\tif err != nil {
\t\treturn nil, err
\t}
\tdefer response.Body.Close()

\tpayloadBytes, err := io.ReadAll(response.Body)
\tif err != nil {
\t\treturn nil, err
\t}

\tpayload := decodePayload(payloadBytes, response.Header.Get("Content-Type"))
\tif response.StatusCode >= 400 {
\t\tapiError := &APIError{
\t\t\tStatus:    response.StatusCode,
\t\t\tDetails:   payload,
\t\t\tRequestID: response.Header.Get("X-Request-Id"),
\t\t}
\t\tif parsed, ok := payload.(map[string]any); ok {
\t\t\tif nested, ok := parsed["error"].(map[string]any); ok {
\t\t\t\tif code, ok := nested["code"].(string); ok {
\t\t\t\t\tapiError.Code = code
\t\t\t\t}
\t\t\t\tif message, ok := nested["message"].(string); ok {
\t\t\t\t\tapiError.Message = message
\t\t\t\t}
\t\t\t}
\t\t}
\t\treturn nil, apiError
\t}

\treturn payload, nil
}

func decodePayload(payload []byte, contentType string) any {
\tif strings.Contains(contentType, "application/json") {
\t\tvar decoded any
\t\tif err := json.Unmarshal(payload, &decoded); err == nil {
\t\t\treturn decoded
\t\t}
\t}
\treturn string(payload)
}

func serializeQueryValue(value any) string {
\tswitch typed := value.(type) {
\tcase string:
\t\treturn typed
\tcase bool:
\t\tif typed {
\t\t\treturn "true"
\t\t}
\t\treturn "false"
\tcase fmt.Stringer:
\t\treturn typed.String()
\tcase time.Time:
\t\treturn typed.Format(time.RFC3339)
\t}

\trv := reflect.ValueOf(value)
\tif rv.IsValid() && (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) {
\t\tparts := make([]string, 0, rv.Len())
\t\tfor i := 0; i < rv.Len(); i++ {
\t\t\tparts = append(parts, serializeQueryValue(rv.Index(i).Interface()))
\t\t}
\t\treturn strings.Join(parts, ",")
\t}

\tif payload, err := json.Marshal(value); err == nil && (rv.Kind() == reflect.Map || rv.Kind() == reflect.Struct) {
\t\treturn string(payload)
\t}

\treturn fmt.Sprint(value)
}

${services}
`;
}

function renderRubyClient() {
  const services = namespaces
    .map(([namespace, methods]) => {
      const serviceName = `${namespaceClassNames[namespace]}Service`;
      const methodLines = Object.entries(methods).map(([name, endpoint]) => `    # ${endpoint.description}
    def ${toSnakeCase(name)}(params = {})
      @client.request(${endpointLiteral(endpoint)}, params)
    end`).join('\n\n');

      return `  class ${serviceName} < Service
${methodLines}
  end`;
    })
    .join('\n\n');

  const serviceReaders = namespaces.map(([namespace]) => `:${namespace}`).join(', ');
  const serviceInit = namespaces
    .map(([namespace]) => `      @${namespace} = ${namespaceClassNames[namespace]}Service.new(self)`)
    .join('\n');

  return `# frozen_string_literal: true

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
    attr_reader ${serviceReaders}

    def initialize(api_key: ENV["DOMSCAN_API_KEY"], base_url: "https://domscan.net", timeout: 10, headers: {}, user_agent: "domscan-ruby/0.1.0")
      @api_key = api_key
      @base_url = base_url.sub(%r{/+$}, "")
      @timeout = timeout
      @headers = headers
      @user_agent = user_agent
${serviceInit}
    end

    def request(endpoint, params = {})
      request_path = endpoint.fetch("path")
      consumed_keys = []

      endpoint.fetch("pathParams").each do |path_param|
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

      query_payload = if endpoint.fetch("hasBody")
        endpoint.fetch("queryParams").each_with_object({}) do |query_key, memo|
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

      request_class = case endpoint.fetch("method")
      when "GET" then Net::HTTP::Get
      when "POST" then Net::HTTP::Post
      when "PUT" then Net::HTTP::Put
      when "PATCH" then Net::HTTP::Patch
      when "DELETE" then Net::HTTP::Delete
      else
        raise ArgumentError, "Unsupported HTTP method: #{endpoint.fetch("method")}"
      end

      request = request_class.new(uri)
      request["Accept"] = "application/json"
      request["X-DomScan-SDK"] = @user_agent
      request["Authorization"] = "Bearer #{@api_key}" if @api_key
      request["X-API-Key"] = @api_key if @api_key
      @headers.each { |key, value| request[key] = value }

      if endpoint.fetch("hasBody")
        body_payload = remaining.reject { |key, _value| endpoint.fetch("queryParams").include?(key) }
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

${services}
end
`;
}

function renderPhpClient() {
  const services = namespaces
    .map(([namespace, methods]) => {
      const serviceName = `${namespaceClassNames[namespace]}Service`;
      const methodLines = Object.entries(methods).map(([name, endpoint]) => `    /**
     * ${endpoint.description}
     */
    public function ${toCamelCase(name)}(array $params = []): mixed
    {
        return $this->client->request(${phpArrayForEndpoint(endpoint)}, $params);
    }`).join('\n\n');

      return `final class ${serviceName} extends AbstractService
{
${methodLines}
}`;
    })
    .join('\n\n');

  const serviceProperties = namespaces
    .map(([namespace]) => `    private ${namespaceClassNames[namespace]}Service $${namespace};`)
    .join('\n');
  const serviceInit = namespaces
    .map(([namespace]) => `        $this->${namespace} = new ${namespaceClassNames[namespace]}Service($this);`)
    .join('\n');
  const serviceAccessors = namespaces
    .map(([namespace]) => `    public function ${namespace}(): ${namespaceClassNames[namespace]}Service
    {
        return $this->${namespace};
    }`).join('\n\n');

  return `<?php

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
${serviceProperties}

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
${serviceInit}
    }

${serviceAccessors}

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
        foreach (explode("\\r\\n", $headerText) as $headerLine) {
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
        } catch (\\JsonException) {
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

        if ($value instanceof \\DateTimeInterface) {
            return $value->format(DATE_ATOM);
        }

        if (is_object($value)) {
            return json_encode($value, JSON_THROW_ON_ERROR);
        }

        return (string) $value;
    }
}

${services}
`;
}

function phpArrayForEndpoint(endpoint) {
  return `[
            'method' => ${JSON.stringify(endpoint.method)},
            'path' => ${JSON.stringify(endpoint.path)},
            'pathParams' => [${endpoint.pathParams.map((param) => JSON.stringify(param)).join(', ')}],
            'queryParams' => [${endpoint.queryParams.map((param) => JSON.stringify(param)).join(', ')}],
            'hasBody' => ${endpoint.hasBody ? 'true' : 'false'},
        ]`;
}

function renderJavaClient() {
  const services = namespaces.map(([namespace, methods]) => {
    const className = `${namespaceClassNames[namespace]}Service`;
    const methodLines = Object.entries(methods).map(([name, endpoint]) => `        /**
         * ${endpoint.description}
         */
        public String ${toCamelCase(name)}(Map<String, Object> params) throws IOException, InterruptedException {
            return client.request(new Endpoint(
                ${JSON.stringify(endpoint.method)},
                ${JSON.stringify(endpoint.path)},
                List.of(${endpoint.pathParams.map((param) => JSON.stringify(param)).join(', ')}),
                List.of(${endpoint.queryParams.map((param) => JSON.stringify(param)).join(', ')}),
                ${endpoint.hasBody}
            ), params);
        }`).join('\n\n');

    return `    public static final class ${className} extends Service {
        private ${className}(DomScanClient client) {
            super(client);
        }

${methodLines}
    }`;
  }).join('\n\n');

  const serviceFields = namespaces.map(([namespace]) => `    public final ${namespaceClassNames[namespace]}Service ${namespace};`).join('\n');
  const serviceInit = namespaces.map(([namespace]) => `        this.${namespace} = new ${namespaceClassNames[namespace]}Service(this);`).join('\n');

  return `package net.domscan;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

public final class DomScanClient {
    private final String apiKey;
    private final String baseUrl;
    private final Duration timeout;
    private final String userAgent;
    private final HttpClient httpClient;
    private final Map<String, String> defaultHeaders;
${serviceFields}

    public DomScanClient() {
        this(new Builder());
    }

    private DomScanClient(Builder builder) {
        this.apiKey = builder.apiKey != null ? builder.apiKey : System.getenv("DOMSCAN_API_KEY");
        this.baseUrl = trimTrailingSlash(builder.baseUrl != null ? builder.baseUrl : "https://domscan.net");
        this.timeout = builder.timeout != null ? builder.timeout : Duration.ofSeconds(10);
        this.userAgent = builder.userAgent != null ? builder.userAgent : "domscan-java/0.1.0";
        this.httpClient = builder.httpClient != null ? builder.httpClient : HttpClient.newBuilder().connectTimeout(this.timeout).build();
        this.defaultHeaders = builder.headers != null ? new LinkedHashMap<>(builder.headers) : new LinkedHashMap<>();
${serviceInit}
    }

    private String request(Endpoint endpoint, Map<String, Object> params) throws IOException, InterruptedException {
        Map<String, Object> source = params != null ? new LinkedHashMap<>(params) : new LinkedHashMap<>();
        String requestPath = endpoint.path;
        Map<String, Boolean> consumedKeys = new LinkedHashMap<>();

        for (String pathParam : endpoint.pathParams) {
            Object value = source.get(pathParam);
            if (value == null) {
                throw new IllegalArgumentException("Missing required path parameter: " + pathParam);
            }
            requestPath = requestPath.replace(":" + pathParam, encode(value));
            consumedKeys.put(pathParam, true);
        }

        Map<String, Object> remaining = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            if (entry.getValue() == null || consumedKeys.containsKey(entry.getKey())) {
                continue;
            }
            remaining.put(entry.getKey(), entry.getValue());
        }

        Map<String, Object> queryPayload = new LinkedHashMap<>();
        if (endpoint.hasBody) {
            for (String queryKey : endpoint.queryParams) {
                if (remaining.containsKey(queryKey)) {
                    queryPayload.put(queryKey, remaining.get(queryKey));
                }
            }
        } else {
            queryPayload.putAll(remaining);
        }

        StringBuilder urlBuilder = new StringBuilder(baseUrl).append(requestPath);
        if (!queryPayload.isEmpty()) {
            StringJoiner joiner = new StringJoiner("&");
            for (Map.Entry<String, Object> entry : queryPayload.entrySet()) {
                joiner.add(encode(entry.getKey()) + "=" + encode(serializeQueryValue(entry.getValue())));
            }
            urlBuilder.append("?").append(joiner);
        }

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(urlBuilder.toString()))
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("X-DomScan-SDK", userAgent);

        if (apiKey != null && !apiKey.isBlank()) {
            requestBuilder.header("Authorization", "Bearer " + apiKey);
            requestBuilder.header("X-API-Key", apiKey);
        }

        for (Map.Entry<String, String> header : defaultHeaders.entrySet()) {
            requestBuilder.header(header.getKey(), header.getValue());
        }

        if (endpoint.hasBody) {
            Map<String, Object> bodyPayload = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : remaining.entrySet()) {
                if (!endpoint.queryParams.contains(entry.getKey())) {
                    bodyPayload.put(entry.getKey(), entry.getValue());
                }
            }
            requestBuilder.header("Content-Type", "application/json");
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.ofString(toJson(bodyPayload)));
        } else {
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        String payload = response.body();
        if (response.statusCode() < 400) {
            return payload;
        }

        throw new APIError(
            extractJsonField(payload, "message", "DomScan request failed with status " + response.statusCode()),
            response.statusCode(),
            extractJsonField(payload, "code", null),
            payload,
            response.headers().firstValue("x-request-id").orElse(null)
        );
    }

    private static String trimTrailingSlash(String value) {
        return value.replaceAll("/+$", "");
    }

    private static String encode(Object value) {
        return URLEncoder.encode(String.valueOf(value), StandardCharsets.UTF_8);
    }

    private static String serializeQueryValue(Object value) {
        if (value instanceof Iterable<?> iterable) {
            List<String> parts = new ArrayList<>();
            for (Object item : iterable) {
                if (item != null) {
                    parts.add(serializeQueryValue(item));
                }
            }
            return String.join(",", parts);
        }
        if (value instanceof Boolean boolValue) {
            return boolValue ? "true" : "false";
        }
        if (value instanceof TemporalAccessor) {
            return value.toString();
        }
        if (value instanceof Map<?, ?> || value instanceof List<?>) {
            return toJson(value);
        }
        return String.valueOf(value);
    }

    private static String toJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String stringValue) {
            return quote(stringValue);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        if (value instanceof Map<?, ?> mapValue) {
            StringJoiner joiner = new StringJoiner(",", "{", "}");
            for (Map.Entry<?, ?> entry : mapValue.entrySet()) {
                joiner.add(quote(String.valueOf(entry.getKey())) + ":" + toJson(entry.getValue()));
            }
            return joiner.toString();
        }
        if (value instanceof Iterable<?> iterable) {
            StringJoiner joiner = new StringJoiner(",", "[", "]");
            for (Object item : iterable) {
                joiner.add(toJson(item));
            }
            return joiner.toString();
        }
        return quote(String.valueOf(value));
    }

    private static String quote(String value) {
        return "\\""+ value
            .replace("\\\\", "\\\\\\\\")
            .replace("\\"", "\\\\\\"")
            .replace("\\n", "\\\\n")
            .replace("\\r", "\\\\r")
            .replace("\\t", "\\\\t") + "\\"";
    }

    private static String extractJsonField(String json, String field, String fallback) {
        String needle = "\\"" + field + "\\":\\"";
        int start = json.indexOf(needle);
        if (start < 0) {
            return fallback;
        }
        int valueStart = start + needle.length();
        int valueEnd = json.indexOf('"', valueStart);
        if (valueEnd < 0) {
            return fallback;
        }
        return json.substring(valueStart, valueEnd);
    }

    public static final class Builder {
        private String apiKey;
        private String baseUrl;
        private Duration timeout;
        private String userAgent;
        private HttpClient httpClient;
        private Map<String, String> headers;

        public Builder apiKey(String value) {
            this.apiKey = value;
            return this;
        }

        public Builder baseUrl(String value) {
            this.baseUrl = value;
            return this;
        }

        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        public Builder userAgent(String value) {
            this.userAgent = value;
            return this;
        }

        public Builder httpClient(HttpClient value) {
            this.httpClient = value;
            return this;
        }

        public Builder headers(Map<String, String> value) {
            this.headers = value;
            return this;
        }

        public DomScanClient build() {
            return new DomScanClient(this);
        }
    }

    public abstract static class Service {
        protected final DomScanClient client;

        protected Service(DomScanClient client) {
            this.client = client;
        }
    }

    public static final class APIError extends IOException {
        public final int status;
        public final String code;
        public final String details;
        public final String requestId;

        public APIError(String message, int status, String code, String details, String requestId) {
            super(message);
            this.status = status;
            this.code = code;
            this.details = details;
            this.requestId = requestId;
        }
    }

    private record Endpoint(String method, String path, List<String> pathParams, List<String> queryParams, boolean hasBody) {}

${services}
}
`;
}

function renderCSharpClient() {
  const services = namespaces.map(([namespace, methods]) => {
    const className = `${namespaceClassNames[namespace]}Service`;
    const methodLines = Object.entries(methods).map(([name, endpoint]) => `        /// <summary>
        /// ${endpoint.description}
        /// </summary>
        public Task<JsonNode?> ${toPascalCase(name)}Async(
            IDictionary<string, object?>? parameters = null,
            CancellationToken cancellationToken = default
        ) => _client.RequestAsync(new EndpointDefinition(
            ${JSON.stringify(endpoint.method)},
            ${JSON.stringify(endpoint.path)},
            new[] { ${endpoint.pathParams.map((param) => JSON.stringify(param)).join(', ')} },
            new[] { ${endpoint.queryParams.map((param) => JSON.stringify(param)).join(', ')} },
            ${endpoint.hasBody ? 'true' : 'false'}
        ), parameters, cancellationToken);`).join('\n\n');

    return `public sealed class ${className}
{
    private readonly DomScanClient _client;

    internal ${className}(DomScanClient client)
    {
        _client = client;
    }

${methodLines}
}`;
  }).join('\n\n');

  const serviceProps = namespaces.map(([namespace]) => `    public ${namespaceClassNames[namespace]}Service ${namespaceClassNames[namespace]} { get; }`).join('\n');
  const serviceInit = namespaces.map(([namespace]) => `        ${namespaceClassNames[namespace]} = new ${namespaceClassNames[namespace]}Service(this);`).join('\n');

  return `using System;
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

${serviceProps}

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
${serviceInit}
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

${services}
`;
}

function renderKotlinClient() {
  const services = namespaces.map(([namespace, methods]) => {
    const className = `${namespaceClassNames[namespace]}Service`;
    const methodLines = Object.entries(methods).map(([name, endpoint]) => `    /**
     * ${endpoint.description}
     */
    fun ${toCamelCase(name)}(params: Map<String, Any?> = emptyMap()): String =
        client.request(
            EndpointDefinition(
                method = ${JSON.stringify(endpoint.method)},
                path = ${JSON.stringify(endpoint.path)},
                pathParams = listOf(${endpoint.pathParams.map((param) => JSON.stringify(param)).join(', ')}),
                queryParams = listOf(${endpoint.queryParams.map((param) => JSON.stringify(param)).join(', ')}),
                hasBody = ${endpoint.hasBody ? 'true' : 'false'}
            ),
            params
        )`).join('\n\n');

    return `class ${className}(private val client: DomScanClient) {
${methodLines}
}`;
  }).join('\n\n');

  const serviceProps = namespaces.map(([namespace]) => `    val ${namespace}: ${namespaceClassNames[namespace]}Service = ${namespaceClassNames[namespace]}Service(this)`).join('\n');
  const kotlinQueryJoinLine = '                        "${encode(key)}=${encode(serializeQueryValue(value))}"';
  const kotlinStatusMessageLine = '            extractJsonField(response.body(), "message") ?: "DomScan request failed with status ${response.statusCode()}",';
  const kotlinJsonStringLine = '        is String -> "\\"${value.replace("\\\\", "\\\\\\\\").replace("\\\"", "\\\\\\\"")}\\""';
  const kotlinJsonMapEntryLine = '            "\\"${key.toString()}\\":${toJson(item)}"';
  const kotlinJsonElseLine = '        else -> "\\"${value.toString()}\\""';

  return `package net.domscan

import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.temporal.TemporalAccessor

data class EndpointDefinition(
    val method: String,
    val path: String,
    val pathParams: List<String>,
    val queryParams: List<String>,
    val hasBody: Boolean
)

class DomScanApiException(
    message: String,
    val status: Int,
    val codeValue: String? = null,
    val details: String? = null,
    val requestId: String? = null
) : RuntimeException(message)

class DomScanClient(
    apiKey: String? = System.getenv("DOMSCAN_API_KEY"),
    baseUrl: String = "https://domscan.net",
    private val timeout: Duration = Duration.ofSeconds(10),
    private val headers: Map<String, String> = emptyMap(),
    private val userAgent: String = "domscan-kotlin/0.1.0",
    private val httpClient: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
) {
    private val apiKey: String? = apiKey?.takeUnless { it.isBlank() }
    private val baseUrl: String = baseUrl.trimEnd('/')

${serviceProps}

    internal fun request(endpoint: EndpointDefinition, params: Map<String, Any?> = emptyMap()): String {
        var requestPath = endpoint.path
        val remaining = params.toMutableMap()

        endpoint.pathParams.forEach { pathParam ->
            val value = remaining.remove(pathParam)
                ?: throw IllegalArgumentException("Missing required path parameter: $pathParam")
            requestPath = requestPath.replace(":$pathParam", encode(value.toString()))
        }

        val queryPayload = if (endpoint.hasBody) {
            remaining.filterKeys { endpoint.queryParams.contains(it) && remaining[it] != null }
        } else {
            remaining.filterValues { it != null }
        }

        val url = buildString {
            append(baseUrl)
            append(requestPath)
            if (queryPayload.isNotEmpty()) {
                append('?')
                append(
                    queryPayload.entries.joinToString("&") { (key, value) ->
${kotlinQueryJoinLine}
                    }
                )
            }
        }

        val requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("X-DomScan-SDK", userAgent)

        if (!apiKey.isNullOrBlank()) {
            requestBuilder.header("Authorization", "Bearer $apiKey")
            requestBuilder.header("X-API-Key", apiKey)
        }

        headers.forEach { (key, value) -> requestBuilder.header(key, value) }

        if (endpoint.hasBody) {
            val bodyPayload = remaining.filterKeys { !endpoint.queryParams.contains(it) && remaining[it] != null }
            requestBuilder.header("Content-Type", "application/json")
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.ofString(toJson(bodyPayload)))
        } else {
            requestBuilder.method(endpoint.method, HttpRequest.BodyPublishers.noBody())
        }

        val response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() < 400) {
            return response.body()
        }

        throw DomScanApiException(
${kotlinStatusMessageLine}
            response.statusCode(),
            extractJsonField(response.body(), "code"),
            response.body(),
            response.headers().firstValue("x-request-id").orElse(null)
        )
    }

    private fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

    private fun serializeQueryValue(value: Any?): String = when (value) {
        null -> ""
        is String -> value
        is Boolean -> if (value) "true" else "false"
        is TemporalAccessor -> value.toString()
        is Iterable<*> -> value.filterNotNull().joinToString(",") { serializeQueryValue(it) }
        is Map<*, *> -> toJson(value)
        else -> value.toString()
    }

    private fun toJson(value: Any?): String = when (value) {
        null -> "null"
${kotlinJsonStringLine}
        is Number, is Boolean -> value.toString()
        is Map<*, *> -> value.entries.joinToString(prefix = "{", postfix = "}") { (key, item) ->
${kotlinJsonMapEntryLine}
        }
        is Iterable<*> -> value.joinToString(prefix = "[", postfix = "]") { item -> toJson(item) }
${kotlinJsonElseLine}
    }

    private fun extractJsonField(json: String, field: String): String? {
        val marker = "\\"$field\\":\\""
        val start = json.indexOf(marker)
        if (start < 0) {
            return null
        }
        val valueStart = start + marker.length
        val valueEnd = json.indexOf('"', valueStart)
        return if (valueEnd < 0) null else json.substring(valueStart, valueEnd)
    }
}

${services}
`;
}

function renderSwiftClient() {
  const services = namespaces.map(([namespace, methods]) => {
    const className = `${namespaceClassNames[namespace]}Service`;
    const methodLines = Object.entries(methods).map(([name, endpoint]) => `    /// ${endpoint.description}
    public func ${toCamelCase(name)}(_ params: [String: Any?] = [:]) async throws -> Any {
        try await client.request(
            endpoint: EndpointDefinition(
                method: ${JSON.stringify(endpoint.method)},
                path: ${JSON.stringify(endpoint.path)},
                pathParams: [${endpoint.pathParams.map((param) => JSON.stringify(param)).join(', ')}],
                queryParams: [${endpoint.queryParams.map((param) => JSON.stringify(param)).join(', ')}],
                hasBody: ${endpoint.hasBody ? 'true' : 'false'}
            ),
            params: params
        )
    }`).join('\n\n');

    return `public final class ${className} {
    private let client: DomScanClient

    init(client: DomScanClient) {
        self.client = client
    }

${methodLines}
}`;
  }).join('\n\n');

  const serviceProps = namespaces.map(([namespace]) => `    public lazy var ${namespace}: ${namespaceClassNames[namespace]}Service = ${namespaceClassNames[namespace]}Service(client: self)`).join('\n');

  return `import Foundation

public struct EndpointDefinition {
    let method: String
    let path: String
    let pathParams: [String]
    let queryParams: [String]
    let hasBody: Bool
}

public struct DomScanAPIError: Error {
    public let status: Int
    public let code: String?
    public let message: String
    public let details: Any
    public let requestId: String?
}

public final class DomScanClient {
    private let apiKey: String?
    private let baseURL: String
    private let timeout: TimeInterval
    private let userAgent: String
    private let headers: [String: String]

${serviceProps}

    public init(
        apiKey: String? = ProcessInfo.processInfo.environment["DOMSCAN_API_KEY"],
        baseURL: String = "https://domscan.net",
        timeout: TimeInterval = 10,
        headers: [String: String] = [:],
        userAgent: String = "domscan-swift/0.1.0"
    ) {
        self.apiKey = apiKey
        self.baseURL = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        self.timeout = timeout
        self.headers = headers
        self.userAgent = userAgent
    }

    func request(endpoint: EndpointDefinition, params: [String: Any?]) async throws -> Any {
        var requestPath = endpoint.path
        var remaining = params

        for pathParam in endpoint.pathParams {
            guard let rawValue = remaining.removeValue(forKey: pathParam) ?? nil else {
                throw NSError(domain: "DomScan", code: 0, userInfo: [NSLocalizedDescriptionKey: "Missing required path parameter: \\(pathParam)"])
            }
            requestPath = requestPath.replacingOccurrences(of: ":\\(pathParam)", with: String(describing: rawValue).addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? "")
        }

        var components = URLComponents(string: baseURL + requestPath)!
        let queryPayload: [String: Any?]
        if endpoint.hasBody {
            queryPayload = remaining.filter { endpoint.queryParams.contains($0.key) && $0.value != nil }
        } else {
            queryPayload = remaining.filter { $0.value != nil }
        }

        if !queryPayload.isEmpty {
            components.queryItems = queryPayload.compactMap { key, value in
                guard let value else { return nil }
                return URLQueryItem(name: key, value: serializeQueryValue(value))
            }
        }

        var request = URLRequest(url: components.url!)
        request.httpMethod = endpoint.method
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(userAgent, forHTTPHeaderField: "X-DomScan-SDK")
        if let apiKey, !apiKey.isEmpty {
            request.setValue("Bearer \\(apiKey)", forHTTPHeaderField: "Authorization")
            request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        }
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        if endpoint.hasBody {
            let bodyPayload = remaining.filter { !endpoint.queryParams.contains($0.key) && $0.value != nil }
                .mapValues { $0! }
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: bodyPayload, options: [])
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        let httpResponse = response as! HTTPURLResponse
        let payload = decodePayload(data)
        if httpResponse.statusCode < 400 {
            return payload
        }

        let errorObject = payload as? [String: Any]
        let nested = errorObject?["error"] as? [String: Any]
        throw DomScanAPIError(
            status: httpResponse.statusCode,
            code: nested?["code"] as? String,
            message: nested?["message"] as? String ?? "DomScan request failed with status \\(httpResponse.statusCode)",
            details: payload,
            requestId: httpResponse.value(forHTTPHeaderField: "x-request-id")
        )
    }

    private func decodePayload(_ data: Data) -> Any {
        (try? JSONSerialization.jsonObject(with: data, options: [])) ?? String(data: data, encoding: .utf8) ?? ""
    }

    private func serializeQueryValue(_ value: Any) -> String {
        switch value {
        case let array as [Any]:
            return array.map(serializeQueryValue).joined(separator: ",")
        case let boolean as Bool:
            return boolean ? "true" : "false"
        case let date as Date:
            return ISO8601DateFormatter().string(from: date)
        case let dictionary as [String: Any]:
            if let data = try? JSONSerialization.data(withJSONObject: dictionary, options: []),
               let string = String(data: data, encoding: .utf8) {
                return string
            }
            return ""
        default:
            return String(describing: value)
        }
    }
}

${services}
`;
}

function renderRustClient() {
  const serviceStructs = namespaces.map(([namespace, methods]) => {
    const structName = `${namespaceClassNames[namespace]}Service`;
    const methodLines = Object.entries(methods).map(([name, endpoint]) => `    /// ${endpoint.description}
    pub async fn ${toSnakeCase(name)}(&self, params: Params) -> Result<Value, DomScanError> {
        self.client.request(EndpointDefinition {
            method: ${JSON.stringify(endpoint.method)}.to_string(),
            path: ${JSON.stringify(endpoint.path)}.to_string(),
            path_params: vec![${endpoint.pathParams.map((param) => `${JSON.stringify(param)}.to_string()`).join(', ')}],
            query_params: vec![${endpoint.queryParams.map((param) => `${JSON.stringify(param)}.to_string()`).join(', ')}],
            has_body: ${endpoint.hasBody ? 'true' : 'false'},
        }, params).await
    }`).join('\n\n');

    return `#[derive(Clone)]
pub struct ${structName} {
    client: Arc<InnerClient>,
}

impl ${structName} {
${methodLines}
}`;
  }).join('\n\n');

  const accessors = namespaces.map(([namespace]) => `    pub fn ${namespace}(&self) -> ${namespaceClassNames[namespace]}Service {
        ${namespaceClassNames[namespace]}Service { client: Arc::clone(&self.inner) }
    }`).join('\n\n');

  return `use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
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

${accessors}
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
            let encoded = urlencoding::encode(&serialize_query_value(&value));
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

${serviceStructs}
`;
}

function renderScriptPackage(name, install, example, files) {
  return { name, install, example, files };
}

function renderPackages() {
  const packages = [];

  packages.push(renderScriptPackage('go', 'go get github.com/estevecastells/domscan-sdk/go', {
    lang: 'go',
    code: `package main

import (
    "context"
    "fmt"

    domscan "github.com/estevecastells/domscan-sdk/go/domscan"
)

func main() {
    client := domscan.NewClient(nil)
    response, err := client.Availability.CheckDomainAvailability(context.Background(), domscan.Params{
        "name": "launch",
        "tlds": []string{"com", "io", "ai"},
        "prefer_cache": true,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(response)
}`
  }, {
    'go/README.md': renderLanguageReadme('Go', 'go get github.com/estevecastells/domscan-sdk/go', {
      lang: 'go',
      code: `package main

import (
    "context"
    "fmt"

    domscan "github.com/estevecastells/domscan-sdk/go/domscan"
)

func main() {
    client := domscan.NewClient(nil)
    response, err := client.Availability.CheckDomainAvailability(context.Background(), domscan.Params{
        "name": "launch",
        "tlds": []string{"com", "io", "ai"},
        "prefer_cache": true,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(response)
}`
    }, ['Responses are decoded into Go `any` values via the standard `encoding/json` package.']),
    'go/go.mod': `module github.com/estevecastells/domscan-sdk/go

go 1.22
`,
    'go/domscan/client.go': renderGoClient(),
  }));

  packages.push(renderScriptPackage('ruby', 'bundle add domscan-sdk', { lang: 'ruby', code: `require "domscan"

client = DomScan::Client.new
response = client.availability.check_domain_availability(
  "name" => "launch",
  "tlds" => ["com", "io", "ai"],
  "prefer_cache" => true
)

puts response` }, {
    'ruby/README.md': renderLanguageReadme('Ruby', 'bundle add domscan-sdk', { lang: 'ruby', code: `require "domscan"

client = DomScan::Client.new
response = client.availability.check_domain_availability(
  "name" => "launch",
  "tlds" => ["com", "io", "ai"],
  "prefer_cache" => true
)

puts response` }),
    'ruby/domscan-sdk.gemspec': `Gem::Specification.new do |spec|
  spec.name          = "domscan-sdk"
  spec.version       = "0.1.0"
  spec.authors       = ["DomScan"]
  spec.email         = ["support@domscan.net"]
  spec.summary       = "Official Ruby SDK for the DomScan API"
  spec.homepage      = "https://github.com/estevecastells/domscan-sdk"
  spec.license       = "MIT"
  spec.files         = Dir["lib/**/*.rb"] + ["README.md", "../LICENSE"]
  spec.require_paths = ["lib"]
end
`,
    'ruby/lib/domscan.rb': renderRubyClient(),
  }));

  packages.push(renderScriptPackage('php', 'composer require estevecastells/domscan-sdk', { lang: 'php', code: `<?php

require 'vendor/autoload.php';

$client = new \\DomScan\\Client();
$response = $client->availability()->checkDomainAvailability([
    'name' => 'launch',
    'tlds' => ['com', 'io', 'ai'],
    'prefer_cache' => true,
]);

var_dump($response);` }, {
    'php/README.md': renderLanguageReadme('PHP', 'composer require estevecastells/domscan-sdk', { lang: 'php', code: `<?php

require 'vendor/autoload.php';

$client = new \\DomScan\\Client();
$response = $client->availability()->checkDomainAvailability([
    'name' => 'launch',
    'tlds' => ['com', 'io', 'ai'],
    'prefer_cache' => true,
]);

var_dump($response);` }),
    'php/composer.json': `{
  "name": "estevecastells/domscan-sdk",
  "description": "Official PHP SDK for the DomScan API",
  "type": "library",
  "license": "MIT",
  "autoload": {
    "files": ["src/DomScan.php"]
  },
  "require": {
    "php": "^8.2"
  }
}
`,
    'php/src/DomScan.php': renderPhpClient(),
  }));

  packages.push(renderScriptPackage('java', 'mvn dependency:get -Dartifact=net.domscan:domscan-sdk-java:0.1.0', { lang: 'java', code: `import java.util.Map;
import net.domscan.DomScanClient;

var client = new DomScanClient();
var response = client.availability.checkDomainAvailability(Map.of(
    "name", "launch",
    "tlds", java.util.List.of("com", "io", "ai"),
    "prefer_cache", true
));
System.out.println(response);` }, {
    'java/README.md': renderLanguageReadme('Java', 'mvn dependency:get -Dartifact=net.domscan:domscan-sdk-java:0.1.0', { lang: 'java', code: `import java.util.List;
import java.util.Map;
import net.domscan.DomScanClient;

DomScanClient client = new DomScanClient();
String response = client.availability.checkDomainAvailability(Map.of(
    "name", "launch",
    "tlds", List.of("com", "io", "ai"),
    "prefer_cache", true
));
System.out.println(response);` }, ['The Java SDK currently returns raw JSON strings for responses to keep the dependency footprint minimal.']),
    'java/pom.xml': `<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>net.domscan</groupId>
  <artifactId>domscan-sdk-java</artifactId>
  <version>0.1.0</version>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
  </properties>
</project>
`,
    'java/src/main/java/net/domscan/DomScanClient.java': renderJavaClient(),
  }));

  packages.push(renderScriptPackage('csharp', 'dotnet add package DomScan.Sdk', { lang: 'csharp', code: `using DomScan;

var client = new DomScanClient();
var response = await client.Availability.CheckDomainAvailabilityAsync(new Dictionary<string, object?>
{
    ["name"] = "launch",
    ["tlds"] = new[] { "com", "io", "ai" },
    ["prefer_cache"] = true,
});

Console.WriteLine(response);` }, {
    'csharp/README.md': renderLanguageReadme('C#', 'dotnet add package DomScan.Sdk', { lang: 'csharp', code: `using DomScan;

var client = new DomScanClient();
var response = await client.Availability.CheckDomainAvailabilityAsync(new Dictionary<string, object?>
{
    ["name"] = "launch",
    ["tlds"] = new[] { "com", "io", "ai" },
    ["prefer_cache"] = true,
});

Console.WriteLine(response);` }),
    'csharp/DomScan.SDK.csproj': `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <PackageId>DomScan.Sdk</PackageId>
    <Version>0.1.0</Version>
  </PropertyGroup>
</Project>
`,
    'csharp/DomScanClient.cs': renderCSharpClient(),
  }));

  packages.push(renderScriptPackage('kotlin', 'implementation("net.domscan:domscan-sdk-kotlin:0.1.0")', { lang: 'kotlin', code: `import net.domscan.DomScanClient

val client = DomScanClient()
val response = client.availability.checkDomainAvailability(
    mapOf(
        "name" to "launch",
        "tlds" to listOf("com", "io", "ai"),
        "prefer_cache" to true,
    )
)

println(response)` }, {
    'kotlin/README.md': renderLanguageReadme('Kotlin', 'implementation("net.domscan:domscan-sdk-kotlin:0.1.0")', { lang: 'kotlin', code: `import net.domscan.DomScanClient

val client = DomScanClient()
val response = client.availability.checkDomainAvailability(
    mapOf(
        "name" to "launch",
        "tlds" to listOf("com", "io", "ai"),
        "prefer_cache" to true,
    )
)

println(response)` }, ['The Kotlin SDK currently returns raw JSON strings for responses to stay dependency-light.']),
    'kotlin/settings.gradle.kts': `rootProject.name = "domscan-sdk-kotlin"
`,
    'kotlin/build.gradle.kts': `plugins {
    kotlin("jvm") version "1.9.24"
}

group = "net.domscan"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
}
`,
    'kotlin/src/main/kotlin/net/domscan/DomScanClient.kt': renderKotlinClient(),
  }));

  packages.push(renderScriptPackage('swift', 'Swift Package Manager: https://github.com/estevecastells/domscan-sdk.git', { lang: 'swift', code: `import DomScan

let client = DomScanClient()
let response = try await client.availability.checkDomainAvailability([
    "name": "launch",
    "tlds": ["com", "io", "ai"],
    "prefer_cache": true,
])

print(response)` }, {
    'swift/README.md': renderLanguageReadme('Swift', 'Add https://github.com/estevecastells/domscan-sdk.git and use the `DomScan` product', { lang: 'swift', code: `import DomScan

let client = DomScanClient()
let response = try await client.availability.checkDomainAvailability([
    "name": "launch",
    "tlds": ["com", "io", "ai"],
    "prefer_cache": true,
])

print(response)` }),
    'swift/Package.swift': `// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DomScan",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: "DomScan", targets: ["DomScan"])
    ],
    targets: [
        .target(name: "DomScan", path: "Sources")
    ]
)
`,
    'swift/Sources/DomScan/DomScanClient.swift': renderSwiftClient(),
  }));

  packages.push(renderScriptPackage('rust', 'cargo add domscan-sdk', { lang: 'rust', code: `use serde_json::{json, Map, Value};

let client = domscan_sdk::DomScanClient::new(None);
let mut params = Map::new();
params.insert("name".into(), Value::String("launch".into()));
params.insert("tlds".into(), json!(["com", "io", "ai"]));
params.insert("prefer_cache".into(), Value::Bool(true));

let response = client.availability().check_domain_availability(params).await?;
println!("{response}");` }, {
    'rust/README.md': renderLanguageReadme('Rust', 'cargo add domscan-sdk', { lang: 'rust', code: `use serde_json::{json, Map, Value};

let client = domscan_sdk::DomScanClient::new(None);
let mut params = Map::new();
params.insert("name".into(), Value::String("launch".into()));
params.insert("tlds".into(), json!(["com", "io", "ai"]));
params.insert("prefer_cache".into(), Value::Bool(true));

let response = client.availability().check_domain_availability(params).await?;
println!("{response}");` }),
    'rust/Cargo.toml': `[package]
name = "domscan-sdk"
version = "0.1.0"
edition = "2021"
license = "MIT"
description = "Official Rust SDK for the DomScan API"

[dependencies]
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
serde_json = "1"
urlencoding = "2"
tokio = { version = "1", features = ["rt", "macros"] }
`,
    'rust/src/lib.rs': renderRustClient(),
  }));

  return packages;
}

async function main() {
  const packages = renderPackages();
  await writeFile(path.join(root, 'README.md'), renderRootReadme(), 'utf8');

  for (const pkg of packages) {
    for (const [relativePath, contents] of Object.entries(pkg.files)) {
      const target = path.join(root, relativePath);
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, contents, 'utf8');
    }
  }

  console.log(`Generated ${packages.length} additional SDK packages from manifest/endpoints.json.`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
