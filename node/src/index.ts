import { endpointManifest, type EndpointManifest } from './generated.js';

export interface DomScanClientOptions {
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
  userAgent?: string;
  fetch?: typeof globalThis.fetch;
  headers?: HeadersInit;
}

export interface RequestOptions {
  headers?: HeadersInit;
  signal?: AbortSignal;
  timeout?: number;
}

type ManifestEndpoint = {
  title: string;
  description: string;
  method: string;
  path: string;
  pathParams: readonly string[];
  queryParams: readonly string[];
  hasBody: boolean;
};

type QueryValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | Date
  | QueryValue[]
  | Record<string, unknown>;

type RequestParams = Record<string, QueryValue>;
type DomScanMethod = (params?: RequestParams, options?: RequestOptions) => Promise<unknown>;
type ServiceMap<TNamespace extends Record<string, unknown>> = {
  -readonly [K in keyof TNamespace]: DomScanMethod;
};

export type DomScanServices = {
  -readonly [Namespace in keyof EndpointManifest]: ServiceMap<EndpointManifest[Namespace]>;
};

function resolveApiKey(apiKey?: string): string | undefined {
  if (apiKey) {
    return apiKey;
  }

  const maybeProcess =
    typeof globalThis !== 'undefined' && 'process' in globalThis
      ? (globalThis as typeof globalThis & {
          process?: {
            env?: Record<string, string | undefined>;
          };
        }).process
      : undefined;

  if (maybeProcess?.env) {
    return maybeProcess.env.DOMSCAN_API_KEY;
  }

  return undefined;
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
}

function serializeScalar(value: Exclude<QueryValue, QueryValue[] | Record<string, unknown>>): string {
  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  return String(value);
}

function serializeQueryValue(value: QueryValue): string {
  if (Array.isArray(value)) {
    return value
      .filter((item) => item !== undefined && item !== null)
      .map((item) => serializeQueryValue(item))
      .join(',');
  }

  if (value instanceof Date || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return serializeScalar(value);
  }

  return JSON.stringify(value);
}

function extractPayload(
  params: RequestParams,
  keysToExclude: Set<string>
): Record<string, QueryValue> {
  const payload: Record<string, QueryValue> = {};

  for (const [key, value] of Object.entries(params)) {
    if (keysToExclude.has(key) || value === undefined) {
      continue;
    }

    payload[key] = value;
  }

  return payload;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export class DomScanAPIError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly details?: unknown;
  readonly requestId?: string;

  constructor(
    message: string,
    options: {
      status: number;
      code?: string;
      details?: unknown;
      requestId?: string;
    }
  ) {
    super(message);
    this.name = 'DomScanAPIError';
    this.status = options.status;
    this.code = options.code;
    this.details = options.details;
    this.requestId = options.requestId;
  }
}

function createServices(
  request: (endpoint: ManifestEndpoint, params?: RequestParams, options?: RequestOptions) => Promise<unknown>
): DomScanServices {
  const services = {} as Record<string, Record<string, DomScanMethod>>;

  for (const namespace of Object.keys(endpointManifest) as Array<keyof EndpointManifest>) {
    const definitions = endpointManifest[namespace];
    const service = {} as Record<string, DomScanMethod>;

    for (const methodName of Object.keys(definitions) as Array<keyof typeof definitions>) {
      const endpoint = definitions[methodName] as ManifestEndpoint;
      service[String(methodName)] = (
        params?: RequestParams,
        options?: RequestOptions
      ) => request(endpoint, params, options);
    }

    services[String(namespace)] = service;
  }

  return services as DomScanServices;
}

export class DomScan {
  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly defaultHeaders: HeadersInit;

  constructor(options: DomScanClientOptions = {}) {
    const fetchImpl = options.fetch ?? globalThis.fetch;

    if (!fetchImpl) {
      throw new Error('Fetch is not available in this runtime. Pass a fetch implementation explicitly.');
    }

    this.apiKey = resolveApiKey(options.apiKey);
    this.baseUrl = normalizeBaseUrl(options.baseUrl || 'https://domscan.net');
    this.timeout = options.timeout ?? 10_000;
    this.userAgent = options.userAgent ?? 'domscan-node/0.1.0';
    this.fetchImpl = fetchImpl;
    this.defaultHeaders = options.headers ?? {};

    Object.assign(this, createServices((endpoint, params, requestOptions) => this.request(endpoint, params, requestOptions)));
  }

  private async request(
    endpoint: ManifestEndpoint,
    params: RequestParams = {},
    options: RequestOptions = {}
  ): Promise<unknown> {
    let requestPath = endpoint.path;
    const consumedKeys = new Set<string>();

    for (const pathParam of endpoint.pathParams) {
      const value = params[pathParam];
      if (value === undefined || value === null) {
        throw new Error(`Missing required path parameter: ${pathParam}`);
      }

      requestPath = requestPath.replace(`:${pathParam}`, encodeURIComponent(String(value)));
      consumedKeys.add(pathParam);
    }

    const remaining = extractPayload(params, consumedKeys);
    const queryPayload: Record<string, QueryValue> = {};

    if (endpoint.hasBody) {
      for (const queryKey of endpoint.queryParams) {
        if (remaining[queryKey] !== undefined) {
          queryPayload[queryKey] = remaining[queryKey];
        }
      }
    } else {
      Object.assign(queryPayload, remaining);
    }

    const url = new URL(`${this.baseUrl}${requestPath}`);

    for (const [key, value] of Object.entries(queryPayload)) {
      if (value === undefined || value === null) {
        continue;
      }

      url.searchParams.set(key, serializeQueryValue(value));
    }

    const bodyPayload = endpoint.hasBody
      ? extractPayload(params, new Set([...consumedKeys, ...endpoint.queryParams]))
      : undefined;

    const headers = new Headers(this.defaultHeaders);
    headers.set('accept', 'application/json');
    headers.set('user-agent', this.userAgent);
    headers.set('x-domscan-sdk', this.userAgent);

    if (this.apiKey) {
      headers.set('authorization', `Bearer ${this.apiKey}`);
      headers.set('x-api-key', this.apiKey);
    }

    if (options.headers) {
      new Headers(options.headers).forEach((value, key) => headers.set(key, value));
    }

    let body: string | undefined;
    if (endpoint.hasBody) {
      headers.set('content-type', 'application/json');
      body = JSON.stringify(bodyPayload || {});
    }

    const controller = new AbortController();
    const timeoutMs = options.timeout ?? this.timeout;
    const signal = controller.signal;
    const externalSignal = options.signal;

    if (externalSignal) {
      if (externalSignal.aborted) {
        controller.abort(externalSignal.reason);
      } else {
        externalSignal.addEventListener('abort', () => controller.abort(externalSignal.reason), {
          once: true,
        });
      }
    }

    const timeoutId = setTimeout(() => controller.abort(new Error('Request timed out')), timeoutMs);

    try {
      const response = await this.fetchImpl(url, {
        method: endpoint.method,
        headers,
        body,
        signal,
      });

      const contentType = response.headers.get('content-type') || '';
      const payload = contentType.includes('application/json')
        ? await response.json()
        : await response.text();

      if (!response.ok) {
        throw this.buildApiError(response.status, response.headers.get('x-request-id'), payload);
      }

      return payload;
    } catch (error) {
      if (error instanceof DomScanAPIError) {
        throw error;
      }

      if (error instanceof Error && error.name === 'AbortError') {
        throw new DomScanAPIError('Request timed out', {
          status: 408,
          details: error,
        });
      }

      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private buildApiError(
    status: number,
    requestId: string | null,
    payload: unknown
  ): DomScanAPIError {
    const errorPayload = isRecord(payload) && isRecord(payload.error) ? payload.error : isRecord(payload) ? payload : undefined;
    const message =
      (errorPayload && typeof errorPayload.message === 'string' && errorPayload.message) ||
      `DomScan request failed with status ${status}`;
    const code =
      errorPayload && typeof errorPayload.code === 'string' ? errorPayload.code : undefined;

    return new DomScanAPIError(message, {
      status,
      code,
      requestId: requestId || undefined,
      details: payload,
    });
  }
}

export interface DomScan extends DomScanServices {}

export function isDomScanAPIError(error: unknown): error is DomScanAPIError {
  return error instanceof DomScanAPIError;
}

export default DomScan;
