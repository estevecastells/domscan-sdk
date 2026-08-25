import { endpointManifest, type EndpointManifest } from './generated.js';
import type {
  OperationName,
  OperationParams,
  OperationResponse,
} from './generated-types.js';

export type * from './generated-types.js';

export const VERSION = '0.3.0';

export interface DomScanClientOptions {
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
  userAgent?: string;
  fetch?: typeof globalThis.fetch;
  headers?: HeadersInit;
  maxRetries?: number;
}

export interface RequestOptions {
  headers?: HeadersInit;
  signal?: AbortSignal;
  timeout?: number;
  maxRetries?: number;
  idempotencyKey?: string;
  withResponse?: boolean;
}

export interface DomScanResponseMetadata {
  requestId?: string;
  apiVersion?: string;
  responseTimeMs?: number;
  credits: {
    requested?: number;
    charged?: number;
    refunded?: number;
    remaining?: number;
  };
  rateLimit: {
    plan?: string;
    limit?: number;
    remaining?: number;
    policy?: string;
    retryAfter?: number;
  };
  freshness?: 'fresh' | 'cached' | 'stale' | 'mixed' | 'unknown' | string;
}

export interface DomScanResponse<TData> {
  data: TData;
  meta: DomScanResponseMetadata;
  response: Response;
}

type ManifestEndpoint = {
  title: string;
  description: string;
  method: string;
  operationId: string;
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
type DataRequestOptions = RequestOptions & { withResponse?: false };
type FullRequestOptions = RequestOptions & { withResponse: true };
type OperationFor<TEndpoint> = TEndpoint extends { operationId: infer TName extends OperationName }
  ? TName
  : never;
type OptionalParamsMethod<TName extends OperationName> = {
  (params: OperationParams<TName> | undefined, options: FullRequestOptions): Promise<
    DomScanResponse<OperationResponse<TName>>
  >;
  (params?: OperationParams<TName>, options?: DataRequestOptions): Promise<OperationResponse<TName>>;
};
type RequiredParamsMethod<TName extends OperationName> = {
  (params: OperationParams<TName>, options: FullRequestOptions): Promise<
    DomScanResponse<OperationResponse<TName>>
  >;
  (params: OperationParams<TName>, options?: DataRequestOptions): Promise<OperationResponse<TName>>;
};
type DomScanMethod<TEndpoint> = OperationFor<TEndpoint> extends infer TName extends OperationName
  ? {} extends OperationParams<TName>
    ? OptionalParamsMethod<TName>
    : RequiredParamsMethod<TName>
  : never;
type ServiceMap<TNamespace extends Record<string, unknown>> = {
  -readonly [K in keyof TNamespace]: DomScanMethod<TNamespace[K]>;
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
  readonly type?: string;
  readonly retryable: boolean;
  readonly retryAfter?: number;
  readonly docsUrl?: string;

  constructor(
    message: string,
    options: {
      status: number;
      code?: string;
      details?: unknown;
      requestId?: string;
      type?: string;
      retryable?: boolean;
      retryAfter?: number;
      docsUrl?: string;
    }
  ) {
    super(message);
    this.name = 'DomScanAPIError';
    this.status = options.status;
    this.code = options.code;
    this.details = options.details;
    this.requestId = options.requestId;
    this.type = options.type;
    this.retryable = options.retryable ?? false;
    this.retryAfter = options.retryAfter;
    this.docsUrl = options.docsUrl;
  }
}

export class DomScanAuthenticationError extends DomScanAPIError {}
export class DomScanCreditsError extends DomScanAPIError {}
export class DomScanRateLimitError extends DomScanAPIError {}
export class DomScanValidationError extends DomScanAPIError {}
export class DomScanTimeoutError extends DomScanAPIError {}
export class DomScanUpstreamError extends DomScanAPIError {}

function optionalInteger(headers: Headers, name: string): number | undefined {
  const raw = headers.get(name);
  if (raw === null || raw === '') return undefined;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) ? value : undefined;
}

function retryAfterSeconds(headers: Headers): number | undefined {
  const raw = headers.get('retry-after');
  if (!raw) return undefined;
  const seconds = Number.parseInt(raw, 10);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(raw);
  if (!Number.isFinite(date)) return undefined;
  return Math.max(0, Math.ceil((date - Date.now()) / 1_000));
}

function responseMetadata(headers: Headers): DomScanResponseMetadata {
  const responseTime = headers.get('x-response-time');
  return {
    requestId: headers.get('x-request-id') || undefined,
    apiVersion: headers.get('x-api-version') || undefined,
    responseTimeMs: responseTime ? Number.parseFloat(responseTime) : undefined,
    credits: {
      requested: optionalInteger(headers, 'x-credits-requested'),
      charged: optionalInteger(headers, 'x-credits-charged'),
      refunded: optionalInteger(headers, 'x-credits-refunded'),
      remaining: optionalInteger(headers, 'x-credits-remaining'),
    },
    rateLimit: {
      plan: headers.get('x-ratelimit-plan') || undefined,
      limit: optionalInteger(headers, 'x-ratelimit-limit'),
      remaining: optionalInteger(headers, 'x-ratelimit-remaining'),
      policy: headers.get('x-ratelimit-policy') || undefined,
      retryAfter: retryAfterSeconds(headers),
    },
    freshness: headers.get('x-data-freshness') || undefined,
  };
}

function wait(delayMs: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(resolve, delayMs);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timeout);
        reject(signal.reason);
      },
      { once: true }
    );
  });
}

function createServices(
  request: (
    endpoint: ManifestEndpoint,
    params?: RequestParams,
    options?: RequestOptions
  ) => Promise<unknown>
): DomScanServices {
  const services = {} as Record<
    string,
    Record<string, (params?: RequestParams, options?: RequestOptions) => Promise<unknown>>
  >;

  for (const namespace of Object.keys(endpointManifest) as Array<keyof EndpointManifest>) {
    const definitions = endpointManifest[namespace];
    const service = {} as Record<
      string,
      (params?: RequestParams, options?: RequestOptions) => Promise<unknown>
    >;

    for (const methodName of Object.keys(definitions) as Array<keyof typeof definitions>) {
      const endpoint = definitions[methodName] as ManifestEndpoint;
      service[String(methodName)] = (
        params?: RequestParams,
        options?: RequestOptions
      ) => request(endpoint, params, options);
    }

    services[String(namespace)] = service;
  }

  return services as unknown as DomScanServices;
}

export class DomScan {
  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly defaultHeaders: HeadersInit;
  private readonly maxRetries: number;

  constructor(options: DomScanClientOptions = {}) {
    const fetchImpl = options.fetch ?? globalThis.fetch;

    if (!fetchImpl) {
      throw new Error('Fetch is not available in this runtime. Pass a fetch implementation explicitly.');
    }

    this.apiKey = resolveApiKey(options.apiKey);
    this.baseUrl = normalizeBaseUrl(options.baseUrl || 'https://domscan.net');
    this.timeout = options.timeout ?? 10_000;
    this.userAgent = options.userAgent ?? `domscan-node/${VERSION}`;
    this.fetchImpl = fetchImpl;
    this.defaultHeaders = options.headers ?? {};
    this.maxRetries = Math.max(0, options.maxRetries ?? 2);

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
    }

    if (options.headers) {
      new Headers(options.headers).forEach((value, key) => headers.set(key, value));
    }

    let body: string | undefined;
    if (endpoint.hasBody) {
      headers.set('content-type', 'application/json');
      body = JSON.stringify(bodyPayload || {});
    }

    const timeoutMs = options.timeout ?? this.timeout;
    const externalSignal = options.signal;

    if (options.idempotencyKey) {
      headers.set('idempotency-key', options.idempotencyKey);
    }

    const maxRetries = Math.max(0, options.maxRetries ?? this.maxRetries);
    const safelyRetryable = endpoint.method === 'GET' || Boolean(options.idempotencyKey);

    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      let externalAbortListener: (() => void) | undefined;
      if (externalSignal) {
        if (externalSignal.aborted) {
          controller.abort(externalSignal.reason);
        } else {
          externalAbortListener = () => controller.abort(externalSignal.reason);
          externalSignal.addEventListener('abort', externalAbortListener, { once: true });
        }
      }
      const timeoutId = setTimeout(
        () => controller.abort(new DOMException('Request timed out', 'AbortError')),
        timeoutMs
      );

      try {
        const response = await this.fetchImpl(url, {
            method: endpoint.method,
            headers,
            body,
            signal: controller.signal,
        });
        const contentType = response.headers.get('content-type') || '';
        const responseBody = await response.text();
        let payload: unknown = responseBody;
        if (responseBody && contentType.includes('json')) {
          try {
            payload = JSON.parse(responseBody);
          } catch {
            payload = responseBody;
          }
        }

        if (!response.ok) {
          const apiError = this.buildApiError(response, payload);
          if (safelyRetryable && apiError.retryable && attempt < maxRetries) {
            await wait(
              (apiError.retryAfter ?? Math.min(8, 2 ** attempt)) * 1_000,
              externalSignal
            );
            continue;
          }
          throw apiError;
        }

        if (options.withResponse) {
          return {
            data: payload,
            meta: responseMetadata(response.headers),
            response,
          } satisfies DomScanResponse<unknown>;
        }
        return payload;
      } catch (error) {
        if (error instanceof DomScanAPIError) throw error;
        if (externalSignal?.aborted) {
          throw new DomScanAPIError('Request aborted', {
            status: 0,
            code: 'SDK_ABORTED',
            type: 'request_error',
            retryable: false,
            details: externalSignal.reason || error,
          });
        }
        if (error instanceof Error && error.name === 'AbortError') {
          if (safelyRetryable && attempt < maxRetries) {
            await wait(Math.min(8_000, 250 * 2 ** attempt), externalSignal);
            continue;
          }
          throw new DomScanTimeoutError('DomScan request timed out', {
            status: 0,
            code: 'SDK_TIMEOUT',
            retryable: safelyRetryable,
            details: error,
          });
        }
        if (safelyRetryable && attempt < maxRetries) {
          await wait(Math.min(8_000, 250 * 2 ** attempt), externalSignal);
          continue;
        }
        throw new DomScanAPIError(
          error instanceof Error ? error.message : 'DomScan network request failed',
          {
            status: 0,
            code: 'SDK_NETWORK_ERROR',
            type: 'request_error',
            retryable: safelyRetryable,
            details: error,
          }
        );
      } finally {
        clearTimeout(timeoutId);
        if (externalAbortListener) {
          externalSignal?.removeEventListener('abort', externalAbortListener);
        }
      }
    }
  }

  private buildApiError(
    response: Response,
    payload: unknown
  ): DomScanAPIError {
    const errorPayload = isRecord(payload) && isRecord(payload.error) ? payload.error : isRecord(payload) ? payload : undefined;
    const message =
      (errorPayload && typeof errorPayload.message === 'string' && errorPayload.message) ||
      `DomScan request failed with status ${response.status}`;
    const code =
      errorPayload && typeof errorPayload.code === 'string' ? errorPayload.code : undefined;
    const type =
      errorPayload && typeof errorPayload.type === 'string' ? errorPayload.type : undefined;
    const retryable = Boolean(errorPayload?.retryable);
    const retryAfter =
      errorPayload && typeof errorPayload.retry_after === 'number'
        ? errorPayload.retry_after
        : retryAfterSeconds(response.headers);
    const docsUrl =
      errorPayload && typeof errorPayload.docs_url === 'string'
        ? errorPayload.docs_url
        : undefined;
    const ErrorClass =
      type === 'authentication_error'
        ? DomScanAuthenticationError
        : type === 'credits_error'
          ? DomScanCreditsError
          : type === 'rate_limit_error'
            ? DomScanRateLimitError
            : type === 'validation_error'
              ? DomScanValidationError
              : type === 'timeout_error'
                ? DomScanTimeoutError
                : type === 'upstream_error'
                  ? DomScanUpstreamError
                  : DomScanAPIError;

    return new ErrorClass(message, {
      status: response.status,
      code,
      type,
      retryable,
      retryAfter,
      docsUrl,
      requestId: response.headers.get('x-request-id') || undefined,
      details: payload,
    });
  }
}

export interface DomScan extends DomScanServices {}

export function isDomScanAPIError(error: unknown): error is DomScanAPIError {
  return error instanceof DomScanAPIError;
}

export default DomScan;
