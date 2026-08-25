import { describe, expect, expectTypeOf, test, vi } from 'vitest';

import {
  DomScan,
  DomScanAPIError,
  DomScanRateLimitError,
  VERSION,
  type Components,
  type DomScanResponse,
} from '../src/index.js';

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
}

describe('DomScan TypeScript SDK', () => {
  test('reports the release version', () => {
    expect(VERSION).toBe('0.3.0');
  });
  test('returns typed data by default and exposes full response metadata on demand', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        { results: [{ domain: 'launch.com', available: true }] },
        {
          headers: {
            'Content-Type': 'application/json',
            'X-Request-Id': 'req_sdk',
            'X-API-Version': '2.15.0',
            'X-Credits-Charged': '1',
            'X-Credits-Remaining': '9999',
            'X-RateLimit-Remaining': '59',
            'X-Data-Freshness': 'fresh',
          },
        }
      )
    );
    const client = new DomScan({ apiKey: 'dsk_test', fetch: fetchMock, maxRetries: 0 });

    const result = await client.availability.checkDomainAvailability(
      { name: 'launch', tlds: 'com' },
      { withResponse: true }
    );

    expectTypeOf(result).toEqualTypeOf<DomScanResponse<Components['StatusResponse']>>();
    expect(result.data.results?.[0]?.domain).toBe('launch.com');
    expect(result.meta).toMatchObject({
      requestId: 'req_sdk',
      apiVersion: '2.15.0',
      credits: { charged: 1, remaining: 9999 },
      rateLimit: { remaining: 59 },
      freshness: 'fresh',
    });
  });

  test('maps structured errors to actionable subclasses', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        {
          error: {
            type: 'rate_limit_error',
            code: 'RATE_LIMITED',
            message: 'Slow down',
            retryable: true,
            retry_after: 4,
            docs_url: 'https://domscan.net/docs/error-codes',
          },
        },
        { status: 429, headers: { 'Content-Type': 'application/json', 'X-Request-Id': 'req_rate' } }
      )
    );
    const client = new DomScan({ apiKey: 'dsk_test', fetch: fetchMock, maxRetries: 0 });

    await expect(
      client.domain.getDomainValue({ domain: 'example.com' })
    ).rejects.toMatchObject({
      constructor: DomScanRateLimitError,
      code: 'RATE_LIMITED',
      requestId: 'req_rate',
      retryable: true,
      retryAfter: 4,
      docsUrl: 'https://domscan.net/docs/error-codes',
    });
  });

  test('keeps fallback errors actionable when a response has no message', async () => {
    const client = new DomScan({
      apiKey: 'dsk_test',
      fetch: vi.fn().mockResolvedValue(jsonResponse({ error: {} }, { status: 503 })),
      maxRetries: 0,
    });

    await expect(client.domain.getDomainValue({ domain: 'example.com' })).rejects.toMatchObject({
      message: 'DomScan request failed with status 503',
      status: 503,
    });
  });

  test('wraps terminal transport failures in the SDK error contract', async () => {
    const client = new DomScan({
      apiKey: 'dsk_test',
      fetch: vi.fn().mockRejectedValue(new TypeError('connection reset')),
      maxRetries: 0,
    });

    await expect(client.domain.getDomainValue({ domain: 'example.com' })).rejects.toMatchObject({
      constructor: DomScanAPIError,
      code: 'SDK_NETWORK_ERROR',
      type: 'request_error',
      retryable: true,
    });
  });

  test('accepts empty JSON responses and preserves malformed JSON as text', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, { status: 204, headers: { 'Content-Type': 'application/json' } })
      )
      .mockResolvedValueOnce(
        new Response('not json', { headers: { 'Content-Type': 'application/problem+json' } })
      );
    const client = new DomScan({ fetch: fetchMock, maxRetries: 0 });

    await expect(client.domain.getScoreInfo()).resolves.toBe('');
    await expect(client.domain.getScoreInfo()).resolves.toBe('not json');
  });

  test('maps caller cancellation into a stable SDK error', async () => {
    const fetchMock = vi.fn().mockImplementation(
      (_input, init: RequestInit | undefined) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
        })
    );
    const client = new DomScan({ fetch: fetchMock, timeout: 1_000, maxRetries: 0 });
    const controller = new AbortController();
    const request = client.domain.getScoreInfo({}, { signal: controller.signal });
    controller.abort();

    await expect(request).rejects.toMatchObject({
      code: 'SDK_ABORTED',
      type: 'request_error',
      retryable: false,
    });
  });

  test('retries retryable GET requests but not POST requests without idempotency', async () => {
    const rateLimited = () =>
      jsonResponse(
        {
          error: {
            type: 'rate_limit_error',
            code: 'RATE_LIMITED',
            message: 'Slow down',
            retryable: true,
            retry_after: 0,
          },
        },
        { status: 429 }
      );
    const getFetch = vi
      .fn()
      .mockResolvedValueOnce(rateLimited())
      .mockResolvedValueOnce(jsonResponse({ domain: 'example.com' }));
    const getClient = new DomScan({ apiKey: 'dsk_test', fetch: getFetch, maxRetries: 1 });

    await expect(getClient.domain.getDomainProfile({ domain: 'example.com' })).resolves.toMatchObject({
      domain: 'example.com',
    });
    expect(getFetch).toHaveBeenCalledTimes(2);

    const postFetch = vi.fn().mockResolvedValue(rateLimited());
    const postClient = new DomScan({ apiKey: 'dsk_test', fetch: postFetch, maxRetries: 1 });
    await expect(
      postClient.domain.bulkDomainValue({ domains: ['example.com'] })
    ).rejects.toBeInstanceOf(DomScanRateLimitError);
    expect(postFetch).toHaveBeenCalledTimes(1);
  });
});
