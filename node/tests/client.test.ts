import { describe, expect, test, vi } from 'vitest';

import { DomScan, DomScanAPIError, VERSION } from '../src/index.js';

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status || 200,
    headers: {
      'content-type': 'application/json',
      ...(init.headers || {}),
    },
  });
}

describe('DomScan Node SDK', () => {
  test('serializes query parameters and authentication headers', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ results: [] }));
    const client = new DomScan({
      apiKey: 'dsk_test',
      fetch: fetchMock,
      baseUrl: 'https://domscan.net/',
    });

    await client.availability.checkDomainAvailability({
      name: 'launch',
      tlds: ['com', 'io', 'ai'],
      prefer_cache: true,
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe(
      'https://domscan.net/v1/status?name=launch&tlds=com%2Cio%2Cai&prefer_cache=true'
    );
    const headers = new Headers(init?.headers);
    expect(headers.get('authorization')).toBe('Bearer dsk_test');
    expect(headers.get('x-domscan-sdk')).toBe(`domscan-node/${VERSION}`);
  });

  test('exposes newly generated API operations', () => {
    const client = new DomScan({ fetch: vi.fn<typeof fetch>() });

    expect(client.domain.getDomainPopularity).toBeTypeOf('function');
    expect(client.intelligence.createTechScanJob).toBeTypeOf('function');
    expect(client.meta.createApiBatch).toBeTypeOf('function');
  });

  test('parses problem JSON and preserves structured API errors', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({ error: { code: 'INSUFFICIENT_CREDITS', message: 'Need more credits' } }),
        {
          status: 402,
          headers: {
            'content-type': 'application/problem+json',
            'x-request-id': 'req_123',
          },
        }
      )
    );
    const client = new DomScan({ apiKey: 'dsk_test', fetch: fetchMock });

    await expect(client.domain.getDomainValue({ domain: 'example.com' })).rejects.toMatchObject({
      status: 402,
      code: 'INSUFFICIENT_CREDITS',
      requestId: 'req_123',
    });
  });

  test('accepts an empty successful response', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(null, { status: 204, headers: { 'content-type': 'application/json' } })
    );
    const client = new DomScan({ fetch: fetchMock });

    await expect(client.meta.getPricingInfo()).resolves.toBe('');
  });

  test('reports request timeouts as SDK errors', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
        })
    );
    const client = new DomScan({ fetch: fetchMock, timeout: 5 });

    await expect(client.meta.getPricingInfo()).rejects.toEqual(
      expect.objectContaining<Partial<DomScanAPIError>>({ status: 408 })
    );
  });

  test('distinguishes caller cancellation from a timeout', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
        })
    );
    const client = new DomScan({ fetch: fetchMock, timeout: 1_000 });
    const controller = new AbortController();
    const request = client.meta.getPricingInfo({}, { signal: controller.signal });
    controller.abort();

    await expect(request).rejects.toMatchObject({ status: 0, message: 'Request aborted' });
  });
});
