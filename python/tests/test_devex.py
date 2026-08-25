import io
import json
import os
import sys
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError


SDK_SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SDK_SRC))

from domscan import DomScan, DomScanRateLimitError, DomScanResponse, __version__  # noqa: E402


class FakeResponse:
  def __init__(self, payload, *, status=200, headers=None):
    self.payload = json.dumps(payload).encode("utf-8")
    self.status = status
    self.headers = Message()
    self.headers["Content-Type"] = "application/json"
    for name, value in (headers or {}).items():
      self.headers[name] = value

  def __enter__(self):
    return self

  def __exit__(self, *_args):
    return False

  def read(self):
    return self.payload


def http_error(status, payload, headers=None):
  message = Message()
  message["Content-Type"] = "application/json"
  for name, value in (headers or {}).items():
    message[name] = value
  return HTTPError(
    "https://domscan.net/v1/status",
    status,
    "failed",
    message,
    io.BytesIO(json.dumps(payload).encode("utf-8")),
  )


class DomScanPythonSdkTest(unittest.TestCase):
  def setUp(self):
    os.environ.pop("DOMSCAN_API_KEY", None)

  def test_release_version(self):
    self.assertEqual(__version__, "0.3.0")

  def test_returns_full_response_metadata_on_demand(self):
    response = FakeResponse(
      {"results": [{"domain": "launch.com", "available": True}]},
      headers={
        "X-Request-Id": "req_python",
        "X-API-Version": "2.15.0",
        "X-Credits-Charged": "1",
        "X-Credits-Remaining": "9999",
        "X-RateLimit-Remaining": "59",
        "X-Data-Freshness": "fresh",
      },
    )
    with patch("domscan._client.urllib_request.urlopen", return_value=response):
      client = DomScan(api_key="dsk_test", max_retries=0)
      result = client.availability.check_domain_availability(
        name="launch",
        tlds="com",
        _with_response=True,
      )

    self.assertIsInstance(result, DomScanResponse)
    self.assertEqual(result.data["results"][0]["domain"], "launch.com")
    self.assertEqual(result.request_id, "req_python")
    self.assertEqual(result.credits_charged, 1)
    self.assertEqual(result.credits_remaining, 9999)
    self.assertEqual(result.rate_limit_remaining, 59)
    self.assertEqual(result.freshness, "fresh")

  def test_maps_actionable_errors(self):
    error = http_error(
      429,
      {
        "error": {
          "type": "rate_limit_error",
          "code": "RATE_LIMITED",
          "message": "Slow down",
          "retryable": True,
          "retry_after": 4,
          "docs_url": "https://domscan.net/docs/error-codes",
        }
      },
      {"X-Request-Id": "req_rate"},
    )
    with patch("domscan._client.urllib_request.urlopen", side_effect=error):
      client = DomScan(api_key="dsk_test", max_retries=0)
      with self.assertRaises(DomScanRateLimitError) as raised:
        client.domain.get_domain_value(domain="example.com")

    self.assertEqual(raised.exception.code, "RATE_LIMITED")
    self.assertEqual(raised.exception.request_id, "req_rate")
    self.assertTrue(raised.exception.retryable)
    self.assertEqual(raised.exception.retry_after, 4)

  def test_retries_get_but_not_post_without_idempotency(self):
    retry_error = http_error(
      429,
      {
        "error": {
          "type": "rate_limit_error",
          "code": "RATE_LIMITED",
          "message": "Slow down",
          "retryable": True,
          "retry_after": 0,
        }
      },
    )
    get_transport = Mock(
      side_effect=[retry_error, FakeResponse({"domain": "example.com"})]
    )
    with patch("domscan._client.urllib_request.urlopen", get_transport), patch(
      "domscan._client.time.sleep"
    ):
      client = DomScan(api_key="dsk_test", max_retries=1)
      result = client.domain.get_domain_profile(domain="example.com")
    self.assertEqual(result["domain"], "example.com")
    self.assertEqual(get_transport.call_count, 2)

    post_transport = Mock(
      side_effect=http_error(
        429,
        {
          "error": {
            "type": "rate_limit_error",
            "code": "RATE_LIMITED",
            "message": "Slow down",
            "retryable": True,
            "retry_after": 0,
          }
        },
      )
    )
    with patch("domscan._client.urllib_request.urlopen", post_transport):
      client = DomScan(api_key="dsk_test", max_retries=1)
      with self.assertRaises(DomScanRateLimitError):
        client.domain.bulk_domain_value(domains=["example.com"])
    self.assertEqual(post_transport.call_count, 1)

  def test_honors_http_date_retry_after(self):
    retry_error = http_error(
      503,
      {
        "error": {
          "type": "upstream_error",
          "code": "UPSTREAM_UNAVAILABLE",
          "message": "Try again",
          "retryable": True,
        }
      },
      {"Retry-After": "Thu, 01 Jan 1970 00:00:05 GMT"},
    )
    transport = Mock(side_effect=[retry_error, FakeResponse({"domain": "example.com"})])
    with patch("domscan._client.urllib_request.urlopen", transport), patch(
      "domscan._client.time.time", return_value=0
    ), patch("domscan._client.time.sleep") as sleep:
      result = DomScan(api_key="dsk_test", max_retries=1).domain.get_domain_profile(
        domain="example.com"
      )

    self.assertEqual(result["domain"], "example.com")
    sleep.assert_called_once_with(5)

  def test_python_keyword_parameters_keep_wire_names(self):
    response = FakeResponse({"observations": []})
    with patch("domscan._client.urllib_request.urlopen", return_value=response) as transport:
      client = DomScan(api_key="dsk_test", max_retries=0)
      client.dns.get_dns_history(domain="example.com", from_="2026-08-01")

    request = transport.call_args.args[0]
    self.assertIn("from=2026-08-01", request.full_url)
    self.assertNotIn("from_=", request.full_url)

  def test_empty_and_malformed_json_are_safe(self):
    self.assertEqual(DomScan._decode_payload(b"", "application/json"), "")
    self.assertEqual(
      DomScan._decode_payload(b"not json", "application/problem+json"),
      "not json",
    )


if __name__ == "__main__":
  unittest.main()
