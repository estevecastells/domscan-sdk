import unittest

from domscan import DomScan, __version__
from domscan._generated import ENDPOINTS


class DomScanClientTests(unittest.TestCase):
  def test_release_version(self):
    self.assertEqual(__version__, "0.2.0")

  def test_new_operations_are_generated(self):
    client = DomScan(api_key="dsk_test")

    self.assertTrue(callable(client.domain.get_domain_popularity))
    self.assertTrue(callable(client.intelligence.create_tech_scan_job))
    self.assertTrue(callable(client.meta.create_api_batch))
    self.assertEqual(sum(len(methods) for methods in ENDPOINTS.values()), 113)

  def test_decodes_problem_json(self):
    payload = DomScan._decode_payload(
      b'{"error":{"code":"INSUFFICIENT_CREDITS"}}',
      "application/problem+json",
    )

    self.assertEqual(payload["error"]["code"], "INSUFFICIENT_CREDITS")

  def test_accepts_an_empty_json_response(self):
    self.assertEqual(DomScan._decode_payload(b"", "application/json"), "")

  def test_preserves_malformed_json_as_text(self):
    self.assertEqual(DomScan._decode_payload(b"not json", "application/json"), "not json")


if __name__ == "__main__":
  unittest.main()
