from typing import assert_type

from domscan import DomScan, DomScanResponse
from domscan._types import CheckDomainAvailabilityResponse


client = DomScan(api_key="dsk_typecheck")

data = client.availability.check_domain_availability(
  name="launch",
  tlds="com,io,ai",
)
assert_type(data, CheckDomainAvailabilityResponse)

full_response = client.availability.check_domain_availability(
  name="launch",
  tlds="com,io,ai",
  _with_response=True,
)
assert_type(full_response, DomScanResponse[CheckDomainAvailabilityResponse])
