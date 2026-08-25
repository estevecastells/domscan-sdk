from __future__ import annotations

import json
import os
import keyword
import time
from dataclasses import dataclass
from datetime import date, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Generic, Iterable, Mapping, Optional, TypeVar, Union
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from ._generated import ENDPOINTS


QueryValue = Any
T = TypeVar("T")


@dataclass
class DomScanResponse(Generic[T]):
  data: T
  status: int
  request_id: Optional[str]
  api_version: Optional[str]
  response_time_ms: Optional[float]
  credits_requested: Optional[int]
  credits_charged: Optional[int]
  credits_refunded: Optional[int]
  credits_remaining: Optional[int]
  rate_limit_plan: Optional[str]
  rate_limit_limit: Optional[int]
  rate_limit_remaining: Optional[int]
  retry_after: Optional[int]
  freshness: Optional[str]
  headers: Mapping[str, str]


@dataclass
class EndpointDefinition:
  title: str
  description: str
  method: str
  path: str
  path_params: list[str]
  query_params: list[str]
  has_body: bool


class DomScanAPIError(Exception):
  def __init__(
    self,
    message: str,
    *,
    status: int,
    code: Optional[str] = None,
    details: Any = None,
    request_id: Optional[str] = None,
    error_type: Optional[str] = None,
    retryable: bool = False,
    retry_after: Optional[int] = None,
    docs_url: Optional[str] = None,
  ) -> None:
    super().__init__(message)
    self.status = status
    self.code = code
    self.details = details
    self.request_id = request_id
    self.error_type = error_type
    self.retryable = retryable
    self.retry_after = retry_after
    self.docs_url = docs_url


class DomScanAuthenticationError(DomScanAPIError):
  pass


class DomScanCreditsError(DomScanAPIError):
  pass


class DomScanRateLimitError(DomScanAPIError):
  pass


class DomScanValidationError(DomScanAPIError):
  pass


class DomScanTimeoutError(DomScanAPIError):
  pass


class DomScanUpstreamError(DomScanAPIError):
  pass


class _Service:
  def __init__(self, client: "DomScan", definitions: Mapping[str, Mapping[str, Any]]) -> None:
    self._client = client
    self._definitions = definitions

  def __getattr__(self, name: str):
    definition_data = self._definitions.get(name)
    if definition_data is None:
      raise AttributeError(name)

    definition = EndpointDefinition(
      title=str(definition_data["title"]),
      description=str(definition_data["description"]),
      method=str(definition_data["method"]),
      path=str(definition_data["path"]),
      path_params=list(definition_data["pathParams"]),
      query_params=list(definition_data["queryParams"]),
      has_body=bool(definition_data["hasBody"]),
    )

    def call(params: Optional[Mapping[str, QueryValue]] = None, /, **kwargs: QueryValue) -> Any:
      with_response = bool(kwargs.pop("_with_response", False))
      timeout = kwargs.pop("_timeout", None)
      max_retries = kwargs.pop("_max_retries", None)
      idempotency_key = kwargs.pop("_idempotency_key", None)
      merged: Dict[str, QueryValue] = {}
      if params:
        merged.update(dict(params))
      merged.update({
        key[:-1] if key.endswith('_') and keyword.iskeyword(key[:-1]) else key: value
        for key, value in kwargs.items()
      })
      return self._client._request(
        definition,
        merged,
        with_response=with_response,
        timeout=timeout,
        max_retries=max_retries,
        idempotency_key=idempotency_key,
      )

    call.__name__ = name
    call.__doc__ = definition.description
    return call


class DomScan:
  def __init__(
    self,
    *,
    api_key: Optional[str] = None,
    base_url: str = "https://domscan.net",
    timeout: float = 10.0,
    max_retries: int = 2,
    user_agent: str = "domscan-python/0.3.0",
    headers: Optional[Mapping[str, str]] = None,
  ) -> None:
    self.api_key = api_key or os.getenv("DOMSCAN_API_KEY")
    self.base_url = base_url.rstrip("/")
    self.timeout = timeout
    self.max_retries = max(0, max_retries)
    self.user_agent = user_agent
    self.default_headers = dict(headers or {})

    for namespace, definitions in ENDPOINTS.items():
      setattr(self, namespace, _Service(self, definitions))

  def _request(
    self,
    definition: EndpointDefinition,
    params: Mapping[str, QueryValue],
    *,
    with_response: bool = False,
    timeout: Optional[float] = None,
    max_retries: Optional[int] = None,
    idempotency_key: Optional[str] = None,
  ) -> Any:
    request_path = definition.path
    consumed_keys = set()

    for path_param in definition.path_params:
      value = params.get(path_param)
      if value is None:
        raise ValueError(f"Missing required path parameter: {path_param}")

      request_path = request_path.replace(f":{path_param}", urllib_parse.quote(str(value), safe=""))
      consumed_keys.add(path_param)

    remaining = {
      key: value
      for key, value in params.items()
      if key not in consumed_keys and value is not None
    }

    if definition.has_body:
      query_payload = {
        key: value
        for key, value in remaining.items()
        if key in definition.query_params
      }
      body_payload = {
        key: value
        for key, value in remaining.items()
        if key not in definition.query_params
      }
    else:
      query_payload = remaining
      body_payload = None

    url = f"{self.base_url}{request_path}"
    if query_payload:
      query_string = urllib_parse.urlencode(
        {key: self._serialize_query_value(value) for key, value in query_payload.items()},
        doseq=False,
      )
      url = f"{url}?{query_string}"

    headers = {
      "Accept": "application/json",
      "User-Agent": self.user_agent,
      "X-DomScan-SDK": self.user_agent,
      **self.default_headers,
    }

    if self.api_key:
      headers["Authorization"] = f"Bearer {self.api_key}"

    if idempotency_key:
      headers["Idempotency-Key"] = idempotency_key

    data = None
    if definition.has_body:
      headers["Content-Type"] = "application/json"
      data = json.dumps(body_payload or {}).encode("utf-8")

    request = urllib_request.Request(
      url,
      data=data,
      headers=headers,
      method=definition.method,
    )

    retry_count = max(0, self.max_retries if max_retries is None else max_retries)
    safely_retryable = definition.method == "GET" or bool(idempotency_key)
    request_timeout = self.timeout if timeout is None else timeout

    for attempt in range(retry_count + 1):
      try:
        with urllib_request.urlopen(request, timeout=request_timeout) as response:
          payload = self._decode_payload(response.read(), response.headers.get("Content-Type", ""))
          if with_response:
            return self._build_response(payload, response.status, response.headers)
          return payload
      except urllib_error.HTTPError as exc:
        body = exc.read()
        payload = self._decode_payload(body, exc.headers.get("Content-Type", ""))
        api_error = self._build_api_error(exc.code, exc.headers, payload)
        if safely_retryable and api_error.retryable and attempt < retry_count:
          time.sleep(api_error.retry_after if api_error.retry_after is not None else min(8, 2 ** attempt))
          continue
        raise api_error from None
      except (urllib_error.URLError, TimeoutError) as exc:
        reason = getattr(exc, "reason", exc)
        if safely_retryable and attempt < retry_count:
          time.sleep(min(8.0, 0.25 * (2 ** attempt)))
          continue
        error_class = DomScanTimeoutError if isinstance(reason, TimeoutError) else DomScanAPIError
        raise error_class(
          str(reason),
          status=0,
          code="SDK_TIMEOUT" if error_class is DomScanTimeoutError else "SDK_NETWORK_ERROR",
          retryable=safely_retryable,
          details={"reason": str(reason)},
        ) from None

    raise RuntimeError("unreachable")

  @staticmethod
  def _optional_int(headers: Mapping[str, str], name: str) -> Optional[int]:
    value = headers.get(name)
    if value is None:
      return None
    try:
      return int(value)
    except (TypeError, ValueError):
      return None

  def _build_response(
    self,
    payload: T,
    status: int,
    headers: Mapping[str, str],
  ) -> DomScanResponse[T]:
    response_time = headers.get("x-response-time")
    try:
      response_time_ms = float(response_time[:-2]) if response_time and response_time.endswith("ms") else None
    except ValueError:
      response_time_ms = None
    return DomScanResponse(
      data=payload,
      status=status,
      request_id=headers.get("x-request-id"),
      api_version=headers.get("x-api-version"),
      response_time_ms=response_time_ms,
      credits_requested=self._optional_int(headers, "x-credits-requested"),
      credits_charged=self._optional_int(headers, "x-credits-charged"),
      credits_refunded=self._optional_int(headers, "x-credits-refunded"),
      credits_remaining=self._optional_int(headers, "x-credits-remaining"),
      rate_limit_plan=headers.get("x-ratelimit-plan"),
      rate_limit_limit=self._optional_int(headers, "x-ratelimit-limit"),
      rate_limit_remaining=self._optional_int(headers, "x-ratelimit-remaining"),
      retry_after=self._optional_int(headers, "retry-after"),
      freshness=headers.get("x-data-freshness"),
      headers=dict(headers),
    )

  def _build_api_error(
    self,
    status: int,
    headers: Mapping[str, str],
    payload: Any,
  ) -> DomScanAPIError:
    error_payload = payload.get("error") if isinstance(payload, dict) and isinstance(payload.get("error"), dict) else payload
    message = (
      error_payload.get("message")
      if isinstance(error_payload, dict) and isinstance(error_payload.get("message"), str)
      else f"DomScan request failed with status {status}"
    )
    code = error_payload.get("code") if isinstance(error_payload, dict) and isinstance(error_payload.get("code"), str) else None
    error_type = error_payload.get("type") if isinstance(error_payload, dict) and isinstance(error_payload.get("type"), str) else None
    retryable = bool(error_payload.get("retryable")) if isinstance(error_payload, dict) else False
    retry_after = error_payload.get("retry_after") if isinstance(error_payload, dict) and isinstance(error_payload.get("retry_after"), int) else self._retry_after(headers)
    docs_url = error_payload.get("docs_url") if isinstance(error_payload, dict) and isinstance(error_payload.get("docs_url"), str) else None
    error_class = {
      "authentication_error": DomScanAuthenticationError,
      "credits_error": DomScanCreditsError,
      "rate_limit_error": DomScanRateLimitError,
      "validation_error": DomScanValidationError,
      "timeout_error": DomScanTimeoutError,
      "upstream_error": DomScanUpstreamError,
    }.get(error_type, DomScanAPIError)
    return error_class(
      message,
      status=status,
      code=code,
      details=payload,
      request_id=headers.get("x-request-id"),
      error_type=error_type,
      retryable=retryable,
      retry_after=retry_after,
      docs_url=docs_url,
    )

  @staticmethod
  def _retry_after(headers: Mapping[str, str]) -> Optional[int]:
    raw = headers.get("retry-after")
    if raw is None:
      return None
    try:
      return max(0, int(raw))
    except (TypeError, ValueError):
      try:
        retry_at = parsedate_to_datetime(raw)
        return max(0, int(retry_at.timestamp() - time.time() + 0.999))
      except (TypeError, ValueError, OverflowError):
        return None

  @staticmethod
  def _decode_payload(body: bytes, content_type: str) -> Any:
    decoded = body.decode("utf-8")
    if not decoded:
      return ""
    if "json" in content_type:
      try:
        return json.loads(decoded)
      except json.JSONDecodeError:
        return decoded
    return decoded

  @staticmethod
  def _serialize_query_value(value: QueryValue) -> str:
    if isinstance(value, (list, tuple, set)):
      return ",".join(DomScan._serialize_query_value(item) for item in value)

    if isinstance(value, bool):
      return "true" if value else "false"

    if isinstance(value, (datetime, date)):
      return value.isoformat()

    if isinstance(value, Mapping):
      return json.dumps(dict(value))

    return str(value)
