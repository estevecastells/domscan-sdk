from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, Iterable, Mapping, Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from ._generated import ENDPOINTS


QueryValue = Any


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
  ) -> None:
    super().__init__(message)
    self.status = status
    self.code = code
    self.details = details
    self.request_id = request_id


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
      merged: Dict[str, QueryValue] = {}
      if params:
        merged.update(dict(params))
      merged.update(kwargs)
      return self._client._request(definition, merged)

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
    user_agent: str = "domscan-python/0.1.0",
    headers: Optional[Mapping[str, str]] = None,
  ) -> None:
    self.api_key = api_key or os.getenv("DOMSCAN_API_KEY")
    self.base_url = base_url.rstrip("/")
    self.timeout = timeout
    self.user_agent = user_agent
    self.default_headers = dict(headers or {})

    for namespace, definitions in ENDPOINTS.items():
      setattr(self, namespace, _Service(self, definitions))

  def _request(self, definition: EndpointDefinition, params: Mapping[str, QueryValue]) -> Any:
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
      headers["X-API-Key"] = self.api_key

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

    try:
      with urllib_request.urlopen(request, timeout=self.timeout) as response:
        payload = self._decode_payload(response.read(), response.headers.get("Content-Type", ""))
        return payload
    except urllib_error.HTTPError as exc:
      body = exc.read()
      payload = self._decode_payload(body, exc.headers.get("Content-Type", ""))
      raise self._build_api_error(exc.code, exc.headers.get("x-request-id"), payload) from None
    except urllib_error.URLError as exc:
      raise DomScanAPIError(
        str(exc.reason),
        status=0,
        details={"reason": str(exc.reason)},
      ) from None

  def _build_api_error(
    self,
    status: int,
    request_id: Optional[str],
    payload: Any,
  ) -> DomScanAPIError:
    error_payload = payload.get("error") if isinstance(payload, dict) and isinstance(payload.get("error"), dict) else payload
    message = (
      error_payload.get("message")
      if isinstance(error_payload, dict) and isinstance(error_payload.get("message"), str)
      else f"DomScan request failed with status {status}"
    )
    code = error_payload.get("code") if isinstance(error_payload, dict) and isinstance(error_payload.get("code"), str) else None
    return DomScanAPIError(
      message,
      status=status,
      code=code,
      details=payload,
      request_id=request_id,
    )

  @staticmethod
  def _decode_payload(body: bytes, content_type: str) -> Any:
    if "application/json" in content_type:
      return json.loads(body.decode("utf-8"))
    return body.decode("utf-8")

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
