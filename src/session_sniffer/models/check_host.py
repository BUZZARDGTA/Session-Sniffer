"""Pydantic models for Check-Host.net distributed ping API responses.

This module provides validation for the `/check-ping` and `/check-result/{id}`
JSON endpoints returned by check-host.net.
"""

import math
from typing import Final, cast

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, model_validator

_NODE_INFO_COUNTRY_INDEX: Final = 1
_NODE_INFO_CITY_INDEX: Final = 2
_ATTEMPT_MIN_FIELDS: Final = 2


class CheckHostNodeInfo(BaseModel):
    """Geographic metadata for a single Check-Host.net probe node."""

    model_config = ConfigDict(extra='ignore')

    country: str = ''
    city: str = ''

    @model_validator(mode='before')
    @classmethod
    def _parse_node_metadata(cls, value: object) -> object:
        """Normalize Check-Host's positional `[code, country, city, ip, asn]` list."""
        if not isinstance(value, list):
            return value
        items = cast('list[object]', value)
        country = items[_NODE_INFO_COUNTRY_INDEX] if len(items) > _NODE_INFO_COUNTRY_INDEX and isinstance(items[_NODE_INFO_COUNTRY_INDEX], str) else ''
        city = items[_NODE_INFO_CITY_INDEX] if len(items) > _NODE_INFO_CITY_INDEX and isinstance(items[_NODE_INFO_CITY_INDEX], str) else ''
        return {'country': country, 'city': city}


class CheckHostPingRequestResponse(BaseModel):
    """Response returned by `GET /check-ping` when initiating a distributed ping check."""

    model_config = ConfigDict(extra='ignore')

    ok: int = 0
    request_id: str | None = None
    nodes: dict[str, CheckHostNodeInfo] | None = None


class CheckHostPingAttempt(BaseModel):
    """Single ping probe attempt reported by a Check-Host.net node."""

    model_config = ConfigDict(extra='ignore')

    status: str
    rtt_seconds: StrictFloat | StrictInt | None = None

    @model_validator(mode='before')
    @classmethod
    def _parse_attempt(cls, value: object) -> object:
        """Normalize Check-Host's positional `[status, rtt_seconds, ip?]` list."""
        if not isinstance(value, list):
            return value
        items = cast('list[object]', value)
        if not items or not isinstance(items[0], str):
            return items
        raw_rtt = items[1] if len(items) >= _ATTEMPT_MIN_FIELDS else None
        rtt_seconds: float | int | None = (
            raw_rtt
            if isinstance(raw_rtt, (int, float)) and not isinstance(raw_rtt, bool) and math.isfinite(raw_rtt)
            else None
        )
        return {'status': items[0], 'rtt_seconds': rtt_seconds}


class CheckHostPingNodeResult(BaseModel):
    """Aggregated ping probe attempts reported by one Check-Host.net node."""

    model_config = ConfigDict(extra='ignore')

    attempts: list[CheckHostPingAttempt] = Field(default_factory=list[CheckHostPingAttempt])

    @model_validator(mode='before')
    @classmethod
    def _parse_node_payload(cls, value: object) -> object:
        """Normalize Check-Host's nested per-node result array.

        Check-Host returns several shapes per node:
        - `[[["OK", 0.001, "1.1.1.1"], ["OK", 0.002], ...]]` for completed probes,
        - `[[null]]` when DNS resolution or probe setup fails on the node,
        - `[null, {"message": "..."}]` when the node itself reports an error.
        """
        if not isinstance(value, list):
            return value
        outer = cast('list[object]', value)
        if not outer or outer[0] is None:
            return {'attempts': []}
        if isinstance(outer[0], list):
            raw_attempts = cast('list[object]', outer[0])
            return {'attempts': [item for item in raw_attempts if item is not None]}
        return outer

    @property
    def successful_rtts_ms(self) -> list[float]:
        """Return round-trip times in milliseconds for all successful (`OK`) attempts."""
        return [
            float(attempt.rtt_seconds) * 1000.0
            for attempt in self.attempts
            if attempt.status == 'OK' and attempt.rtt_seconds is not None
        ]


class CheckHostPingResultResponse(BaseModel):
    """Mapping of Check-Host.net node hostnames to their ping results from `GET /check-result/{id}`."""

    model_config = ConfigDict(extra='ignore')

    nodes: dict[str, CheckHostPingNodeResult | None] = Field(default_factory=dict[str, CheckHostPingNodeResult | None])

    @model_validator(mode='before')
    @classmethod
    def _wrap_node_mapping(cls, value: object) -> object:
        """Wrap the top-level `{node_name: result}` JSON object into `nodes`."""
        if not isinstance(value, dict):
            return value
        raw_mapping = cast('dict[object, object]', value)
        if 'nodes' in raw_mapping:
            return raw_mapping
        return {'nodes': raw_mapping}
