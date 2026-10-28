#!/usr/bin/env python3
"""
tls_resilient_harvester.py — Ultra-Lightweight (128MB RAM) Network-Layer Harvester Engine
for USASpending.gov (FPDS) Incumbent & Recompete Vulnerability Intelligence.

Principal: Apoorv A S (@apoorv_xs) | System: THE EYE (Nexus-HAL v12.0)
Partner: Argon (High-Reasoning Sovereign Partner)

Features:
  - HTTP/2 TLS session impersonation (`curl_cffi` Chrome 124 JA3/JA4 + Akamai framing)
    supporting both JSON `POST` (`/api/v2/search/spending_by_award/`) and `GET`
    (`/api/v2/awards/{generated_internal_id}/`).
  - Pre-charge Recompete Countdown & Stage Classification (`days_until_expiration`,
    `RECOMPETE_IMMINENT_0_90D`, `RECOMPETE_PIPELINE_91_180D`, `RECOMPETE_HORIZON_181_365D`,
    `RECENTLY_EXPIRED_BRIDGE_RISK`).
  - Secondary FPDS Competition Vulnerability Enrichment (`offers_received`,
    `single_bid_vulnerable`, `extent_competed`, `potential_ceiling_amount`,
    `solicitation_identifier` for SAM.gov cross-walking).
  - Hard <115MB Live RSS guard via Linux `/proc/self/statm` & `malloc_trim(0)`.
"""

from __future__ import annotations

import asyncio
import email.utils
import gc
import itertools
import json
import logging
import os
import random
import re
import ssl
import sys
import time
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Dict, Generic, Iterable, List, Optional, Tuple, Type, TypeVar

import pydantic
from pydantic import BaseModel, Field, HttpUrl, ValidationError

PYDANTIC_V2 = int(pydantic.__version__.split(".")[0]) >= 2

if PYDANTIC_V2:
    from pydantic import ConfigDict, TypeAdapter, field_validator, model_validator
else:  # pragma: no cover
    from pydantic import parse_obj_as, parse_raw_as, root_validator, validator

    def ConfigDict(**kwargs: Any) -> Dict[str, Any]:  # type: ignore[misc]
        return kwargs

    class TypeAdapter(Generic[TypeVar("T")]):  # type: ignore[no-redef]
        def __init__(self, target_type: Any) -> None:
            self.target_type = target_type

        def validate_json(self, raw_bytes: bytes | str) -> Any:
            return parse_raw_as(self.target_type, raw_bytes)

        def validate_python(self, obj: Any) -> Any:
            return parse_obj_as(self.target_type, obj)

    def field_validator(*fields: str, **kwargs: Any) -> Callable[[Any], Any]:  # type: ignore[misc]
        return validator(*fields, allow_reuse=True)

    def model_validator(*, mode: str = "before") -> Callable[[Any], Any]:  # type: ignore[misc]
        return root_validator(pre=(mode == "before"), allow_reuse=True)

try:
    import orjson as _orjson
except ImportError:  # pragma: no cover
    _orjson = None  # type: ignore[assignment]

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession, ExtraFingerprints, Response as CurlResponse
    HAS_CURL_CFFI = True
except ImportError:  # pragma: no cover
    CurlAsyncSession = None  # type: ignore[assignment,misc]
    ExtraFingerprints = None  # type: ignore[assignment,misc]
    CurlResponse = None  # type: ignore[assignment,misc]
    HAS_CURL_CFFI = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]
    HAS_HTTPX = False

if not HAS_CURL_CFFI and not HAS_HTTPX:  # pragma: no cover
    raise RuntimeError(
        "Neither `curl_cffi` nor `httpx` is available. Install via `pip install curl-cffi>=0.7.3`."
    )

logger = logging.getLogger("argon.usaspending_harvester")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

TModel = TypeVar("TModel", bound=BaseModel)

# ---------------------------------------------------------------------------
# 1. TLS / JA3 / JA4 & HTTP/2 Akamai Fingerprint Profiles (Chrome 124+)
# ---------------------------------------------------------------------------

CHROME_124_JA3: str = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
    "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
)

CHROME_124_AKAMAI_H2: str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

CHROME_124_EXTRA_FP: Dict[str, Any] = {
    "tls_grease": True,
    "tls_permute_extensions": True,
    "tls_cert_compression": "brotli",
    "http2_stream_weight": 256,
    "http2_stream_exclusive": 1,
}

CHROME_124_HEADERS: Dict[str, str] = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json",
    "Referer": "https://www.usaspending.gov/search",
    "Origin": "https://www.usaspending.gov",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
}

_WAF_HTML_SIGNATURES: Tuple[bytes, ...] = (
    b"<!doctype html",
    b"<html",
    b"access denied",
    b"_incapsula_resource",
    b"cf-browser-verification",
    b"attention required! | cloudflare",
    b"akamai",
    b"captcha-delivery.com",
)


class WAFChallengeError(RuntimeError):
    """Raised when an upstream endpoint returns a soft WAF challenge or HTML block."""


# ---------------------------------------------------------------------------
# 2. Recompete Countdown & Vulnerability Classification Helpers
# ---------------------------------------------------------------------------

def compute_recompete_metrics(
    end_date_str: Optional[str],
    reference_date: Optional[date] = None,
) -> Tuple[Optional[int], str]:
    """
    Calculate `days_until_expiration` and actionable GovCon BD `recompete_stage`
    from a contract's Period of Performance End Date (`YYYY-MM-DD`).
    """
    if not end_date_str or not isinstance(end_date_str, str):
        return None, "UNKNOWN_END_DATE"

    cleaned = end_date_str.strip()[:10]
    try:
        end_dt = datetime.strptime(cleaned, "%Y-%m-%d").date()
    except ValueError:
        return None, "UNKNOWN_END_DATE"

    ref = reference_date or datetime.now(timezone.utc).date()
    delta_days = (end_dt - ref).days

    if delta_days < -90:
        return delta_days, "EXPIRED_HISTORICAL"
    if delta_days < 0:
        return delta_days, "RECENTLY_EXPIRED_BRIDGE_RISK"
    if delta_days <= 90:
        return delta_days, "RECOMPETE_IMMINENT_0_90D"
    if delta_days <= 180:
        return delta_days, "RECOMPETE_PIPELINE_91_180D"
    if delta_days <= 365:
        return delta_days, "RECOMPETE_HORIZON_181_365D"
    return delta_days, "ACTIVE_LONG_TERM"


# ---------------------------------------------------------------------------
# 3. Pydantic Strict Network-Layer Schema Models
# ---------------------------------------------------------------------------

class HarvesterConfig(BaseModel):
    """Strict runtime configuration for the 128MB RAM TLS Harvester."""

    if PYDANTIC_V2:
        model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)
    else:
        class Config:
            allow_mutation = False
            extra = "forbid"
            anystr_strip_whitespace = True

    impersonate: str = Field(default="chrome124", description="curl_cffi browser target")
    ja3_override: Optional[str] = Field(default=CHROME_124_JA3)
    akamai_override: Optional[str] = Field(default=CHROME_124_AKAMAI_H2)
    timeout_seconds: float = Field(default=15.0, ge=0.5, le=60.0)
    max_retries: int = Field(default=4, ge=1, le=8)
    base_backoff_seconds: float = Field(default=0.35, ge=0.05, le=10.0)
    max_concurrency: int = Field(default=6, ge=1, le=64)
    page_size: int = Field(default=50, ge=1, le=100)
    stream_chunk_size: int = Field(default=25, ge=1, le=100)
    memory_ceiling_mb: int = Field(default=115, ge=32, le=128)
    proxies: List[str] = Field(default_factory=list)


class CompetitionVulnerabilityDetails(BaseModel):
    """
    Secondary FPDS competition & pricing intelligence extracted from
    `GET https://api.usaspending.gov/api/v2/awards/{generated_internal_id}/`.
    """

    if PYDANTIC_V2:
        model_config = ConfigDict(extra="ignore", str_strip_whitespace=True, frozen=True)
    else:
        class Config:
            extra = "ignore"
            anystr_strip_whitespace = True
            allow_mutation = False

    potential_ceiling_amount: Optional[Decimal] = Field(default=None)
    offers_received: Optional[int] = Field(default=None, ge=0)
    single_bid_vulnerable: bool = Field(default=False)
    extent_competed: Optional[str] = Field(default=None)
    set_aside_type: Optional[str] = Field(default=None)
    solicitation_identifier: Optional[str] = Field(default=None)
    contracting_office_name: Optional[str] = Field(default=None)
    pricing_type: Optional[str] = Field(default=None)


def _normalize_usaspending_award_dict(
    data: Dict[str, Any],
    reference_date: Optional[date] = None,
) -> Dict[str, Any]:
    """
    Normalize a raw row from `POST /api/v2/search/spending_by_award/` (which uses
    capitalized spaced keys like `"Award ID"`, `"Recipient Name"`, `"End Date"`)
    or already snake_cased keys into canonical fields for `IncumbentAwardRecord`.
    """
    if not isinstance(data, dict):
        return data

    out: Dict[str, Any] = dict(data)

    award_id = (
        out.get("award_id")
        or out.get("Award ID")
        or out.get("piid")
        or out.get("fain")
        or out.get("uri")
    )
    if award_id is not None:
        out["award_id"] = str(award_id).strip()

    gen_id = (
        out.get("generated_internal_id")
        or out.get("internal_id")
        or (f"CONT_AWD_{out.get('award_id', 'UNKNOWN')}" if out.get("award_id") else None)
    )
    if gen_id is not None:
        out["generated_internal_id"] = str(gen_id).strip()

    incumbent_name = (
        out.get("incumbent_name")
        or out.get("Recipient Name")
        or out.get("recipient_name")
        or "UNKNOWN RECIPIENT"
    )
    out["incumbent_name"] = str(incumbent_name).strip()

    incumbent_uei = (
        out.get("incumbent_uei")
        or out.get("Recipient UEI")
        or out.get("recipient_uei")
        or out.get("uei")
    )
    out["incumbent_uei"] = str(incumbent_uei).strip() if incumbent_uei else None

    parent_name = (
        out.get("parent_recipient_name")
        or out.get("Parent Recipient Name")
    )
    out["parent_recipient_name"] = str(parent_name).strip() if parent_name else None

    raw_amt = (
        out.get("award_amount")
        if out.get("award_amount") is not None
        else out.get("Award Amount")
    )
    if isinstance(raw_amt, str):
        cleaned_amt = re.sub(r"[^\d.-]", "", raw_amt)
        out["award_amount"] = cleaned_amt if cleaned_amt else "0.00"
    elif raw_amt is not None:
        out["award_amount"] = raw_amt
    else:
        out["award_amount"] = Decimal("0.00")

    raw_outlays = (
        out.get("total_outlays")
        if out.get("total_outlays") is not None
        else out.get("Total Outlays")
    )
    if isinstance(raw_outlays, str):
        cleaned_out = re.sub(r"[^\d.-]", "", raw_outlays)
        out["total_outlays"] = cleaned_out if cleaned_out else None
    else:
        out["total_outlays"] = raw_outlays

    start_dt = out.get("start_date") or out.get("Start Date")
    out["start_date"] = str(start_dt).strip()[:10] if start_dt else None

    end_dt = out.get("end_date") or out.get("End Date")
    out["end_date"] = str(end_dt).strip()[:10] if end_dt else None

    days_left, stage = compute_recompete_metrics(out.get("end_date"), reference_date=reference_date)
    out["days_until_expiration"] = days_left
    out["recompete_stage"] = stage

    out["awarding_agency"] = (
        str(out.get("awarding_agency") or out.get("Awarding Agency") or "US-FED").strip()
    )
    sub_ag = out.get("awarding_sub_agency") or out.get("Awarding Sub Agency")
    out["awarding_sub_agency"] = str(sub_ag).strip() if sub_ag else None

    fund_ag = out.get("funding_agency") or out.get("Funding Agency")
    out["funding_agency"] = str(fund_ag).strip() if fund_ag else None

    contract_type = out.get("contract_award_type") or out.get("Contract Award Type")
    out["contract_award_type"] = str(contract_type).strip() if contract_type else None

    desc = out.get("description") or out.get("Description")
    out["description"] = str(desc).strip() if desc else None

    naics = out.get("naics_code") or out.get("NAICS Code")
    if isinstance(naics, dict):
        naics = naics.get("code")
    out["naics_code"] = str(naics).strip() if naics else None

    naics_desc = out.get("naics_description") or out.get("NAICS Description")
    out["naics_description"] = str(naics_desc).strip() if naics_desc else None

    psc = out.get("psc_code") or out.get("PSC Code")
    if isinstance(psc, dict):
        psc = psc.get("code")
    out["psc_code"] = str(psc).strip() if psc else None

    pop_state = out.get("pop_state_code") or out.get("Place of Performance State Code")
    out["pop_state_code"] = str(pop_state).strip() if pop_state else None

    last_mod = out.get("last_modified_date") or out.get("Last Modified Date")
    out["last_modified_date"] = str(last_mod).strip()[:10] if last_mod else None

    src_url = out.get("source_url")
    if not src_url and out.get("generated_internal_id"):
        src_url = f"https://www.usaspending.gov/award/{out['generated_internal_id']}"
    out["source_url"] = src_url

    return out


def extract_award_vulnerability_details(payload: Any) -> CompetitionVulnerabilityDetails:
    """
    Parse `GET https://api.usaspending.gov/api/v2/awards/{generated_internal_id}/`
    response to extract FPDS competition vulnerability and ceiling metadata.
    """
    if not isinstance(payload, dict):
        return CompetitionVulnerabilityDetails()

    txn = payload.get("latest_transaction_contract_data")
    if not isinstance(txn, dict):
        txn = {}

    # 1. Potential Total Value of Award (Ceiling)
    raw_ceiling = (
        payload.get("potential_total_value_of_award")
        or payload.get("base_and_all_options_value")
        or txn.get("potential_total_value_of_award")
    )
    ceiling_dec: Optional[Decimal] = None
    if raw_ceiling is not None:
        try:
            ceiling_dec = Decimal(str(raw_ceiling))
        except Exception:
            ceiling_dec = None

    # 2. Number of Offers Received
    raw_offers = (
        txn.get("number_of_offers_received")
        if txn.get("number_of_offers_received") is not None
        else payload.get("number_of_offers_received")
    )
    offers_int: Optional[int] = None
    if raw_offers is not None:
        try:
            offers_int = int(str(raw_offers).strip())
        except (ValueError, TypeError):
            offers_int = None

    # 3. Extent Competed
    extent_competed = (
        txn.get("extent_competed_description")
        or txn.get("extent_competed")
        or payload.get("extent_competed_description")
    )
    extent_str = str(extent_competed).strip() if extent_competed else None

    # 4. Single-Bid / Sole-Source Vulnerability Detection
    single_bid = False
    if offers_int is not None and offers_int <= 1:
        single_bid = True
    elif extent_str and any(
        kw in extent_str.upper()
        for kw in ("NOT COMPETED", "SOLE SOURCE", "ONLY ONE SOURCE", "FOLLOW-ON")
    ):
        single_bid = True

    # 5. Set-Aside Type
    set_aside = (
        txn.get("type_set_aside_description")
        or txn.get("type_set_aside")
        or payload.get("type_set_aside_description")
    )

    # 6. Solicitation Identifier (Direct Crosswalk Key to SAM.gov!)
    solicitation_id = (
        txn.get("solicitation_identifier")
        or payload.get("solicitation_identifier")
        or payload.get("solicitation_id")
    )

    # 7. Contracting Office Name
    awarding_agency_obj = payload.get("awarding_agency") if isinstance(payload.get("awarding_agency"), dict) else {}
    office_name = (
        awarding_agency_obj.get("office_agency_name")
        or txn.get("awarding_office_name")
        or payload.get("contracting_office_name")
    )

    # 8. Pricing Type
    pricing_type = (
        txn.get("type_of_contract_pricing_description")
        or txn.get("type_of_contract_pricing")
    )

    return CompetitionVulnerabilityDetails(
        potential_ceiling_amount=ceiling_dec,
        offers_received=offers_int,
        single_bid_vulnerable=single_bid,
        extent_competed=extent_str,
        set_aside_type=str(set_aside).strip() if set_aside else None,
        solicitation_identifier=str(solicitation_id).strip() if solicitation_id else None,
        contracting_office_name=str(office_name).strip() if office_name else None,
        pricing_type=str(pricing_type).strip() if pricing_type else None,
    )


class IncumbentAwardRecord(BaseModel):
    """Strict Pydantic B2B schema for USASpending Prime Contract & Recompete Intelligence."""

    if PYDANTIC_V2:
        model_config = ConfigDict(
            extra="ignore",
            str_strip_whitespace=True,
            frozen=True,
            populate_by_name=True,
        )
    else:
        class Config:
            extra = "ignore"
            anystr_strip_whitespace = True
            allow_mutation = False
            allow_population_by_field_name = True

    award_id: str = Field(min_length=2)
    generated_internal_id: str = Field(min_length=3)
    incumbent_name: str = Field(min_length=1)
    incumbent_uei: Optional[str] = Field(default=None)
    parent_recipient_name: Optional[str] = Field(default=None)
    award_amount: Decimal = Field(default=Decimal("0.00"))
    total_outlays: Optional[Decimal] = Field(default=None)
    start_date: Optional[str] = Field(default=None)
    end_date: Optional[str] = Field(default=None)
    days_until_expiration: Optional[int] = Field(default=None)
    recompete_stage: str = Field(default="UNKNOWN_END_DATE")
    awarding_agency: str = Field(default="US-FED")
    awarding_sub_agency: Optional[str] = Field(default=None)
    funding_agency: Optional[str] = Field(default=None)
    contract_award_type: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    naics_code: Optional[str] = Field(default=None)
    naics_description: Optional[str] = Field(default=None)
    psc_code: Optional[str] = Field(default=None)
    pop_state_code: Optional[str] = Field(default=None)
    last_modified_date: Optional[str] = Field(default=None)
    source_url: Optional[HttpUrl] = Field(default=None)

    # Secondary FPDS Competition Vulnerability Enrichment Fields
    potential_ceiling_amount: Optional[Decimal] = Field(default=None)
    offers_received: Optional[int] = Field(default=None)
    single_bid_vulnerable: Optional[bool] = Field(default=None)
    extent_competed: Optional[str] = Field(default=None)
    set_aside_type: Optional[str] = Field(default=None)
    solicitation_identifier: Optional[str] = Field(default=None)
    contracting_office_name: Optional[str] = Field(default=None)
    pricing_type: Optional[str] = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def preprocess_usaspending_payload(cls, values: Any) -> Any:
        if isinstance(values, dict):
            return _normalize_usaspending_award_dict(values)
        return values

    def with_vulnerability_details(
        self, details: CompetitionVulnerabilityDetails
    ) -> "IncumbentAwardRecord":
        """Return a new validated copy enriched with secondary FPDS competition metrics."""
        updates = {
            "potential_ceiling_amount": details.potential_ceiling_amount,
            "offers_received": details.offers_received,
            "single_bid_vulnerable": details.single_bid_vulnerable,
            "extent_competed": details.extent_competed,
            "set_aside_type": details.set_aside_type,
            "solicitation_identifier": details.solicitation_identifier,
            "contracting_office_name": details.contracting_office_name,
            "pricing_type": details.pricing_type,
        }
        if hasattr(self, "model_copy"):
            return self.model_copy(update=updates)
        return self.copy(update=updates)

    def to_dataset_dict(self) -> Dict[str, Any]:
        """Serialize validated model to a flat, CRM/Clay-ready JSON dict for `Actor.push_data()`."""
        return {
            "award_id": self.award_id,
            "generated_internal_id": self.generated_internal_id,
            "incumbent_name": self.incumbent_name,
            "incumbent_uei": self.incumbent_uei,
            "parent_recipient_name": self.parent_recipient_name,
            "award_amount": float(self.award_amount) if self.award_amount is not None else 0.0,
            "potential_ceiling_amount": (
                float(self.potential_ceiling_amount)
                if self.potential_ceiling_amount is not None
                else None
            ),
            "total_outlays": float(self.total_outlays) if self.total_outlays is not None else None,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "days_until_expiration": self.days_until_expiration,
            "recompete_stage": self.recompete_stage,
            "single_bid_vulnerable": self.single_bid_vulnerable,
            "offers_received": self.offers_received,
            "extent_competed": self.extent_competed,
            "set_aside_type": self.set_aside_type,
            "solicitation_identifier": self.solicitation_identifier,
            "pricing_type": self.pricing_type,
            "awarding_agency": self.awarding_agency,
            "awarding_sub_agency": self.awarding_sub_agency,
            "funding_agency": self.funding_agency,
            "contracting_office_name": self.contracting_office_name,
            "contract_award_type": self.contract_award_type,
            "naics_code": self.naics_code,
            "naics_description": self.naics_description,
            "psc_code": self.psc_code,
            "pop_state_code": self.pop_state_code,
            "description": self.description,
            "last_modified_date": self.last_modified_date,
            "source_url": str(self.source_url) if self.source_url is not None else None,
        }


class HarvestedEnvelope(BaseModel, Generic[TModel]):
    """Envelope wrapping validated record + telemetry metadata."""

    if PYDANTIC_V2:
        model_config = ConfigDict(arbitrary_types_allowed=True)
    else:
        class Config:
            arbitrary_types_allowed = True

    record: Any
    latency_ms: float
    status_code: int
    proxy_used: Optional[str] = None
    rss_memory_mb: float


# ---------------------------------------------------------------------------
# 4. Proxy Pool Rotator & Real-Time Live RSS Memory Guard
# ---------------------------------------------------------------------------

class ProxyRotator:
    """Lock-free round-robin + health-weighted proxy rotator with quarantine."""

    def __init__(self, proxy_urls: Iterable[str], quarantine_ttl: float = 60.0) -> None:
        self._proxies: List[str] = [p.strip() for p in proxy_urls if p and p.strip()]
        self._cycle = itertools.cycle(self._proxies) if self._proxies else None
        self._quarantined: Dict[str, float] = {}
        self._quarantine_ttl: float = quarantine_ttl

    def next_proxy(self) -> Optional[str]:
        if not self._proxies or self._cycle is None:
            return None
        now = time.monotonic()
        for _ in range(len(self._proxies)):
            candidate = next(self._cycle)
            unban_time = self._quarantined.get(candidate, 0.0)
            if now >= unban_time:
                if candidate in self._quarantined:
                    del self._quarantined[candidate]
                return candidate
        return random.choice(self._proxies)

    def mark_throttled(self, proxy_url: Optional[str], duration: Optional[float] = None) -> None:
        if proxy_url:
            ttl = duration if duration is not None else self._quarantine_ttl
            self._quarantined[proxy_url] = time.monotonic() + ttl


_PAGE_SIZE_BYTES: int = 4096
try:
    _PAGE_SIZE_BYTES = os.sysconf("SC_PAGE_SIZE")
except (AttributeError, ValueError, OSError):  # pragma: no cover
    pass

_LIBC_MALLOC_TRIM: Optional[Callable[[int], int]] = None
if sys.platform.startswith("linux"):
    try:
        import ctypes
        _libc = ctypes.CDLL("libc.so.6")
        if hasattr(_libc, "malloc_trim"):
            _LIBC_MALLOC_TRIM = _libc.malloc_trim
    except Exception:  # pragma: no cover
        _LIBC_MALLOC_TRIM = None


def get_current_rss_mb() -> float:
    """Return current live Resident Set Size (RSS) in MiB."""
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/statm", "rb") as f:
                parts = f.read().split()
                if len(parts) >= 2:
                    resident_pages = int(parts[1])
                    return (resident_pages * _PAGE_SIZE_BYTES) / (1024.0 * 1024.0)
        except Exception:
            pass

    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return usage / (1024.0 * 1024.0)
        return usage / 1024.0
    except ImportError:
        return 32.0


def reclaim_memory(force_trim: bool = False) -> float:
    """Run cyclic garbage collection and return freed C-heap arenas to OS kernel on Linux."""
    gc.collect()
    if force_trim and _LIBC_MALLOC_TRIM is not None:
        try:
            _LIBC_MALLOC_TRIM(0)
        except Exception:
            pass
    return get_current_rss_mb()


def _fast_json_loads(raw_bytes: bytes) -> Any:
    if _orjson is not None:
        return _orjson.loads(raw_bytes)
    return json.loads(raw_bytes.decode("utf-8", errors="replace"))


def _fast_json_dumps(payload: Any) -> bytes:
    if _orjson is not None:
        return _orjson.dumps(payload)
    return json.dumps(payload).encode("utf-8")


def _parse_retry_after(header_val: Optional[str], max_wait: float = 12.0) -> Optional[float]:
    if not header_val:
        return None
    val = header_val.strip()
    try:
        return min(max(0.05, float(val)), max_wait)
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return min(max(0.05, delta), max_wait)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 5. TLS Resilient Harvester Engine (POST + GET Support)
# ---------------------------------------------------------------------------

class TLSResilientHarvester(Generic[TModel]):
    """
    High-throughput, <128MB RAM network-layer harvester supporting both JSON POST
    and GET over `curl_cffi` HTTP/2 TLS impersonation with Pydantic validation.
    """

    RETRYABLE_STATUS_CODES = {403, 408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 524}

    def __init__(
        self,
        config: HarvesterConfig,
        schema_model: Type[TModel],
        transport_override: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.config = config
        self.schema_model = schema_model
        self._adapter: TypeAdapter[TModel] = TypeAdapter(schema_model)
        self.proxy_rotator = ProxyRotator(config.proxies)
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._session: Optional[Any] = None
        self._owns_session: bool = False
        self._transport_override = transport_override
        self._request_counter: int = 0
        self.peak_rss_mb: float = get_current_rss_mb()

    async def __aenter__(self) -> "TLSResilientHarvester[TModel]":
        await self.open()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def open(self) -> Any:
        if self._session is not None:
            return self._session

        if HAS_CURL_CFFI and CurlAsyncSession is not None:
            self._session = CurlAsyncSession(
                impersonate=self.config.impersonate,  # type: ignore[arg-type]
                max_clients=self.config.max_concurrency,
                timeout=self.config.timeout_seconds,
            )
            await self._session.__aenter__()
        elif HAS_HTTPX and httpx is not None:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            limits = httpx.Limits(
                max_connections=self.config.max_concurrency,
                max_keepalive_connections=max(2, self.config.max_concurrency // 2),
                keepalive_expiry=15.0,
            )
            self._session = httpx.AsyncClient(
                verify=ssl_ctx,
                limits=limits,
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
            )
        self._owns_session = True
        return self._session

    async def close(self) -> None:
        if self._session is not None and self._owns_session:
            try:
                if HAS_CURL_CFFI and CurlAsyncSession is not None and isinstance(self._session, CurlAsyncSession):
                    await self._session.__aexit__(None, None, None)
                elif hasattr(self._session, "aclose"):
                    await self._session.aclose()
            except Exception as exc:
                logger.debug("Ignoring non-fatal error during session close: %s", exc)
            finally:
                self._session = None
                self._owns_session = False
                reclaim_memory(force_trim=True)

    def _build_extra_fp(self) -> Any:
        if HAS_CURL_CFFI and ExtraFingerprints is not None:
            return ExtraFingerprints(**CHROME_124_EXTRA_FP)
        return None

    def _enforce_memory_guard(self, force_check: bool = False) -> float:
        rss_mb = get_current_rss_mb()
        if rss_mb > self.peak_rss_mb:
            self.peak_rss_mb = rss_mb

        soft_threshold = self.config.memory_ceiling_mb * 0.85
        if force_check or rss_mb >= soft_threshold or (self._request_counter % 20 == 0):
            rss_mb = reclaim_memory(force_trim=(rss_mb >= soft_threshold))
            if rss_mb > self.peak_rss_mb:
                self.peak_rss_mb = rss_mb
        return rss_mb

    @staticmethod
    def _is_waf_or_html_block(raw_bytes: bytes, content_type: str) -> bool:
        if not raw_bytes:
            return True
        ct_lower = (content_type or "").lower()
        head_lower = raw_bytes[:512].lstrip().lower()
        if "text/html" in ct_lower or head_lower.startswith((b"<!doctype", b"<html")):
            return True
        for sig in _WAF_HTML_SIGNATURES:
            if sig in head_lower:
                return True
        return False

    async def _execute_raw_request(
        self,
        session: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]],
        json_body: Optional[Dict[str, Any]],
        headers: Dict[str, str],
        proxy: Optional[str],
    ) -> Tuple[bytes, int, Dict[str, str]]:
        if self._transport_override is not None:
            res = self._transport_override(method, url, params, json_body, headers, proxy)
            if asyncio.iscoroutine(res):
                res = await res
            return res

        body_bytes = _fast_json_dumps(json_body) if json_body is not None else None

        if HAS_CURL_CFFI and CurlAsyncSession is not None and isinstance(session, CurlAsyncSession):
            if method.upper() == "POST":
                resp: CurlResponse = await session.post(
                    url,
                    params=params,
                    data=body_bytes,
                    headers=headers,
                    proxy=proxy,
                    timeout=self.config.timeout_seconds,
                    impersonate=self.config.impersonate,  # type: ignore[arg-type]
                    ja3=self.config.ja3_override,
                    akamai=self.config.akamai_override,
                    extra_fp=self._build_extra_fp(),
                )
            else:
                resp = await session.get(
                    url,
                    params=params,
                    headers=headers,
                    proxy=proxy,
                    timeout=self.config.timeout_seconds,
                    impersonate=self.config.impersonate,  # type: ignore[arg-type]
                    ja3=self.config.ja3_override,
                    akamai=self.config.akamai_override,
                    extra_fp=self._build_extra_fp(),
                )
            resp_headers = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
            return resp.content, int(resp.status_code), resp_headers

        if method.upper() == "POST":
            resp_hx = await session.post(
                url,
                params=params,
                content=body_bytes,
                headers=headers,
                timeout=self.config.timeout_seconds,
            )
        else:
            resp_hx = await session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.config.timeout_seconds,
            )
        resp_headers = {str(k).lower(): str(v) for k, v in resp_hx.headers.items()}
        return resp_hx.content, int(resp_hx.status_code), resp_headers

    async def _request_with_backoff(
        self,
        session: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bytes, int, Optional[str], float]:
        headers = {**CHROME_124_HEADERS, **(extra_headers or {})}
        last_exc: Optional[Exception] = None
        active_session = session or await self.open()

        for attempt in range(1, self.config.max_retries + 1):
            proxy = self.proxy_rotator.next_proxy()
            t0 = time.perf_counter()
            self._request_counter += 1
            try:
                raw_bytes, status_code, resp_headers = await self._execute_raw_request(
                    active_session,
                    method=method,
                    url=url,
                    params=params,
                    json_body=json_body,
                    headers=headers,
                    proxy=proxy,
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0

                if status_code == 200:
                    content_type = resp_headers.get("content-type", "")
                    if self._is_waf_or_html_block(raw_bytes, content_type):
                        self.proxy_rotator.mark_throttled(proxy, duration=90.0)
                        raise WAFChallengeError(
                            f"Soft WAF/HTML challenge detected on HTTP 200 from {url}"
                        )
                    return raw_bytes, status_code, proxy, elapsed_ms

                if status_code in self.RETRYABLE_STATUS_CODES:
                    self.proxy_rotator.mark_throttled(proxy)
                    retry_after = _parse_retry_after(
                        resp_headers.get("retry-after") or resp_headers.get("x-ratelimit-reset")
                    )
                    sleep_s = (
                        retry_after
                        if retry_after is not None
                        else random.uniform(
                            self.config.base_backoff_seconds,
                            min(10.0, self.config.base_backoff_seconds * (2 ** (attempt - 1))),
                        )
                    )
                    logger.warning(
                        "HTTP %d on %s %s (attempt %d/%d). Backing off %.2fs",
                        status_code,
                        method,
                        url,
                        attempt,
                        self.config.max_retries,
                        sleep_s,
                    )
                    await asyncio.sleep(sleep_s)
                    continue

                raise RuntimeError(f"Non-retryable HTTP {status_code} for {url}")

            except Exception as exc:
                last_exc = exc
                self.proxy_rotator.mark_throttled(proxy)
                if attempt >= self.config.max_retries:
                    break
                sleep_s = random.uniform(
                    self.config.base_backoff_seconds,
                    min(10.0, self.config.base_backoff_seconds * (2 ** attempt)),
                )
                logger.warning(
                    "Transport/WAF exception on %s (attempt %d/%d): %s. Retrying in %.2fs",
                    url,
                    attempt,
                    self.config.max_retries,
                    exc,
                    sleep_s,
                )
                await asyncio.sleep(sleep_s)

        raise RuntimeError(
            f"Exhausted {self.config.max_retries} retries for {url}. Last error: {last_exc}"
        )

    async def fetch_award_search_page(
        self,
        url: str,
        json_payload: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> Tuple[List[HarvestedEnvelope[TModel]], bool, float]:
        """
        Execute `POST https://api.usaspending.gov/api/v2/search/spending_by_award/`,
        validate each award row against `IncumbentAwardRecord`, and return
        `(envelopes, has_next_page, rss_mb)`.
        """
        async with self._semaphore:
            raw_bytes, status_code, proxy, latency_ms = await self._request_with_backoff(
                session or self._session,
                method="POST",
                url=url,
                json_body=json_payload,
            )
            try:
                decoded = _fast_json_loads(raw_bytes)
            finally:
                del raw_bytes

        raw_results = decoded.get("results") if isinstance(decoded, dict) else []
        page_meta = decoded.get("page_metadata") if isinstance(decoded, dict) else {}
        has_next = bool(page_meta.get("hasNext", False)) if isinstance(page_meta, dict) else False
        del decoded

        if not isinstance(raw_results, list):
            raw_results = []

        envelopes: List[HarvestedEnvelope[TModel]] = []
        per_record_latency = round(latency_ms / max(1, len(raw_results)), 2)
        rss_mb = self._enforce_memory_guard()

        for raw_item in raw_results:
            if not isinstance(raw_item, dict):
                continue
            try:
                validated: TModel = self._adapter.validate_python(raw_item)
                envelopes.append(
                    HarvestedEnvelope(
                        record=validated,
                        latency_ms=per_record_latency,
                        status_code=status_code,
                        proxy_used=proxy,
                        rss_memory_mb=rss_mb,
                    )
                )
            except ValidationError as verr:
                logger.warning(
                    "Skipping malformed USASpending award record (%s): %s",
                    raw_item.get("Award ID") or raw_item.get("award_id") or "unknown",
                    verr.errors()[0].get("msg", str(verr)) if verr.errors() else str(verr),
                )

        del raw_results
        rss_mb = self._enforce_memory_guard()
        return envelopes, has_next, rss_mb

    async def fetch_award_vulnerability(
        self,
        generated_internal_id: str,
        session: Optional[Any] = None,
    ) -> Optional[CompetitionVulnerabilityDetails]:
        """
        Fetch secondary FPDS competition & ceiling details from
        `GET https://api.usaspending.gov/api/v2/awards/{generated_internal_id}/`.
        """
        detail_url = f"https://api.usaspending.gov/api/v2/awards/{generated_internal_id}/"
        try:
            async with self._semaphore:
                raw_bytes, _, _, _ = await self._request_with_backoff(
                    session or self._session,
                    method="GET",
                    url=detail_url,
                )
                try:
                    decoded = _fast_json_loads(raw_bytes)
                finally:
                    del raw_bytes
            details = extract_award_vulnerability_details(decoded)
            del decoded
            self._enforce_memory_guard()
            return details
        except Exception as exc:
            logger.warning(
                "Secondary vulnerability enrichment failed for %s: %s",
                generated_internal_id,
                exc,
            )
            return None


async def _self_test() -> None:
    """Verify Pydantic validation, recompete stage calculation, and <115MB RSS ceiling."""
    sample_row = {
        "Award ID": "W911NF24C0088",
        "Recipient Name": "PALADIN DEFENSE SYSTEMS LLC",
        "Recipient UEI": "J8K2L9M4N1P2",
        "Parent Recipient Name": "PALADIN HOLDINGS INC",
        "Start Date": "2024-01-15",
        "End Date": "2026-12-15",
        "Award Amount": 1850000.00,
        "Total Outlays": 1420000.00,
        "Awarding Agency": "Department of Defense",
        "Awarding Sub Agency": "Department of the Army",
        "Funding Agency": "Department of Defense",
        "Contract Award Type": "DEFINITIVE CONTRACT",
        "Description": "ZERO TRUST TACTICAL NETWORK ENGINEERING",
        "NAICS Code": "541512",
        "NAICS Description": "COMPUTER SYSTEMS DESIGN SERVICES",
        "PSC Code": "D310",
        "Place of Performance State Code": "VA",
        "Last Modified Date": "2026-10-15",
        "generated_internal_id": "CONT_AWD_W911NF24C0088_9700_-NONE-_-NONE-",
    }
    adapter = TypeAdapter(IncumbentAwardRecord)
    rec = adapter.validate_python(sample_row)
    vuln = extract_award_vulnerability_details(
        {
            "potential_total_value_of_award": 4500000.00,
            "latest_transaction_contract_data": {
                "number_of_offers_received": "1",
                "extent_competed_description": "NOT COMPETED",
                "type_set_aside_description": "8(A) SOLE SOURCE",
                "solicitation_identifier": "W911NF-24-R-0019",
                "awarding_office_name": "W6QK ACC-APG",
                "type_of_contract_pricing_description": "FIRM FIXED PRICE",
            },
        }
    )
    enriched = rec.with_vulnerability_details(vuln)
    rss = get_current_rss_mb()
    assert enriched.single_bid_vulnerable is True
    assert enriched.offers_received == 1
    assert enriched.solicitation_identifier == "W911NF-24-R-0019"
    print(
        f"[SELF-TEST OK] Award={enriched.award_id} | Incumbent={enriched.incumbent_name} "
        f"| Stage={enriched.recompete_stage} ({enriched.days_until_expiration}d) "
        f"| SingleBidVulnerable={enriched.single_bid_vulnerable} | LiveRSS={rss:.2f}MB"
    )


if __name__ == "__main__":
    asyncio.run(_self_test())
