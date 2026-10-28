#!/usr/bin/env python3
"""
test_run_local.py — Standalone Local Verification & 550-Record Stress Suite for Actor #2
(`usaspending-incumbent-recompete-enricher`)

Verifies:
  1. 550-record streaming harvest across `POST /api/v2/search/spending_by_award/`.
  2. Pre-charge `expiringWithinDays` client-side recompete filtering (ensuring non-expiring
     contracts are filtered out BEFORE billing PPE).
  3. Secondary `GET /api/v2/awards/{id}/` FPDS competition vulnerability enrichment
     (`offers_received`, `single_bid_vulnerable`, `potential_ceiling_amount`, `solicitation_identifier`).
  4. Adversarial HTTP 429 rate-limit and HTTP 200 WAF soft-block recovery.
  5. Graceful SIGTERM container preemption handling.
  6. Hard memory ceiling assertion: Peak & Final RSS strictly < 115.0 MB.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from main import run_harvester_pipeline
from tls_resilient_harvester import _self_test as engine_self_test


class LocalActorHarness:
    """Drop-in local simulation of `apify.Actor` for offline verification."""

    def __init__(self, actor_input: Dict[str, Any]) -> None:
        self._input = actor_input
        self.dataset: List[Dict[str, Any]] = []
        self.charge_ledger: Dict[str, int] = {}
        self.kv_store: Dict[str, Any] = {}
        self.log = logging.getLogger("apify.local_harness")

    async def get_input(self) -> Dict[str, Any]:
        return dict(self._input)

    async def push_data(self, data: Any) -> None:
        if isinstance(data, list):
            self.dataset.extend(data)
        elif isinstance(data, dict):
            self.dataset.append(data)

    async def charge(self, event_name: str, count: int = 1) -> Any:
        self.charge_ledger[event_name] = self.charge_ledger.get(event_name, 0) + int(count)

        class _ChargeResult:
            event_charge_limit_reached = False

        return _ChargeResult()

    async def set_value(self, key: str, value: Any) -> None:
        self.kv_store[key] = value


class MockUSASpendingServer:
    """
    Deterministic simulator of `api.usaspending.gov` (`/api/v2/search/spending_by_award/`
    and `/api/v2/awards/{id}/`) with injected HTTP 429 and WAF 200 faults.
    """

    def __init__(self, total_pages: int = 15, trigger_sigterm_on_page: Optional[int] = None) -> None:
        self.total_pages = total_pages
        self.request_count = 0
        self.injected_429 = False
        self.injected_waf = False
        self.trigger_sigterm_on_page = trigger_sigterm_on_page
        self.now_date = datetime.now(timezone.utc).date()

    async def handle_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]],
        json_body: Optional[Dict[str, Any]],
        headers: Dict[str, str],
        proxy: Optional[str],
    ) -> Tuple[bytes, int, Dict[str, str]]:
        self.request_count += 1
        req_id = self.request_count
        await asyncio.sleep(0.0005)

        if req_id == 2 and not self.injected_429 and self.trigger_sigterm_on_page is None:
            self.injected_429 = True
            return (
                b'{"detail": "Request was throttled."}',
                429,
                {"content-type": "application/json", "retry-after": "0.05"},
            )

        if req_id == 5 and not self.injected_waf and self.trigger_sigterm_on_page is None:
            self.injected_waf = True
            return (
                b"<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body>Block</body></html>",
                200,
                {"content-type": "text/html; charset=utf-8"},
            )

        # Secondary Award Detail Endpoint: GET /api/v2/awards/{generated_internal_id}/
        if method.upper() == "GET" and "/api/v2/awards/" in url:
            internal_id = url.rstrip("/").split("/")[-1]
            idx_num = int(internal_id.split("-")[-1]) if internal_id.split("-")[-1].isdigit() else 1
            single_bid = (idx_num % 3 == 0)
            detail_payload = {
                "generated_unique_award_id": internal_id,
                "potential_total_value_of_award": 2500000.00 + (idx_num * 5000),
                "awarding_agency": {
                    "office_agency_name": "DEPT OF DEFENSE ACC-APG CONTRACTING OFFICE",
                },
                "latest_transaction_contract_data": {
                    "number_of_offers_received": "1" if single_bid else "4",
                    "extent_competed_description": (
                        "NOT COMPETED" if single_bid else "FULL AND OPEN COMPETITION"
                    ),
                    "type_set_aside_description": (
                        "TOTAL SMALL BUSINESS SET-ASIDE (FAR 19.5)"
                        if idx_num % 2 == 0
                        else "SERVICE DISABLED VETERAN OWNED SMALL BUSINESS"
                    ),
                    "solicitation_identifier": f"W911NF-25-R-{idx_num:04d}",
                    "type_of_contract_pricing_description": "FIRM FIXED PRICE",
                },
            }
            return (
                json.dumps(detail_payload).encode("utf-8"),
                200,
                {"content-type": "application/json"},
            )

        # Primary Search Endpoint: POST /api/v2/search/spending_by_award/
        body = json_body or {}
        page = int(body.get("page", 1))
        limit = int(body.get("limit", 50))

        if self.trigger_sigterm_on_page is not None and page == self.trigger_sigterm_on_page:
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.005)

        start_idx = (page - 1) * limit
        results: List[Dict[str, Any]] = []

        incumbents = [
            ("AEGIS CYBER DEFENSE LLC", "J8K2L9M4N1P2", "AEGIS HOLDINGS INC"),
            ("PALADIN FEDERAL SYSTEMS INC", "M9N8B7V6C5X4", "PALADIN GROUP"),
            ("VALKYRIE TACTICAL CLOUD CORP", "Q1W2E3R4T5Y6", None),
            ("SENTINEL GOVCON SOLUTIONS LLC", "Z9X8C7V6B5N4", None),
        ]

        for i in range(start_idx, start_idx + limit):
            inc_name, inc_uei, parent_name = incumbents[i % len(incumbents)]
            # Every 10th record has an End Date 900 days in the future (to verify pre-charge filtering!)
            if i % 10 == 9:
                end_dt = (self.now_date + timedelta(days=900)).strftime("%Y-%m-%d")
            else:
                days_offset = (i % 300) - 20  # Between -20 days (recently expired) and +280 days
                end_dt = (self.now_date + timedelta(days=days_offset)).strftime("%Y-%m-%d")

            start_dt = (self.now_date - timedelta(days=730)).strftime("%Y-%m-%d")
            award_id = f"W911NF24C{i + 1:04d}"
            internal_id = f"CONT_AWD_{award_id}_9700_-NONE-_-NONE--{i + 1}"

            results.append(
                {
                    "Award ID": award_id,
                    "Recipient Name": inc_name,
                    "Recipient UEI": inc_uei,
                    "Parent Recipient Name": parent_name,
                    "Start Date": start_dt,
                    "End Date": end_dt,
                    "Award Amount": 350000.00 + (i * 2500),
                    "Total Outlays": 275000.00 + (i * 1500),
                    "Awarding Agency": "Department of Defense",
                    "Awarding Sub Agency": "Department of the Army",
                    "Funding Agency": "Department of Defense",
                    "Contract Award Type": "DEFINITIVE CONTRACT",
                    "Description": f"ZERO TRUST CLOUD & CYBERSECURITY ENGINEERING TASK #{i + 1}",
                    "NAICS Code": "541512" if i % 2 == 0 else "541511",
                    "NAICS Description": "COMPUTER SYSTEMS DESIGN SERVICES",
                    "PSC Code": "D310",
                    "Place of Performance State Code": "VA",
                    "Last Modified Date": self.now_date.strftime("%Y-%m-%d"),
                    "generated_internal_id": internal_id,
                }
            )

        envelope = {
            "results": results,
            "page_metadata": {
                "page": page,
                "hasNext": page < self.total_pages,
            },
        }
        return (
            json.dumps(envelope).encode("utf-8"),
            200,
            {"content-type": "application/json"},
        )


async def run_verification_suite() -> None:
    print("=" * 78)
    print("ACTOR #2 VERIFICATION SUITE: USASPENDING INCUMBENT & RECOMPETE ENRICHER")
    print("=" * 78)

    await engine_self_test()

    target_records = 550
    actor_input = {
        "searchKeywords": "zero trust cybersecurity",
        "naicsCodes": ["541511", "541512"],
        "pscCodes": ["D310"],
        "expiringWithinDays": 365,
        "includeRecentlyExpiredDays": 60,
        "minAwardAmount": 100000,
        "maxRecords": target_records,
        "enrichCompetitionVulnerability": True,
    }

    harness = LocalActorHarness(actor_input)
    mock_server = MockUSASpendingServer(total_pages=20)

    t0 = time.perf_counter()
    summary = await run_harvester_pipeline(
        actor_cls=harness,
        transport_override=mock_server.handle_request,
    )
    elapsed_s = time.perf_counter() - t0

    harvested_count = len(harness.dataset)
    assert harvested_count == target_records, f"Expected {target_records}, got {harvested_count}"

    # Verify that pre-charge recompete filtering excluded records with days_until_expiration > 365
    for row in harness.dataset:
        days = row["days_until_expiration"]
        assert -60 <= days <= 365, f"Filter breach: record with days_until_expiration={days} was billed!"
        assert row["solicitation_identifier"] is not None, "Missing enriched solicitation_identifier!"
        assert row["offers_received"] in (1, 4), f"Unexpected offers_received={row['offers_received']}"

    assert summary["total_scanned_before_filter"] > harvested_count, (
        "Expected pre-charge filter to drop 900-day future contracts before billing!"
    )

    start_charges = harness.charge_ledger.get("actor-start", 0)
    award_charges = harness.charge_ledger.get("incumbent-award-harvested", 0)
    vuln_charges = harness.charge_ledger.get("recompete-vulnerability-enriched", 0)

    assert start_charges == 1
    assert award_charges == target_records
    assert vuln_charges == target_records
    assert mock_server.injected_429 is True
    assert mock_server.injected_waf is True

    peak_rss = summary["peak_rss_mb"]
    final_rss = summary["final_rss_mb"]
    assert peak_rss < 115.0, f"Peak RSS {peak_rss:.2f}MB breached 115MB ceiling"

    if hasattr(signal, "SIGTERM") and sys.platform != "win32":
        sigterm_harness = LocalActorHarness(
            {"searchKeywords": "cyber", "maxRecords": 200, "enrichCompetitionVulnerability": False}
        )
        sigterm_server = MockUSASpendingServer(total_pages=10, trigger_sigterm_on_page=2)
        sigterm_summary = await run_harvester_pipeline(
            actor_cls=sigterm_harness,
            transport_override=sigterm_server.handle_request,
        )
        assert sigterm_summary["status"] == "aborted_gracefully"

    gross_rev_usd = (start_charges * 0.05) + (award_charges * 0.03) + (vuln_charges * 0.02)
    net_profit_usd = gross_rev_usd * 0.80 - 0.001

    print("\n" + "-" * 78)
    print("ACTOR #2 VERIFICATION SUMMARY & PPE UNIT ECONOMICS")
    print("-" * 78)
    print(f"Status                         : {summary['status'].upper()}")
    print(f"Total Scanned (Pre-Filter)     : {summary['total_scanned_before_filter']} raw FPDS awards")
    print(f"Recompete Contracts Harvested  : {harvested_count} / {target_records} (100% within recompete window)")
    print(f"Single-Bid Vulnerable Found    : {summary['single_bid_vulnerable_contracts']} vulnerable incumbents")
    print(f"Live RSS Memory (Final / Peak) : {final_rss:.2f} MB / {peak_rss:.2f} MB (Hard cap: 115.00 MB)")
    print(f"Total Execution Time           : {elapsed_s:.3f}s")
    print(f"Gross Run Revenue              : ${gross_rev_usd:.2f} (Net after 20% Apify fee: ${net_profit_usd:.2f})")
    print("-" * 78)
    print("SAMPLE ENRICHED INCUMBENT & RECOMPETE RECORD:")
    print(json.dumps(harness.dataset[2], indent=2))
    print("=" * 78)
    print("[ALL ASSERTIONS PASSED — ACTOR #2 READY FOR APIFY STORE DEPLOYMENT]")


if __name__ == "__main__":
    asyncio.run(run_verification_suite())
