#!/usr/bin/env python3
"""
main.py — Production Streaming Entrypoint for USASpending GovCon Incumbent & Recompete Enricher
Principal: Apoorv A S (@apoorv_xs) | Partner: Argon

Executes a memory-bounded (<115MB RSS ceiling inside a 128MB container) streaming harvest
against `POST https://api.usaspending.gov/api/v2/search/spending_by_award/` and secondary
FPDS competition vulnerability enrichment via `GET https://api.usaspending.gov/api/v2/awards/{id}/`.

Pay-Per-Event (PPE) Metering:
  - `actor-start`: $0.05 once at initialization
  - `incumbent-award-harvested`: $0.03 per Pydantic-validated contract matching recompete filter
  - `recompete-vulnerability-enriched`: $0.02 per contract enriched with FPDS single-bid / ceiling data
"""

from __future__ import annotations

import asyncio
import signal
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set

try:
    from apify import Actor
    try:
        from apify.events import Event as ApifyEvent
    except ImportError:  # pragma: no cover
        ApifyEvent = None  # type: ignore[assignment]
except ImportError:  # pragma: no cover
    Actor = None  # type: ignore[assignment]
    ApifyEvent = None  # type: ignore[assignment]

from tls_resilient_harvester import (
    CompetitionVulnerabilityDetails,
    HarvesterConfig,
    IncumbentAwardRecord,
    TLSResilientHarvester,
    get_current_rss_mb,
    reclaim_memory,
)

USASPENDING_SEARCH_URL = "https://api.usaspending.gov/api/v2/search/spending_by_award/"

CONTRACT_TYPE_CODES = ["A", "B", "C", "D"]
IDV_TYPE_CODES = ["IDV_A", "IDV_B", "IDV_B_A", "IDV_B_B", "IDV_B_C", "IDV_C", "IDV_D", "IDV_E"]

SEARCH_FIELDS: List[str] = [
    "Award ID",
    "Recipient Name",
    "Recipient UEI",
    "Parent Recipient Name",
    "Start Date",
    "End Date",
    "Award Amount",
    "Total Outlays",
    "Awarding Agency",
    "Awarding Sub Agency",
    "Funding Agency",
    "Contract Award Type",
    "Description",
    "NAICS Code",
    "NAICS Description",
    "PSC Code",
    "Place of Performance State Code",
    "Last Modified Date",
    "generated_internal_id",
]


def _normalize_str_list(raw: Any) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        return [p.strip() for p in raw.split(",") if p.strip()]
    if isinstance(raw, list):
        return [str(p).strip() for p in raw if str(p).strip()]
    return []


def build_usaspending_search_payload(
    *,
    page: int,
    limit: int,
    keywords: str,
    naics_codes: List[str],
    psc_codes: List[str],
    recipient_search_text: str,
    awarding_agency_name: str,
    award_ids: List[str],
    award_type_group: str,
    min_award_amount: int,
) -> Dict[str, Any]:
    """
    Construct the JSON request body for `POST /api/v2/search/spending_by_award/`.
    Note: USAspending cannot mix `CONTRACTS` and `IDVS` in a single request unless
    supported by the specific endpoint call; defaults to `["A", "B", "C", "D"]`.
    """
    if award_type_group == "IDVS_ONLY":
        type_codes = list(IDV_TYPE_CODES)
    else:
        type_codes = list(CONTRACT_TYPE_CODES)

    now_utc = datetime.now(timezone.utc)
    start_bound = (now_utc - timedelta(days=365 * 5)).strftime("%Y-%m-%d")
    end_bound = (now_utc + timedelta(days=365)).strftime("%Y-%m-%d")

    filters: Dict[str, Any] = {
        "award_type_codes": type_codes,
        "time_period": [{"start_date": start_bound, "end_date": end_bound}],
    }

    if keywords:
        filters["keywords"] = [keywords]
    if naics_codes:
        filters["naics_codes"] = {"require": naics_codes}
    if psc_codes:
        filters["psc_codes"] = {"require": psc_codes}
    if recipient_search_text:
        filters["recipient_search_text"] = [recipient_search_text]
    if awarding_agency_name:
        filters["agencies"] = [
            {"type": "awarding", "tier": "toptier", "name": awarding_agency_name}
        ]
    if award_ids:
        filters["award_ids"] = award_ids
    if min_award_amount > 0:
        filters["award_amounts"] = [{"lower_bound": float(min_award_amount)}]

    return {
        "filters": filters,
        "fields": list(SEARCH_FIELDS),
        "page": page,
        "limit": limit,
        "sort": "End Date",
        "order": "desc",
        "subawards": False,
    }


def matches_recompete_window(
    rec: IncumbentAwardRecord,
    expiring_within_days: int,
    include_recently_expired_days: int,
) -> bool:
    """
    Client-side Period-of-Performance End Date filter applied BEFORE charging PPE.
    When `expiring_within_days == 0`, all records pass.
    When `expiring_within_days > 0`, only records with `-include_recently_expired_days <= days_until_expiration <= expiring_within_days` pass.
    """
    if expiring_within_days <= 0:
        return True
    if rec.days_until_expiration is None:
        return False
    lower_bound = -abs(include_recently_expired_days)
    return lower_bound <= rec.days_until_expiration <= expiring_within_days


async def _safe_charge(
    actor_cls: Any,
    event_name: str,
    count: int,
) -> bool:
    if count <= 0:
        return True
    if not hasattr(actor_cls, "charge"):
        return True
    try:
        charge_res = await actor_cls.charge(event_name=event_name, count=count)
        if charge_res is not None and getattr(charge_res, "event_charge_limit_reached", False):
            actor_cls.log.warning(
                f"PPE budget cap reached during event '{event_name}' (count={count}). Stopping gracefully."
            )
            return False
        return True
    except TypeError:
        await actor_cls.charge(event_name, count)
        return True
    except Exception as exc:
        actor_cls.log.warning(f"PPE charge warning for '{event_name}' (count={count}): {exc}")
        return True


async def run_harvester_pipeline(
    actor_cls: Any = None,
    transport_override: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    active_actor = actor_cls or Actor
    if active_actor is None:
        raise RuntimeError("Apify `Actor` SDK is required or must be passed via `actor_cls`.")

    t_start = time.perf_counter()
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _on_signal(sig_name: str) -> None:
        if not shutdown_event.is_set():
            active_actor.log.warning(
                f"Received {sig_name} — halting new page requests and flushing in-flight batch..."
            )
            shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _on_signal, sig.name)
        except (NotImplementedError, RuntimeError, ValueError):
            try:
                signal.signal(sig, lambda s, f, name=sig.name: _on_signal(name))
            except Exception:
                pass

    if ApifyEvent is not None and hasattr(active_actor, "on"):
        try:
            active_actor.on(ApifyEvent.ABORTING, lambda *_: _on_signal("ApifyEvent.ABORTING"))
        except Exception:
            pass

    actor_input: Dict[str, Any] = await active_actor.get_input() or {}

    keywords: str = str(actor_input.get("searchKeywords", "") or "").strip()
    naics_codes: List[str] = _normalize_str_list(actor_input.get("naicsCodes"))
    psc_codes: List[str] = _normalize_str_list(actor_input.get("pscCodes"))
    recipient_search_text: str = str(actor_input.get("recipientSearchText", "") or "").strip()
    awarding_agency_name: str = str(actor_input.get("awardingAgencyName", "") or "").strip()
    award_ids: List[str] = _normalize_str_list(actor_input.get("awardIds"))
    award_type_group: str = str(actor_input.get("awardTypeGroup", "CONTRACTS_ONLY") or "CONTRACTS_ONLY").strip()

    expiring_within_days: int = max(0, min(1825, int(actor_input.get("expiringWithinDays", 365))))
    include_recently_expired_days: int = max(0, min(365, int(actor_input.get("includeRecentlyExpiredDays", 60))))
    min_award_amount: int = max(0, int(actor_input.get("minAwardAmount", 100000)))
    max_records: int = max(1, min(10000, int(actor_input.get("maxRecords", 100))))
    enrich_vulnerability: bool = bool(actor_input.get("enrichCompetitionVulnerability", True))

    proxies: List[str] = []
    proxy_cfg_input = actor_input.get("proxyConfiguration")
    if isinstance(proxy_cfg_input, dict):
        custom_urls = proxy_cfg_input.get("proxyUrls")
        if isinstance(custom_urls, list):
            proxies.extend(str(u).strip() for u in custom_urls if str(u).strip())
        elif proxy_cfg_input.get("useApifyProxy") and hasattr(active_actor, "create_proxy_configuration"):
            try:
                proxy_cfg = await active_actor.create_proxy_configuration(
                    actor_proxy_input=proxy_cfg_input
                )
                if proxy_cfg is not None:
                    proxy_url = await proxy_cfg.new_url()
                    if proxy_url:
                        proxies.append(proxy_url)
            except Exception as exc:
                active_actor.log.debug(f"Proceeding with direct TLS impersonation (proxy init: {exc})")

    # Charge one-time `actor-start` PPE event ($0.05)
    await _safe_charge(active_actor, "actor-start", 1)

    page_size = min(50, max(25, max_records))
    config = HarvesterConfig(
        max_concurrency=6,
        page_size=page_size,
        stream_chunk_size=25,
        memory_ceiling_mb=115,
        proxies=proxies,
    )

    harvester = TLSResilientHarvester(
        config=config,
        schema_model=IncumbentAwardRecord,
        transport_override=transport_override,
    )

    active_actor.log.info(
        f"Initialized 128MB USASpending Recompete Harvester | keywords={keywords!r} "
        f"| naics={naics_codes} | expiringWithinDays={expiring_within_days} "
        f"| minAward=${min_award_amount:,} | maxRecords={max_records} "
        f"| enrichVulnerability={enrich_vulnerability} | initialRSS={get_current_rss_mb():.2f}MB"
    )

    seen_internal_ids: Set[str] = set()
    total_harvested: int = 0
    total_scanned_before_filter: int = 0
    total_vulnerabilities_enriched: int = 0
    single_bid_vulnerable_count: int = 0
    page_num: int = 1  # USASpending pagination is 1-indexed

    async with harvester:
        while total_harvested < max_records and not shutdown_event.is_set() and page_num <= 50:
            search_payload = build_usaspending_search_payload(
                page=page_num,
                limit=config.page_size,
                keywords=keywords,
                naics_codes=naics_codes,
                psc_codes=psc_codes,
                recipient_search_text=recipient_search_text,
                awarding_agency_name=awarding_agency_name,
                award_ids=award_ids,
                award_type_group=award_type_group,
                min_award_amount=min_award_amount,
            )

            try:
                envelopes, has_next, rss_mb = await harvester.fetch_award_search_page(
                    USASPENDING_SEARCH_URL,
                    json_payload=search_payload,
                )
            except Exception as exc:
                active_actor.log.error(
                    f"Page {page_num} harvest failed after retries: {exc}. Terminating pagination cleanly."
                )
                break

            if not envelopes:
                active_actor.log.info(f"Pagination complete at page {page_num} (0 records returned).")
                break

            total_scanned_before_filter += len(envelopes)
            matched_records: List[IncumbentAwardRecord] = []

            for env in envelopes:
                rec = env.record
                if rec.generated_internal_id in seen_internal_ids:
                    continue
                seen_internal_ids.add(rec.generated_internal_id)

                # Apply client-side recompete window filter BEFORE charging PPE!
                if not matches_recompete_window(
                    rec,
                    expiring_within_days=expiring_within_days,
                    include_recently_expired_days=include_recently_expired_days,
                ):
                    continue

                matched_records.append(rec)
                if total_harvested + len(matched_records) >= max_records:
                    break

            del envelopes

            if not matched_records:
                if not has_next:
                    break
                page_num += 1
                continue

            # Secondary FPDS Competition Vulnerability Enrichment (+$0.02 PPE event)
            enriched_count_in_batch = 0
            if enrich_vulnerability and not shutdown_event.is_set():
                vuln_tasks = [
                    harvester.fetch_award_vulnerability(rec.generated_internal_id)
                    for rec in matched_records
                ]
                vuln_results: List[Optional[CompetitionVulnerabilityDetails]] = await asyncio.gather(
                    *vuln_tasks, return_exceptions=False
                )
                updated_records: List[IncumbentAwardRecord] = []
                for rec, vuln in zip(matched_records, vuln_results):
                    if vuln is not None:
                        rec = rec.with_vulnerability_details(vuln)
                        enriched_count_in_batch += 1
                        if rec.single_bid_vulnerable:
                            single_bid_vulnerable_count += 1
                    updated_records.append(rec)
                matched_records = updated_records
                del vuln_results

            batch_dicts = [rec.to_dataset_dict() for rec in matched_records]
            batch_count = len(batch_dicts)
            del matched_records

            await active_actor.push_data(batch_dicts)
            del batch_dicts

            budget_ok = await _safe_charge(
                active_actor, "incumbent-award-harvested", batch_count
            )
            total_harvested += batch_count

            if enrich_vulnerability and enriched_count_in_batch > 0:
                vuln_budget_ok = await _safe_charge(
                    active_actor,
                    "recompete-vulnerability-enriched",
                    enriched_count_in_batch,
                )
                total_vulnerabilities_enriched += enriched_count_in_batch
                budget_ok = budget_ok and vuln_budget_ok

            live_rss = reclaim_memory(force_trim=(get_current_rss_mb() > 95.0))
            if live_rss > harvester.peak_rss_mb:
                harvester.peak_rss_mb = live_rss

            active_actor.log.info(
                f"Page {page_num} pushed | +{batch_count} recompete contracts "
                f"(total={total_harvested}/{max_records}, scanned={total_scanned_before_filter}) "
                f"| +{enriched_count_in_batch} FPDS vulnerability enrichments "
                f"| LiveRSS={live_rss:.2f}MB (Peak={harvester.peak_rss_mb:.2f}MB < 115MB ceiling)"
            )

            await asyncio.sleep(0)

            if not budget_ok or shutdown_event.is_set() or not has_next:
                break

            page_num += 1

    elapsed_s = round(time.perf_counter() - t_start, 3)
    final_rss = reclaim_memory(force_trim=True)
    peak_rss = max(harvester.peak_rss_mb, final_rss)
    summary = {
        "status": "aborted_gracefully" if shutdown_event.is_set() else "completed",
        "keywords": keywords,
        "naics_codes": naics_codes,
        "expiring_within_days": expiring_within_days,
        "total_scanned_before_filter": total_scanned_before_filter,
        "contracts_harvested": total_harvested,
        "vulnerabilities_enriched": total_vulnerabilities_enriched,
        "single_bid_vulnerable_contracts": single_bid_vulnerable_count,
        "pages_fetched": page_num,
        "elapsed_seconds": elapsed_s,
        "final_rss_mb": round(final_rss, 2),
        "peak_rss_mb": round(peak_rss, 2),
        "memory_ceiling_mb": config.memory_ceiling_mb,
    }

    if hasattr(active_actor, "set_value"):
        try:
            await active_actor.set_value("RUN_TELEMETRY", summary)
        except Exception:
            pass

    active_actor.log.info(
        f"Harvest finished ({summary['status']}) | Contracts={total_harvested} "
        f"| SingleBidVulnerable={single_bid_vulnerable_count} "
        f"| Enrichments={total_vulnerabilities_enriched} | Elapsed={elapsed_s}s "
        f"| FinalRSS={final_rss:.2f}MB | PeakRSS={peak_rss:.2f}MB"
    )
    return summary


async def main() -> None:
    if Actor is None:
        raise RuntimeError("Apify SDK not installed. Run `pip install apify>=2.0.0` or use `test_run_local.py`.")
    async with Actor:
        await run_harvester_pipeline(actor_cls=Actor)


if __name__ == "__main__":
    asyncio.run(main())
