# USASpending GovCon Incumbent, Expiring Contract & Recompete Enricher

[![Apify Actor](https://img.shields.io/badge/Apify_Store-USASpending_Recompete_Enricher-00C853?logo=apify)](https://apify.com/zodiacxs/usaspending-incumbent-recompete-enricher)
[![Memory Footprint](https://img.shields.io/badge/RAM_Footprint-25MB_Avg_%2F_128MB_Tier-blue)](#)
[![Pricing Model](https://img.shields.io/badge/Pricing-Pay--Per--Event_(PPE)-orange)](#)

Identify **expiring U.S. federal prime contracts, incumbent contractors (Legal Name + 12-char SAM UEI + Corporate Parent), obligated vs. ceiling dollar values, SAM.gov solicitation crosswalk IDs, and single-bid competition vulnerabilities (`Number of Offers Received == 1`)** directly from **USASpending.gov / FPDS**—with **zero API key required**.

Designed specifically for **GovCon business development (BD) teams, capture managers, 8(a)/SDVOSB/Small Business primes, and B2B lead-generation agencies (Clay / n8n / Make)** who want to target recompetes 90–365 days before the RFP drops on SAM.gov.

## Why Generic USASpending Scrapers Fail GovCon Capture Teams (And What This Actor Solves)

1. **Pre-Charge Recompete Countdown Filtering (`expiringWithinDays`):** USAspending's native `time_period` filter matches *any historical transaction action date*, returning years-old expired contracts mixed with 5-year IDIQs. This Actor parses each contract's Period of Performance `End Date`, computes `days_until_expiration` and `recompete_stage` (`RECOMPETE_IMMINENT_0_90D`, `RECOMPETE_PIPELINE_91_180D`, `RECOMPETE_HORIZON_181_365D`, `RECENTLY_EXPIRED_BRIDGE_RISK`), and filters out non-expiring contracts **before charging your Pay-Per-Event budget**.
2. **FPDS Single-Bid Vulnerability Enrichment (`enrichCompetitionVulnerability`):** Queries the secondary FPDS award detail endpoint (`/api/v2/awards/{generated_internal_id}/`) to uncover **how many bidders competed last time (`offers_received`)**. When an expiring contract was won with only **1 offer received** or under a sole-source action, `single_bid_vulnerable` is flagged `true`—giving your capture team the highest-Pwin recompete targets in federal contracting.
3. **Captures the 22,000+ Contractors SAM.gov Award Notices Miss:** Task orders under IDIQs and contract modifications/option exercises report to FPDS/USASpending without generating standalone SAM.gov Award Notices.
4. **Direct SAM.gov Solicitation Crosswalk (`solicitation_identifier`):** Extracts the underlying FPDS `solicitation_identifier` so you can join historical award records directly to our companion **[SAM.gov Federal Contract & Defense Procurement Harvester](https://apify.com/zodiacxs/sam-gov-federal-procurement-harvester)**.

## Input Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `searchKeywords` | `string` | `"cybersecurity"` | Keywords, technical capabilities, or scope phrases (e.g., `"zero trust"`, `"cloud migration"`, `"DevSecOps"`). |
| `naicsCodes` | `array<string>` | `["541511", "541512"]` | 6-digit NAICS codes to filter awards (e.g., `541511`, `541512`, `541519`, `541330`, `541611`). |
| `pscCodes` | `array<string>` | `[]` | Optional 4-character Product & Service Codes (e.g., `["D302", "D310"]`). |
| `recipientSearchText` | `string` | `""` | Optional incumbent company name or 12-character SAM UEI (e.g., `"Booz Allen"`, `"J8K2L9M4N1P2"`). |
| `awardingAgencyName` | `string` | `""` | Optional awarding toptier agency name (e.g., `"Department of Defense"`, `"Department of Veterans Affairs"`). |
| `awardIds` | `array<string>` | `[]` | Optional list of specific contract PIIDs (e.g., `["W911NF24C0088"]`) to enrich. |
| `awardTypeGroup` | `string` | `"CONTRACTS_ONLY"` | Choose `"CONTRACTS_ONLY"` (Definitive Contracts A, B, C, D) or `"IDVS_ONLY"` (IDIQs / GWACs). |
| `expiringWithinDays` | `integer` | `365` | Only harvest contracts whose Period of Performance `End Date` falls within the next `N` days (`1`–`1825`). Set to `0` to disable expiration filtering. |
| `includeRecentlyExpiredDays` | `integer` | `60` | Also include contracts that expired within the past `N` days to catch delayed recompetes and bridge contracts. |
| `minAwardAmount` | `integer` | `100000` | Minimum obligated contract value in USD (e.g., `100000` for `$100k+`). |
| `maxRecords` | `integer` | `100` | Maximum validated contracts to harvest (`1`–`10000`). Hard cap on PPE spend. |
| `enrichCompetitionVulnerability` | `boolean` | `true` | Enrich each matched contract with FPDS competition metrics (`offers_received`, `single_bid_vulnerable`, `extent_competed`, `potential_ceiling_amount`, `solicitation_identifier`) for `+$0.02/record`. |

## Pay-Per-Event (PPE) Pricing

| Event Name | Price (USD) | Trigger Condition |
| :--- | :--- | :--- |
| `actor-start` | **$0.05** | One-time initialization fee per Actor run. |
| `incumbent-award-harvested` | **$0.03** | Charged per validated contract that passes your `expiringWithinDays` recompete filter. |
| `recompete-vulnerability-enriched` | **$0.02** | Charged per contract enriched with secondary FPDS single-bid vulnerability, ceiling, and solicitation crosswalk data. |

## Sample Output Record

```json
{
  "award_id": "W911NF24C0003",
  "generated_internal_id": "CONT_AWD_W911NF24C0003_9700_-NONE-_-NONE--3",
  "incumbent_name": "VALKYRIE TACTICAL CLOUD CORP",
  "incumbent_uei": "Q1W2E3R4T5Y6",
  "parent_recipient_name": null,
  "award_amount": 355000.0,
  "potential_ceiling_amount": 2515000.0,
  "total_outlays": 278000.0,
  "start_date": "2024-10-28",
  "end_date": "2026-10-10",
  "days_until_expiration": -18,
  "recompete_stage": "RECENTLY_EXPIRED_BRIDGE_RISK",
  "single_bid_vulnerable": true,
  "offers_received": 1,
  "extent_competed": "NOT COMPETED",
  "set_aside_type": "SERVICE DISABLED VETERAN OWNED SMALL BUSINESS",
  "solicitation_identifier": "W911NF-25-R-0003",
  "pricing_type": "FIRM FIXED PRICE",
  "awarding_agency": "Department of Defense",
  "awarding_sub_agency": "Department of the Army",
  "funding_agency": "Department of Defense",
  "contracting_office_name": "DEPT OF DEFENSE ACC-APG CONTRACTING OFFICE",
  "contract_award_type": "DEFINITIVE CONTRACT",
  "naics_code": "541512",
  "naics_description": "COMPUTER SYSTEMS DESIGN SERVICES",
  "psc_code": "D310",
  "pop_state_code": "VA",
  "description": "ZERO TRUST CLOUD & CYBERSECURITY ENGINEERING TASK #3",
  "last_modified_date": "2026-10-28",
  "source_url": "https://www.usaspending.gov/award/CONT_AWD_W911NF24C0003_9700_-NONE-_-NONE--3"
}
```

## Pair With Actor #1 (`SAM.gov Harvester`)

Combine this Actor with **[SAM.gov Federal Contract & Defense Procurement Harvester](https://apify.com/zodiacxs/sam-gov-federal-procurement-harvester)** to monitor both **pre-award RFPs/Sources Sought** and **expiring incumbent contracts** across the exact same NAICS codes and defense agencies.
