#!/usr/bin/env python3
"""Fetch Linux-associated CVEs from NVD and store a compact local JSON cache."""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def http_get_json(url: str, headers: dict[str, str]) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def build_url(
    keyword: str,
    start_index: int,
    results_per_page: int,
    pub_start: str | None,
    pub_end: str | None,
) -> str:
    params = {
        "keywordSearch": keyword,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    if pub_start:
        params["pubStartDate"] = pub_start
    if pub_end:
        params["pubEndDate"] = pub_end
    return NVD_CVE_API + "?" + urllib.parse.urlencode(params)


def pick_english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _cvss_score_band_for_v3(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _cvss_score_band_for_v2(score: float) -> str:
    """NVD-style qualitative label for CVSS 2.0 base scores."""
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def pick_cvss(cve: dict) -> dict | None:
    """Extract primary CVSS block (v3.1 > v3.0 > v2) mirroring NVD cvssData + API-style severity object."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        raw_score = data.get("baseScore")
        if raw_score is None:
            continue
        try:
            base_score = float(raw_score)
        except (TypeError, ValueError):
            continue
        version = data.get("version")
        if version is not None and not isinstance(version, str):
            version = str(version)
        if not version:
            version = "3.1" if key == "cvssMetricV31" else "3.0" if key == "cvssMetricV30" else "2.0"
        vector = data.get("vectorString") or ""
        base_sev = data.get("baseSeverity")
        if isinstance(base_sev, str) and base_sev.strip():
            base_severity = base_sev.strip().upper()
        else:
            base_severity = (
                _cvss_score_band_for_v2(base_score)
                if key == "cvssMetricV2"
                else _cvss_score_band_for_v3(base_score)
            )
        return {
            "cvssVersion": version,
            "baseScore": base_score,
            "baseSeverity": base_severity,
            "cvssCode": vector,
        }
    return None


def extract_linux_cves(payload: dict) -> list[dict]:
    results = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        description = pick_english_description(cve)
        detail = pick_cvss(cve)
        row: dict = {
            "cve_id": cve_id,
            "description": description,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        }
        if detail:
            row["cvss_score"] = detail["baseScore"]
            row["severity"] = {
                "cvssVersion": detail["cvssVersion"],
                "baseScore": detail["baseScore"],
                "baseSeverity": detail["baseSeverity"],
                "cvssCode": detail["cvssCode"],
            }
        else:
            row["cvss_score"] = None
            row["severity"] = None
        results.append(row)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyword", default="linux")
    parser.add_argument("--max-records", type=int, default=500)
    parser.add_argument("--results-per-page", type=int, default=200)
    parser.add_argument("--days-back", type=int, default=0)
    parser.add_argument("--output-file", default="data/nvd_linux_cves.json")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--sleep-seconds", type=float, default=1.2)
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    pub_start = None
    pub_end = None
    if args.days_back > 0:
        start_dt = now - timedelta(days=args.days_back)
        pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {"User-Agent": "AMISecOnto-ISWC2026-Demo/1.0"}
    if args.api_key:
        headers["apiKey"] = args.api_key

    all_items: list[dict] = []
    start_index = 0

    while len(all_items) < args.max_records:
        page_size = min(args.results_per_page, args.max_records - len(all_items))
        url = build_url(args.keyword, start_index, page_size, pub_start, pub_end)
        payload = http_get_json(url, headers=headers)
        items = extract_linux_cves(payload)
        if not items:
            break
        all_items.extend(items)

        total = int(payload.get("totalResults", 0))
        start_index += page_size
        if start_index >= total:
            break
        time.sleep(args.sleep_seconds)

    output_path = (Path.cwd() / args.output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "source": "NVD CVE API 2.0",
        "query": {
            "keyword": args.keyword,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "max_records": args.max_records,
        },
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cves": all_items,
    }
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Saved {len(all_items)} CVEs to {output_path}")


if __name__ == "__main__":
    main()
