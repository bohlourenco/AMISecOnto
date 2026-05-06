#!/usr/bin/env python3
"""Run a SPARQL query file against the local Virtuoso endpoint."""

from __future__ import annotations

import argparse
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query_file", help="Path to a .rq file")
    parser.add_argument("--endpoint", default="http://localhost:8890/sparql")
    parser.add_argument("--format", default="text/csv")
    args = parser.parse_args()

    query = Path(args.query_file).read_text(encoding="utf-8")
    payload = urllib.parse.urlencode({"query": query, "format": args.format}).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": args.format,
    }
    req = urllib.request.Request(args.endpoint, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            print(response.read().decode("utf-8", errors="replace"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"SPARQL endpoint returned HTTP {exc.code} ({exc.reason}).\n"
            f"Endpoint: {args.endpoint}\n"
            f"Query file: {args.query_file}\n"
            f"Server response:\n{body}"
        ) from exc
    except URLError as exc:
        raise SystemExit(
            f"Could not reach SPARQL endpoint: {args.endpoint}\n"
            f"Reason: {exc.reason}"
        ) from exc


if __name__ == "__main__":
    main()
