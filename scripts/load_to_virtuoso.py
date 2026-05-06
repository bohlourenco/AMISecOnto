#!/usr/bin/env python3
"""Load ontology and generated instance data into a Virtuoso named graph."""

from __future__ import annotations

import argparse
import urllib.parse
import urllib.request
from pathlib import Path


def request(
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: int = 120,
) -> str:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read()
    return body.decode("utf-8", errors="replace")


def upload_file(
    endpoint: str,
    graph_iri: str,
    path: Path,
    content_type: str,
    method: str,
    timeout_seconds: int,
) -> None:
    url = f"{endpoint}?{urllib.parse.urlencode({'graph-uri': graph_iri})}"
    payload = path.read_bytes()
    request(url, method=method, data=payload, headers={"Content-Type": content_type}, timeout_seconds=timeout_seconds)


def count_triples(query_endpoint: str, graph_iri: str, timeout_seconds: int) -> str:
    query = f"SELECT (COUNT(*) AS ?count) WHERE {{ GRAPH <{graph_iri}> {{ ?s ?p ?o }} }}"
    url = query_endpoint + "?" + urllib.parse.urlencode({"query": query, "format": "text/csv"})
    return request(url, timeout_seconds=timeout_seconds).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph-iri", default="http://localhost:8890/AMISecOnto")
    parser.add_argument("--crud-endpoint", default="http://localhost:8890/sparql-graph-crud")
    parser.add_argument("--query-endpoint", default="http://localhost:8890/sparql")
    parser.add_argument("--ontology-file", default="AMISecOnto.ttl")
    parser.add_argument("--data-file", default="build/amiseconto_demo_data.nt")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=900,
        help="HTTP timeout for upload and query requests (seconds).",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Append to the graph instead of replacing it with ontology + data.",
    )
    args = parser.parse_args()

    root = Path.cwd()
    ontology_file = (root / args.ontology_file).resolve()
    data_file = (root / args.data_file).resolve()

    if not args.keep_existing:
        upload_file(
            args.crud_endpoint,
            args.graph_iri,
            ontology_file,
            "text/turtle",
            "PUT",
            args.timeout_seconds,
        )
        upload_file(
            args.crud_endpoint,
            args.graph_iri,
            data_file,
            "application/n-triples",
            "POST",
            args.timeout_seconds,
        )
    else:
        upload_file(
            args.crud_endpoint,
            args.graph_iri,
            ontology_file,
            "text/turtle",
            "POST",
            args.timeout_seconds,
        )
        upload_file(
            args.crud_endpoint,
            args.graph_iri,
            data_file,
            "application/n-triples",
            "POST",
            args.timeout_seconds,
        )

    print("Graph load complete.")
    print(count_triples(args.query_endpoint, args.graph_iri, args.timeout_seconds))


if __name__ == "__main__":
    main()
