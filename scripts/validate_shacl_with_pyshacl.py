#!/usr/bin/env python3
"""Validate AMISecOnto data with SHACL using pySHACL."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-file", default="build/amiseconto_demo_data.nt")
    parser.add_argument("--ontology-file", default="AMISecOnto.ttl")
    parser.add_argument("--shapes-file", default="shapes/amiseconto_cq_shapes.ttl")
    parser.add_argument("--report-file", default="build/shacl_validation_report.ttl")
    args = parser.parse_args()

    try:
        from pyshacl import validate  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            "pySHACL is not installed. Install it with: pip install pyshacl"
        ) from exc

    root = Path.cwd()
    data_file = (root / args.data_file).resolve()
    ontology_file = (root / args.ontology_file).resolve()
    shapes_file = (root / args.shapes_file).resolve()
    report_file = (root / args.report_file).resolve()
    report_file.parent.mkdir(parents=True, exist_ok=True)

    conforms, report_graph, report_text = validate(
        data_graph=str(data_file),
        shacl_graph=str(shapes_file),
        ont_graph=str(ontology_file),
        data_graph_format="nt",
        shacl_graph_format="turtle",
        ont_graph_format="turtle",
        inference="rdfs",
        advanced=True,
        debug=False,
    )

    report_graph.serialize(destination=str(report_file), format="turtle")
    print(f"Conforms: {conforms}")
    print(report_text)
    print(f"Report written to: {report_file}")


if __name__ == "__main__":
    main()
