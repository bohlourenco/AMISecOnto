# AMISecOnto ISWC 2026 Demo Scripts

This workspace now contains a lightweight demo pipeline to support the Resource Track submission:

1. Parse the `log_20k_AMISecOnto` dataset into RDF instance data aligned with `AMISecOnto.ttl`
2. Fetch Linux-associated CVEs from NVD
3. Load ontology + generated triples into the Virtuoso named graph `http://localhost:8890/AMISecOnto`
4. Run SPARQL queries derived from the competency questions in the article
5. Validate graph quality with SHACL rules aligned with the CQ/SPARQL layer

## Files

- `scripts/build_amiseconto_demo_graph.py`: builds instance triples in N-Triples format
- `scripts/fetch_nvd_linux_cves.py`: fetches Linux-associated CVEs from NVD API 2.0
- `scripts/load_to_virtuoso.py`: loads ontology and instance data into Virtuoso
- `scripts/query_virtuoso.py`: runs a `.rq` file against `http://localhost:8890/sparql`
- `scripts/validate_shacl_with_pyshacl.py`: validates data against SHACL shapes
- `data/curated_vulnerabilities.json`: small curated vulnerability seed for the dependency demo
- `queries/competency_questions/`: runnable SPARQL examples plus CQ mapping notes
- `shapes/amiseconto_cq_shapes.ttl`: SHACL rules for CQ/SPARQL consistency checks

## 1. Fetch Linux vulnerabilities from NVD

```bash
python3 scripts/fetch_nvd_linux_cves.py --max-records 500
```

Optional (recommended) if you have an NVD key:

```bash
python3 scripts/fetch_nvd_linux_cves.py --api-key "$NVD_API_KEY" --max-records 1000
```

Output:

- `data/nvd_linux_cves.json`

## 2. Build the RDF data

```bash
python3 scripts/build_amiseconto_demo_graph.py
```

Outputs:

- `build/amiseconto_demo_data.nt`
- `build/amiseconto_demo_stats.json`

## 3. Load into Virtuoso

```bash
python3 scripts/load_to_virtuoso.py
```

By default this:

- replaces the target named graph with the ontology
- appends the generated instance triples

If you want to append instead of replacing:

```bash
python3 scripts/load_to_virtuoso.py --keep-existing
```

## 4. Run example SPARQL queries

```bash
python3 scripts/query_virtuoso.py queries/competency_questions/cq01_time_range_filtering.rq
python3 scripts/query_virtuoso.py queries/competency_questions/cq09_auth_before_privilege_escalation.rq
python3 scripts/query_virtuoso.py queries/competency_questions/cq24_incident_reconstruction.rq
```

## 5. Run SHACL validation

Install validator:

```bash
pip install pyshacl
```

Run:

```bash
python3 scripts/validate_shacl_with_pyshacl.py
```

Output:

- `build/shacl_validation_report.ttl`

The SHACL rules focus on the constraints needed by your SPARQL query set:

- mandatory core properties for `amis:LogEvent`
- event lineage consistency (`hasPreviousLogEvent`/`hasNextLogEvent`)
- auth/session requirements for authentication tracing queries
- indicator and attribution expectations for security events
- package-event integrity for update/vulnerability queries
- request correlation completeness for cross-source analysis
- vulnerability metadata quality for NVD integration

## Modeling notes

The builder focuses on the parts of the ontology that are most useful for the paper demo:

- log/event population
- host, user, package, dependency, and component entities
- suspicious indicators inferred from log content
- event sequencing using `amis:hasPreviousLogEvent` and `amis:hasNextLogEvent`
- dependency-to-vulnerability links from a curated seed file
- runtime evidence-to-vulnerability links for visible exploit patterns such as Log4Shell-style entries

This is intentionally a demo-oriented pipeline rather than a full production ETL. It is designed to make the paper easy to present, reproduce, and query locally in Virtuoso.
