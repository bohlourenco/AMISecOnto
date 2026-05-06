# Competency Question Query Pack

The files in this folder are a demo-oriented SPARQL pack aligned with the competency questions (CQs) from the ISWC 2026 paper.

## Ready-to-run queries

- `cq01_time_range_filtering.rq`: CQ1 and CQ2
- `cq05_event_lineage_before_after_error.rq`: CQ5 and CQ6
- `cq09_auth_before_privilege_escalation.rq`: CQ9 to CQ12
- `cq16_package_updates_and_related_vulnerabilities.rq`: CQ16 and CQ17
- `cq18_sensitive_operations.rq`: CQ18 to CQ20
- `cq21_cross_source_correlation.rq`: CQ21 (software components ↔ CVEs)
- `cq22_multi_source_attack_patterns.rq`: CQ22 (vulnerabilities ↔ packages, versions, system components)
- `cq23_multi_source_attack_patterns.rq`: CQ23 (indicator-led log correlation)
- `cq24_incident_reconstruction.rq`: CQ24 and CQ25

## How the 25 CQs map to these queries

1. CQ1: filter events by time range using `cq01_time_range_filtering.rq`
2. CQ2: add service or host filters to `cq01_time_range_filtering.rq`
3. CQ3: group by `?requestURI`, `?sessionID`, or `?user`
4. CQ4: inspect `amis:belongsToRequest`, `amis:hasSessionID`, `amo:hasUser`
5. CQ5: use `cq05_event_lineage_before_after_error.rq`
6. CQ6: use `amo:hasPreviousLogEvent` and `amo:hasNextLogEvent`
7. CQ7: join `amis:SecurityLogEvent` with `amis:SystemLogEvent` or `amis:ApplicationLogEvent` on shared host, user, request, or time window
8. CQ8: correlate events from different logs on shared `amis:hasHostname`, time windows, and correlation keys (`amis:hasRequestURI`, `amis:hasSessionID`, `amo:hasUser`); see `cq23_multi_source_attack_patterns.rq` for an indicator-based pattern
9. CQ9: use `cq09_auth_before_privilege_escalation.rq`
10. CQ10: project `?user`, `?sessionID`, `?timestamp`, `?host`, `?message`
11. CQ11: correlate SSH events on `amis:hasSessionID`, `amo:hasUser`, and `amis:hasPort`
12. CQ12: use `amis:hasSessionID`, `amis:hasUserName`, `amis:hasRequestURI`, and `amis:hasProcessID`
13. CQ13: filter catalina/application messages on exploit indicators and correlate with `amo:hasIndicator`
14. CQ14: join application requests by `amis:belongsToRequest` and `amis:hasRequestURI`
15. CQ15: filter system events on `error`, `failed`, `MaxRequestWorkers`, `crash`, or suspicious indicators
16. CQ16: use `cq16_package_updates_and_related_vulnerabilities.rq`
17. CQ17: extend CQ16 with package version filters
18. CQ18: use `cq18_sensitive_operations.rq`
19. CQ19: correlate `su`/`sudo`/SSH events by `?user` and nearby timestamps
20. CQ20: inspect missing joins across `user`, `session`, `request`, and `host`
21. CQ21: use `cq21_cross_source_correlation.rq` (dependencies and dpkg install events linked to CVEs)
22. CQ22: use `cq22_multi_source_attack_patterns.rq` (CVEs linked to JAR dependencies, dpkg events, and `amo:hasVulnerability` on systems)
23. CQ23: use `cq23_multi_source_attack_patterns.rq` and compare counts with and without shared `requestURI`, `sessionID`, and `user`
24. CQ24: use `cq24_incident_reconstruction.rq`
25. CQ25: inspect events that have only raw messages and no correlation anchors

## Adapting the queries

The generated graph exposes these practical anchors:

- `amis:hasTimestamp`
- `amis:hasHostname`
- `amo:hasUser` and `amis:hasUserName`
- `amis:hasSessionID`
- `amis:belongsToRequest`
- `amis:hasRequestURI`
- `amis:hasCommand`
- `amo:hasIndicator`
- `amis:evidenceByLogEvent`
- `amo:hasPreviousLogEvent` and `amo:hasNextLogEvent`

For the paper/demo, it is usually enough to say that the CQ set was operationalized into SPARQL query templates, then show a few representative examples from the ready-to-run files above.
