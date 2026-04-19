# AMISecOnto: An Ontology for Cybersecurity Log and Vulnerability Analysis

## Overview
**AMISecOnto** is a modular ontology designed to support cybersecurity analysis by integrating system entities, vulnerabilities, and log-based observations into a unified semantic framework.  

The ontology follows established ontology engineering best practices, emphasizing:
- Modular design
- Transparent vocabulary reuse (e.g., PROV-O, FOAF)
- Semantic interoperability
- Support for log analysis, event correlation, and vulnerability assessment

---

## Ontology Scope
AMISecOnto models key cybersecurity concepts, including:

- **System Entities** (e.g., Application, Vendor, Product)
- **Vulnerabilities** (aligned with NVD structures)
- **Log Data and Events**
- **User Activities and System Behavior**
- **Indicators and Security Evidence**

It enables linking:
- Static knowledge (e.g., vulnerabilities, configurations)
- Dynamic evidence (e.g., logs, events)

---

## Ontology Architecture
The ontology is structured into interconnected modules:

- **Entity & Vulnerability Module**
- **Log & Event Module**
- **System & Activity Module**
- **Security & Indicator Module**

These modules support:
- Separation of concerns
- Reusability
- Scalable knowledge graph construction

---

## Competency Questions (CQs)

The ontology is designed to answer the following competency questions:

### Event Discovery and Filtering
- CQ1: How are events filtered within a time range?
- CQ2: How to identify events belonging to a specific system or application?
- CQ3: How to group events within the same execution flow?
- CQ4: Which identifiers support event grouping?

### Event Lineage Tracing
- CQ5: What sequence of events led to an error?
- CQ6: How useful is pre/post-event log context?
- CQ7: How to correlate security and system events?
- CQ8: How to link security events with application logs?

### Authentication and Access Tracing
- CQ9: How to analyze authentication attempts?
- CQ10: How to reconstruct user sessions?
- CQ11: How to group SSH events into sessions?
- CQ12: Which identifiers are used for session correlation?

### Application and Container Tracing
- CQ13: How to link container lifecycle events with application errors?
- CQ14: How to correlate database and application events?

### System-Level Tracing
- CQ15: Which events precede system instability?
- CQ16: How to track package installation/update events?
- CQ17: What evidence is used when updates cause failures?

### Security Tracing
- CQ18: What audit data is needed for sensitive operations?
- CQ19: How to correlate access control events?
- CQ20: What challenges exist in trace reconstruction?

### Cross-Source Log Correlation
- CQ21: How to correlate Syslog/Journalctl with application logs?
- CQ22: What multi-source patterns are relevant?
- CQ23: What makes cross-system correlation difficult?

### Anomaly and Incident Reconstruction
- CQ24: What data is required for anomaly reconstruction?
- CQ25: What are common blockers in incident analysis?

---

## Repository Structure

AMISecOnto/  
├── ontology/  
│   └── AMISecOnto.ttl  
├── figures/  
│   ├── entity-model.png  
│   └── log-model.png  
├── docs/  
│   └── paper.pdf  
├── examples/  
│   └── sample-queries.sparql  
└── README.md


---

## Tools and Technologies
- **Protégé** for ontology development
- **OWL / RDF / Turtle**
- **SPARQL** for querying
- Reused vocabularies:
  - PROV-O
  - FOAF

---

## Usage

### Load Ontology
You can load the ontology in:
- Protégé
- RDF triple stores (e.g., OpenLink Virtuoso)
---

## Competency Question–Driven SPARQL Queries
SPARQL queries in AMISSecOnto are designed to retrieve relevant cybersecurity information from the knowledge graph, supporting tasks such as event discovery, filtering, and analysis. This approach ensures that the ontology effectively addresses practical requirements, enabling the extraction of insights related to vulnerabilities, threats, assets, and security events in real-world scenarios.

## Event Discovery and Filtering
### CQ1: When searching for events within a specific time range, which filters do you typically apply?

```sparql
PREFIX amiseconto: <http://www.semanticweb.org/AMISecOnto#>
SELECT ?eventRef ?ts ?cat ?msg
FROM <http://localhost:8890/AMISecOnto>
WHERE {
  ?event a amiseconto:LogEvent ;
         amiseconto:hasTimestamp ?ts ;
         amiseconto:hasCategory ?cat ;
         amiseconto:hasRawMessage ?msg .
  BIND(REPLACE(STR(?event), "^http://www.semanticweb.org/AMISecOnto/event/", "") AS ?eventRef)
  FILTER(STR(?ts) >= "2025-02-21T00:00:00" && STR(?ts) < "2025-02-22T00:00:00")
}
ORDER BY ?ts
LIMIT 500
```
This query returns a time-ordered list of log events with key information extracted for each event.

### CQ2: How do you identify which events belong to a specific application, service, or host?

```sparql
PREFIX amiseconto: <http://www.semanticweb.org/AMISecOnto#>
SELECT ?logRef ?logName ?cat ?eventRef ?line ?ts
FROM <http://localhost:8890/AMISecOnto>
WHERE {
  ?log a amiseconto:Log ;
       amiseconto:hasLogFileName ?logName ;
       amiseconto:hasCategory ?cat ;
       amiseconto:containsEvent ?event .
  ?event amiseconto:hasLineNumber ?line .
  BIND(REPLACE(STR(?log), "^http://www.semanticweb.org/AMISecOnto/log/", "") AS ?logRef)
  BIND(REPLACE(STR(?event), "^http://www.semanticweb.org/AMISecOnto/event/", "") AS ?eventRef)
  OPTIONAL { ?event amiseconto:hasTimestamp ?ts }
}
ORDER BY ?cat ?line
LIMIT 200
```
This query returns a structured view of log files and the events they contain.

## Event Lineage Tracing
### CQ5: What sequence of log events led to a specific error event?
```sparql
PREFIX amiseconto: <http://www.semanticweb.org/AMISecOnto#>
SELECT ?line ?msg
FROM <http://localhost:8890/AMISecOnto>
WHERE {
  ?log amiseconto:hasCategory "error_20k" ;
       amiseconto:containsEvent ?ev .
  ?ev amiseconto:hasLineNumber ?line ;
      amiseconto:hasRawMessage ?msg .
  FILTER(?line >= 130 && ?line <= 150)
}
ORDER BY ?line
```

This query returns a specific slice of log messages from an error log.

### CQ8: How to correlate security events with system or application events in your current analysis workflow?
```sparql
PREFIX amiseconto: <http://www.semanticweb.org/AMISecOnto#>
SELECT ?netRef ?hostRef ?netMsg ?hostMsg
FROM <http://localhost:8890/AMISecOnto>
WHERE {
  ?ne a amiseconto:SecurityLogEvent ;
      amiseconto:hasCategory "netfilter_20k" ;
      amiseconto:hasRawMessage ?netMsg ;
      amiseconto:correlatedWith ?he .
  ?he a amiseconto:SystemLogEvent ;
      amiseconto:hasCategory "host_20k" ;
      amiseconto:hasRawMessage ?hostMsg .
  BIND(REPLACE(STR(?ne), "^http://www.semanticweb.org/AMISecOnto/event/", "") AS ?netRef)
  BIND(REPLACE(STR(?he), "^http://www.semanticweb.org/AMISecOnto/event/", "") AS ?hostRef)
}
LIMIT 200
```
This query shows correlated pairs of security (network) events and system/application (host) events.

## Authentication and Access Tracing
### CQ9: How do you analyze authentication attempts preceding access or privilege escalation events?
```sparql
PREFIX amiseconto: <http://www.semanticweb.org/AMISecOnto#>
SELECT ?eventRef ?line ?ts ?msg
FROM <http://localhost:8890/AMISecOnto>
WHERE {
  ?event a amiseconto:SshLogEvent ;
         amiseconto:hasLineNumber ?line ;
         amiseconto:hasRawMessage ?msg .
  BIND(REPLACE(STR(?event), "^http://www.semanticweb.org/AMISecOnto/event/", "") AS ?eventRef)
  OPTIONAL { ?event amiseconto:hasTimestamp ?ts }
  FILTER(STRSTARTS(STR(?ts), "2025-02-21"))
}
ORDER BY ?line
LIMIT 200
```
This query helps you trace authentication activity (SSH) over a specific day, which is useful for identifying attempts that may precede unauthorized access or privilege escalation.


