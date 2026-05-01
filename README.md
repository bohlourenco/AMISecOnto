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
- **CQ1**: Which events occurred within a specific time range and satisfy selected filters?
- **CQ2**: Which events belong to a specific application, service, host, or component?
- **CQ3**: Which events belong to the same request or execution flow?
- **CQ4**: Which identifiers support grouping events into the same flow?

### Event Lineage Tracing
- **CQ5**: Which sequence of log events led to a specific error event?
- **CQ6**: Which events occurred before and after a given incident?
- **CQ7**: How security events correlate with system or application events?
- **CQ8**: Which entities or events represent the current analysis workflow?

### Authentication and Access Tracing
- **CQ9**: Which authentication attempts preceded access or privilege-escalation events?
- **CQ10**: Which information is required to reconstruct a user session timeline?
- **CQ11**: Which SSH events belong to the same session?
- **CQ12**: Which identifiers are consistently used for event correlation?

### Application, System, and Security Tracing
- **CQ13**: Which container lifecycle events are linked to application errors?
- **CQ14**: Which database events correlate with application requests?
- **CQ15**: Which system-level events preceded instability?
- **CQ16**: Which package installation or update events affect analysis?
- **CQ17**: Which evidence indicates that a package update caused an issue?
- **CQ18**: Which audit information is required for sensitive operations?
- **CQ19**: Which secret-management events correlate with authentication events?
- **CQ20**: Which factors complicate security trace reconstruction?

### Vulnerability Analysis and Exposure
- **CQ21**: Which installed or observed software components are affected by known vulnerabilities (CVEs)?
- **CQ22**: Which vulnerabilities are associated with specific packages, versions, or system components?
- **CQ23**: Which log events indicate the presence or activation of vulnerable components?

### Risk Assessment and Incident Reconstruction (NIS2-aligned)
- **CQ24**: Which combinations of log events and vulnerabilities indicate high-risk situations or potential compromise?
- **CQ25**: How can risk exposure be derived from log evidence, vulnerability severity (e.g., CVSS), and observed behavior?

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

# Competency Questions – SHACL Shapes and SPARQL Queries

This document provides SHACL validation shapes and SPARQL query templates aligned with the defined competency questions (CQs) for the AMISecOnto ontology.

---

## SHACL Shapes

SHACL Shapes in AMISSecOnto are used to validate the structure and quality of data in the knowledge graph. They enforce constraints on entities like events, vulnerabilities, and assets, ensuring consistency and reliability for querying and analysis.

```turtle
@prefix : <http://www.semanticweb.org/AMISecOnto#> .
@prefix amisec: <http://www.semanticweb.org/AMISecOnto/> .
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

:LogEventShape
    a sh:NodeShape ;
    sh:targetClass amisec:LogEvent ;
    sh:property [
        sh:path amisec:hasEventTimestamp ;
        sh:datatype xsd:dateTime ;
        sh:minCount 1 ;
    ] ;
    sh:property [
        sh:path :hasHostname ;
    ] ;
    sh:property [
        sh:path :correlatedWith ;
        sh:class amisec:LogEvent ;
    ] .

:ApplicationLogEventShape
    a sh:NodeShape ;
    sh:targetClass amisec:ApplicationLogEvent ;
    sh:property [
        sh:path :belongsToRequest ;
        sh:class :Request ;
    ] .

:AuthenticationEventShape
    a sh:NodeShape ;
    sh:targetClass :AuthenticationLogEvent ;
    sh:property [
        sh:path :hasSessionID ;
    ] .

:SshEventShape
    a sh:NodeShape ;
    sh:targetClass :SshLogEvent ;
    sh:property [
        sh:path :hasSessionID ;
        sh:minCount 1 ;
    ] .

:PackageEventShape
    a sh:NodeShape ;
    sh:targetClass :InstalledPackageLogEvent ;
    sh:property [
        sh:path :hasPackageName ;
        sh:minCount 1 ;
    ] .

:VulnerabilityShape
    a sh:NodeShape ;
    sh:targetClass amisec:Vulnerability ;
    sh:property [
        sh:path :hasCVSSScore ;
        sh:datatype xsd:decimal ;
    ] .

:RiskAssessmentShape
    a sh:NodeShape ;
    sh:targetClass :RiskAssessment ;
    sh:property [
        sh:path :usesEvidence ;
        sh:minCount 1 ;
    ] ;
    sh:property [
        sh:path :considers ;
        sh:minCount 1 ;
    ] .
```


## SPARQL Queries
SPARQL queries in AMISSecOnto are designed to retrieve relevant cybersecurity information from the knowledge graph, supporting tasks such as event discovery, filtering, and analysis. This approach ensures that the ontology effectively addresses practical requirements, enabling the extraction of insights related to vulnerabilities, threats, assets, and security events in real-world scenarios.

## Event Discovery and Filtering
### CQ1 – Events within a time range

```sparql
PREFIX amis: <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

SELECT ?event ?timestamp ?host ?eventType ?message
WHERE {
  GRAPH <http://localhost:8890/AMISecOnto-v27> {
    ?event a amis:LogEvent ;
           amis:hasTimestamp ?timestamp ;
           amis:hasRawMessage ?message .
    OPTIONAL { ?event amis:hasHostname ?host . }
    OPTIONAL { ?event amis:hasEventType ?eventType . }

    FILTER (
      ?timestamp >= "2025-02-21T10:00:00Z"^^xsd:dateTime &&
      ?timestamp <= "2025-02-21T10:10:00Z"^^xsd:dateTime
    )
  }
}
ORDER BY ?timestamp
LIMIT 200
```
This query returns a time-ordered list of log events with key information extracted for each event.

## CQ5 - Event lineage before and after error
```sparql
PREFIX amis: <http://www.semanticweb.org/AMISecOnto#>

SELECT ?event ?prev ?next ?timestamp ?message
WHERE {
  GRAPH <http://localhost:8890/AMISecOnto-v27> {
    ?event a amis:LogEvent ;
           amis:hasRawMessage ?message .
    OPTIONAL { ?event amis:hasTimestamp ?timestamp . }
    OPTIONAL { ?event amis:hasPreviousLogEvent ?prev . }
    OPTIONAL { ?event amis:hasNextLogEvent ?next . }

    FILTER (
      CONTAINS(LCASE(?message), "error") ||
      CONTAINS(LCASE(?message), "exception") ||
      CONTAINS(LCASE(?message), "failed")
    )
  }
}
ORDER BY ?timestamp
LIMIT 100
```














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


