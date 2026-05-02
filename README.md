# AMISecOnto: An Ontology for Cybersecurity Log and Vulnerability Analysis

Table of contents

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
### CQ1 – Which events occurred within a specific time range and satisfy selected filters?
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

### Event Lineage Tracing
## CQ5 -  Which sequence of log events led to a specific error event?
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

This query identifies error-related log events and reconstructs their temporal context by retrieving preceding and succeeding events, along with timestamps and raw messages, enabling the analysis of event sequences leading to failures.

### Authentication and Access Tracing
## CQ9 - Which authentication attempts preceded access or privilege-escalation events?
```sparql
PREFIX amis: <http://www.semanticweb.org/AMISecOnto#>
PREFIX amo: <http://www.semanticweb.org/AMISecOnto/>

SELECT ?user ?sudoEvent ?sudoTime ?command
WHERE {
  {
    SELECT ?sudoEvent ?sudoTime ?user ?command
    WHERE {
      GRAPH <http://localhost:8890/AMISecOnto-v27> {
        ?sudoEvent a amis:SudoLogEvent ;
          amis:hasTimestamp ?sudoTime ;
          amis:hasUser ?user ;
          amis:hasRawMessage ?sudoMessage .
        OPTIONAL { ?sudoEvent amis:hasCommand ?cmdDirect . }
        OPTIONAL {
          ?h1 amo:hasNextLogEvent ?sudoEvent .
          ?h1 amis:hasCommand ?cmdHop1 .
        }
        OPTIONAL {
          ?h2 amo:hasNextLogEvent ?h1b .
          ?h1b amo:hasNextLogEvent ?sudoEvent .
          ?h2 amis:hasCommand ?cmdHop2 .
        }
        OPTIONAL {
          ?h3 amo:hasNextLogEvent ?h2b .
          ?h2b amo:hasNextLogEvent ?h1c .
          ?h1c amo:hasNextLogEvent ?sudoEvent .
          ?h3 amis:hasCommand ?cmdHop3 .
        }
        OPTIONAL {
          ?h4 amo:hasNextLogEvent ?h3b .
          ?h3b amo:hasNextLogEvent ?h2c .
          ?h2c amo:hasNextLogEvent ?h1d .
          ?h1d amo:hasNextLogEvent ?sudoEvent .
          ?h4 amis:hasCommand ?cmdHop4 .
        }
        OPTIONAL {
          ?h5 amo:hasNextLogEvent ?h4b .
          ?h4b amo:hasNextLogEvent ?h3c .
          ?h3c amo:hasNextLogEvent ?h2d .
          ?h2d amo:hasNextLogEvent ?h1e .
          ?h1e amo:hasNextLogEvent ?sudoEvent .
          ?h5 amis:hasCommand ?cmdHop5 .
        }
        OPTIONAL { ?sudoEvent amis:hasMessage ?sudoMsgShort . }
        FILTER (
          CONTAINS(LCASE(STR(?sudoMessage)), "session opened") ||
          CONTAINS(LCASE(STR(?sudoMessage)), "suspicious") ||
          CONTAINS(LCASE(STR(?sudoMessage)), "sudoers")
        )
        BIND(
          COALESCE(
            ?cmdDirect,
            ?cmdHop1,
            ?cmdHop2,
            ?cmdHop3,
            ?cmdHop4,
            ?cmdHop5,
            IF(
              CONTAINS(STR(?sudoMessage), "COMMAND="),
              REPLACE(STR(?sudoMessage), "^.*COMMAND=", ""),
              COALESCE(?sudoMsgShort, STR(?sudoMessage))
            )
          ) AS ?command
        )
      }
    }
    ORDER BY DESC(?sudoTime)
    LIMIT 250
  }

  FILTER EXISTS {
    GRAPH <http://localhost:8890/AMISecOnto-v27> {
      ?authEvent a amis:AuthenticationLogEvent ;
        amis:hasTimestamp ?authTime ;
        amis:hasUser ?user ;
        amis:hasRawMessage ?authMessage .
      FILTER (?authTime <= ?sudoTime)
      FILTER (
        CONTAINS(LCASE(STR(?authMessage)), "accepted") ||
        CONTAINS(LCASE(STR(?authMessage)), "session opened") ||
        CONTAINS(LCASE(STR(?authMessage)), "authentication")
      )
    }
  }
}
ORDER BY ?sudoTime
LIMIT 100
```
This query correlates authentication events with subsequent access or privilege-escalation activities by identifying prior successful or relevant authentication attempts and linking them to sudo-related log events, reconstructing the command execution context across sequential log entries.


### 
## CQ16 - Which package installation or update events affect analysis?
```sparql
PREFIX amis: <http://www.semanticweb.org/AMISecOnto#>

SELECT ?packageEvent ?timestamp ?packageName ?version ?vulnLabel
WHERE {
  {
    SELECT ?packageEvent ?timestamp ?packageName ?version ?vulnLabel
    WHERE {
      GRAPH <http://localhost:8890/AMISecOnto-v27> {
        ?packageEvent a amis:InstalledPackageLogEvent ;
          amis:hasTimestamp ?timestamp ;
          amis:hasPackageName ?packageName ;
          amis:hasPackage ?package .
        OPTIONAL { ?packageEvent amis:hasPackageVersion ?version . }

        OPTIONAL { ?packageEvent amis:relatedToVulnerability ?v1 . }
        OPTIONAL { ?packageEvent amis:evidenceByLogEvent ?v2 . }
        OPTIONAL {
          ?component a amis:Dependency ;
            amis:hasPackageName ?packageName ;
            amis:relatedToVulnerability ?v3 .
        }
        BIND(COALESCE(?v1, ?v2, ?v3) AS ?vuln)
        BIND(IF(BOUND(?vuln), REPLACE(STR(?vuln), "^.*/", ""), "") AS ?vulnLabel)
      }
    }
  }
}
ORDER BY DESC(STRLEN(?vulnLabel)) DESC(?timestamp)
LIMIT 100
```

This query identifies package installation or update events relevant to security analysis by linking them to associated vulnerabilities (e.g., CVEs) through multiple relationship paths, enabling the detection of potentially affected components and their versions.

### 
## CQ18 -  Which audit information is required for sensitive operations?
```sparql
PREFIX amis: <http://www.semanticweb.org/AMISecOnto#>
PREFIX amo: <http://www.semanticweb.org/AMISecOnto/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

# Demo RDF links indicators with amo:hasIndicator (<.../AMISecOnto/hasIndicator>), not amis:hasIndicator (#…).
# Optional # form covers reasoning stores that align OWL to instance predicates.
# BIND yields a string for ?indicatorLabel (empty when no indicator) so UIs always show the column.
SELECT ?event ?timestamp ?host ?userName ?indicatorLabel ?message
WHERE {
  GRAPH <http://localhost:8890/AMISecOnto-v27> {
    ?event a amis:SecurityLogEvent ;
      amis:hasTimestamp ?timestamp ;
      amis:hasHostname ?host ;
      amis:hasRawMessage ?message .

    FILTER (
      CONTAINS(LCASE(STR(?message)), "sudo") ||
      CONTAINS(LCASE(STR(?message)), "su:") ||
      CONTAINS(LCASE(STR(?message)), "sensitive_read") ||
      CONTAINS(LCASE(STR(?message)), "backdoor") ||
      CONTAINS(LCASE(STR(?message)), "audit")
    )

    OPTIONAL { ?event amis:hasUserName ?userName . }
    OPTIONAL { ?event amo:hasIndicator ?i1 . }
    OPTIONAL { ?event amis:hasIndicator ?i2 . }
    BIND(COALESCE(?i1, ?i2) AS ?indicator)
    OPTIONAL { ?indicator rdfs:label ?il }
    BIND(
      IF(
        BOUND(?indicator),
        COALESCE(?il, REPLACE(STR(?indicator), "^.*/", "")),
        ""
      ) AS ?indicatorLabel
    )
  }
}
ORDER BY DESC(STRLEN(?indicatorLabel)) ?timestamp
LIMIT 200
```








