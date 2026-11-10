
<p align="center">
  <img src="figures/amiseconto-logo.png" alt="AMISecOnto Logo" width="140"/>
</p>

# AMISecOnto
This repository contains all development for the project's ontology/knowledge model, a domain-specific ontology designed to support NIS2-compliant cybersecurity analysis in academic management information systems (AMIS) through standardized and semantically enriched knowledge representation. The ontology formally models the complete cybersecurity monitoring and incident-analysis workflow, integrating heterogeneous log evidence (system, application, and security logs), software supply-chain and asset information, vulnerability intelligence (CVE, CPE, CWE, and CVSS), and risk-aware analysis aligned with NIS2 Article 21 obligations. Built upon foundational upper ontologies, such as DOLCE, and reusing established provenance, actor-identity, IT-service-management, and risk-treatment ontologies (PROV-O, FOAF, ITSMO, and ROSE), AMISecOnto ensures interoperability, extensibility, and compliance with FAIR principles. This repository includes a total of 12 competency questions, the corresponding SPARQL queries, the ontology in OWL/Turtle format, and synthetic example datasets (FénixEdu logs and NVD vulnerability records), as well as supporting documentation demonstrating the interoperability of AMISecOnto with major cybersecurity and Semantic Web standards.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Test Log Dataset](#test-log-dataset)
- [Competency Question (CQ) – Driven SPARQL Queries](#competency-question-cq--driven-sparql-queries)
- [Competency Question (CQ)](#competency-question-cq)
- [SPARQL Queries](#sparql-queries)
  - [Event Discovery and Filtering](#event-discovery-and-filtering)
  - [Event Lineage Tracing](#event-lineage-tracing)
  - [Authentication and Access Tracing](#authentication-and-access-tracing)
  - [Application, System, and Security Tracing](#application-system-and-security-tracing)
  - [Vulnerability Analysis and Exposure](#vulnerability-analysis-and-exposure)
  - [Risk Assessment and Incident Reconstruction (NIS2-Aligned)](#risk-assessment-and-incident-reconstruction-nis2-aligned)
- [Competency Question Traceability Matrix](#competency-question-traceability-matrix)
- [Alignment Classes with External Ontologies](#alignment-classes-with-external-ontologies)
- [Interoperability Mapping with External Ontologies](#interoperability-mapping-with-external-ontologies)
- [Ontology Modules](#ontology-modules)
  - [Asset Module](#asset-module)
  - [Log and Event Module](#log-and-event-module)
  - [Vulnerability Module](#vulnerability-module)
  - [Risk Analysis Module](#risk-analysis-module)
  - [Software Supply-Chain Module](#software-supply-chain-module)


## Overview

**AMISecOnto** is a modular cybersecurity ontology that transforms heterogeneous data, such as AMIS system logs and vulnerability intelligence (e.g., NVD), into a unified semantic knowledge graph for advanced security analysis.

---

## Key Features

- **Integrated data ingestion**: Combines raw logs with vulnerability data for contextual enrichment  
- **Modular design**: Core modules for Entities, Vulnerabilities, and Standards  
- **Semantic enrichment**: Links events to CVE, CPE, and CVSS information  
- **Standards-based**: RDF, OWL  
- **Interoperability & provenance**: Ensures traceability and cross-system integration  
- **Analytics-ready**:
  - Event correlation  
  - Risk assessment  
  - Incident reconstruction  
  - Evidence tracing  

---

# Test Log Dataset

Each non-empty line of the Synthetic Log Dataser is one entry. A line is an **attack** when it matches a named attack: Log4Shell, Spring4Shell, path traversal, command injection, SSRF, prototype pollution, credential attack, privilege escalation, or a CVE identifier. It is **suspicious** when the only signal is a sensitive read (`password`, `/etc/shadow`, or an audit key such as `sensitive_read`). Otherwise it is **normal**. A line that matches both an attack and a sensitive read is counted as an attack.

| Log | Entries | Normal | Attack | Suspicious |
|---|---:|---:|---:|---:|
| access_20k.log | 20,000 | 18,494 (92.47%) | 1,370 (6.85%) | 136 (0.68%) |
| ssh.log | 20,000 | 7,950 (39.75%) | 4,036 (20.18%) | 8,014 (40.07%) |
| sudo_20k.log | 20,000 | 20,000 (100%) | 0 | 0 |
| su_20k.log | 20,000 | 18,988 (94.94%) | 523 (2.62%) | 489 (2.44%) |
| catalina_20k.log | 20,000 | 17,073 (85.36%) | 2,927 (14.63%) | 0 |
| error_20k.log | 20,000 | 17,562 (87.81%) | 2,438 (12.19%) | 0 |
| audit_20k.log | 31,690 | 28,064 (88.56%) | 1,999 (6.31%) | 1,627 (5.13%) |
| dpkg_20k.log | 1,067 | 1,067 (100%) | 0 | 0 |
| fenix.dependencies.txt | 20,001 | 20,001 (100%) | 0 | 0 |

`audit_20k.log` contains 31,690 lines, and `fenix.dependencies.txt` contains 20,001 lines. Every other `20k` log contains 20,000 lines. None of the files contain blank lines.

On `ssh.log`, the 8,014 suspicious lines are `Failed password` lines, because the text contains "password". The 4,036 attacks are `Invalid user` lines. `catalina_20k.log` and `error_20k.log` contain the exploit strings (Log4Shell, Spring4Shell, path traversal, command injection, and SSRF). `sudo_20k.log`, `dpkg_20k.log`, and `fenix.dependencies.txt` contain no attack or suspicious lines.


---

# Triple statistics
The AMISecOntov knowledge graph in Apache Jena holds **3,151,734 triples** in the default graph. There are **185,478** distinct subjects and **124** predicates.
**2,685,459** of those triples (85.20%) belong to log events. The other **466,275** describe the logs themselves, hosts, users, packages, the Maven tree, and the 33 vulnerabilities.
| Log | Events | Event triples | Suspicious events | Vulnerability links |
|---|---:|---:|---:|---:|
| access_20k.log | 20,000 | 439,296 | 1,506 | 0 |
| ssh.log | 20,000 | 384,099 | 12,050 | 0 |
| sudo_20k.log | 20,000 | 379,999 | 0 | 0 |
| su_20k.log | 20,000 | 324,772 | 1,012 | 0 |
| catalina_20k.log | 20,000 | 322,908 | 2,927 | 80 |
| error_20k.log | 20,000 | 345,503 | 2,438 | 0 |
| audit_20k.log | 31,690 | 474,563 | 3,626 | 0 |
| dpkg_20k.log | 1,067 | 14,319 | 0 | 0 |
| **Total** | **152,757** | **2,685,459** | **23,559** | **80** |

`SuspiciousEvent` is any event the graph marks with a threat indicator. That includes attacks. Only `catalina_20k.log` has `relatedToVulnerability` links, and there are 80 of them. The graph contains **33** `Vulnerability` individuals, **33** CVSS metrics, **9** CPE entries, and **229** references.

The largest predicates are:
| Predicate | Triples |
|---|---:|
| rdf:type | 596,564 |
| containsEvent | 152,757 |
| hasHost | 152,757 |
| hasRawMessage | 152,757 |
| registersLogEvent | 152,757 |
| hasNextLogEvent | 152,749 |
| hasEventTimestamp | 150,022 |
| hasOutcome | 135,709 |
| hasEventType | 129,274 |
| hasProcessName | 118,857 |

Outside the logs, the graph also has **7,706** Maven artifacts, **135** system packages, **4,137** IP addresses, **37** users, **23** hosts, **1** system, and **1** operating system.

---

## Competency Question (CQ) – Driven SPARQL Queries
The ontology is designed to answer the following competency questions:

### Event Discovery and Filtering
- **CQ1**: Which events occurred within a specific time range and satisfy selected filters?
- **CQ2**: Which events belong to a specific application, service, host, or component?

### Event Lineage Tracing
- **CQ3**: Which sequence of log events led to a specific error event?
- **CQ4**: Which events occurred before and after a given incident?

### Authentication and Access Tracing
- **CQ5**: Which authentication attempts preceded access or privilege-escalation events?
- **CQ6**: Which information is required to reconstruct a user session timeline?

### Application, System, and Security Tracing
- **CQ7**: Which container lifecycle events are linked to application errors?
- **CQ8**: Which database events correlate with application requests?

### Vulnerability Analysis and Exposure
- **CQ9**: Which installed or observed software components are affected by known vulnerabilities (CVEs)?
- **CQ10**: Which vulnerabilities are associated with specific packages, versions, or system components?

### Risk Assessment and Incident Reconstruction (NIS2-aligned)
- **CQ11**: Which combinations of log events and vulnerabilities indicate high-risk situations or potential compromise?
- **CQ12**: How can risk exposure be derived from log evidence, vulnerability severity (e.g., CVSS), and observed behavior?

---

## SPARQL Queries
SPARQL queries in AMISSecOnto are designed to retrieve relevant cybersecurity information from the knowledge graph, supporting tasks such as event discovery, filtering, and analysis. This approach ensures that the ontology effectively addresses practical requirements, enabling the extraction of insights related to vulnerabilities, threats, assets, and security events in real-world scenarios.

## Event Discovery and Filtering
Consider for the following SPARQL queries:

### CQ1 – Which events occurred within a specific time range and satisfy selected filters?
```sparql
PREFIX : <https://bohlourenco.github.io/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

SELECT ?event ?timestamp ?hostname ?eventType ?logLevel
WHERE {
  ?event a :LogEvent ;
         :hasEventTimestamp ?timestamp ;
         :hasHost ?host .
  ?host :hasHostname ?hostname .

  OPTIONAL { ?event :hasLogLevel  ?logLevel }
  OPTIONAL { ?event :hasEventType ?eventType }

  FILTER (?timestamp >= "2026-01-01T00:00:00"^^xsd:dateTime &&
          ?timestamp <  "2026-02-01T00:00:00"^^xsd:dateTime)
  FILTER (?hostname = "webapp01")
}
ORDER BY ?timestamp

```
This query retrieves log events within a specific time range, optionally filtered by log level, hostname, or event type.

### CQ2 — Which events belong to a specific application, service, host, or component? 
```sparql
PREFIX : <https://bohlourenco.github.io/AMISecOnto#>
PREFIX app: <https://bohlourenco.github.io/AMISecOnto/data/application/>
PREFIX pkg: <https://bohlourenco.github.io/AMISecOnto/data/package/dpkg/>

SELECT ?event ?timestamp ?hostname ?application ?component
WHERE {
  ?event a :LogEvent ;
         :hasEventTimestamp ?timestamp ;
         :hasHost ?host .
  ?host :hasHostname ?hostname .

  ?system :registersLogEvent ?event .
  ?application :runsOn ?system .

  OPTIONAL { ?event :hasPackage ?component }

  FILTER (?hostname = "webapp01")
  # FILTER (?application = app:fenix-webapp)
  # FILTER (?component = pkg:man-db/2.9.4-2)
}
ORDER BY ?timestamp
```
This query returns a time-ordered list of log events with key information extracted for each event.

### Event Lineage Tracing
## CQ3 — Which sequence of log events led to a specific error event?
```sparql
SELECT ?precedingEvent ?timestamp ?eventType ?message
WHERE {
  VALUES ?targetError { :ErrorEvent_123 }   # the specific error event

  ?targetError :hasPreviousLogEvent* ?precedingEvent .

  ?precedingEvent :hasEventTimestamp ?timestamp .
  OPTIONAL { ?precedingEvent :hasEventType ?eventType }
  OPTIONAL { ?precedingEvent :hasTextMessage ?message }
}
ORDER BY ?timestamp
```
This query identifies error-related log events and reconstructs their temporal context by retrieving preceding and succeeding events, along with timestamps and raw messages, enabling the analysis of event sequences leading to failures.

## CQ4 — Which events occurred before and after a given incident?
```sparql
SELECT ?event ?timestamp ?relation
WHERE {
  VALUES ?incident { :IncidentEvent_456 }
  ?incident :hasEventTimestamp ?incidentTime .

  ?event a :LogEvent ;
         :hasEventTimestamp ?timestamp .
  FILTER (?event != ?incident)

  BIND (IF(?timestamp < ?incidentTime, "before", "after") AS ?relation)

  # keep to a reasonable window, e.g. +/- 1 hour
  FILTER (?timestamp >= (?incidentTime - "PT1H"^^xsd:duration) &&
          ?timestamp <= (?incidentTime + "PT1H"^^xsd:duration))
}
ORDER BY ?timestamp
```
This query finds log events occurring within a time window around a specific incident, labeling each as occurring before or after it to support incident reconstruction.

### Authentication and Access Tracing
## CQ5 - Which authentication attempts preceded access or privilege-escalation events?
```sparql
SELECT ?authEvent ?authTime ?username ?privEvent ?privTime ?privType
WHERE {
  ?authEvent a :AuthenticationLogEvent ;
             :hasEventTimestamp ?authTime .
  OPTIONAL { ?authEvent :hasUserName ?username }
  OPTIONAL { ?authEvent :hasHostname ?authHost }

  # Access event (AccessLogEvent) OR privilege escalation (SudoLogEvent / SuLogEvent)
  ?privEvent a ?privType ;
             :hasEventTimestamp ?privTime .
  FILTER (?privType IN (:AccessLogEvent, :SudoLogEvent, :SuLogEvent))

  OPTIONAL { ?privEvent :hasHostname ?privHost }

  FILTER (?authTime < ?privTime)
  FILTER (!BOUND(?authHost) || !BOUND(?privHost) || ?authHost = ?privHost)
}
ORDER BY ?privTime ?authTime
```
This query correlates authentication events with subsequent access or privilege-escalation activities by identifying prior successful or relevant authentication attempts and linking them to sudo-related log events, reconstructing the command execution context across sequential log entries.

## CQ6 - Which authentication attempts preceded access or privilege-escalation events?
```sparql
SELECT ?event ?timestamp ?eventClass ?sessionID ?username ?sessionStatus ?hostname
WHERE {
  VALUES ?user { :User_alice }

  ?event a :LogEvent ;
         a ?eventClass ;
         :hasEventTimestamp ?timestamp .

  { ?event :hasUser ?user }
  UNION
  { ?event :hasSessionID ?sessionID }
  UNION
  { ?event :hasUserName ?username }

  OPTIONAL { ?event :hasSessionID     ?sessionID }
  OPTIONAL { ?event :hasSessionStatus ?sessionStatus }
  OPTIONAL { ?event :hasHostname      ?hostname }
  OPTIONAL { ?event :hasUserName      ?username }

  FILTER (?eventClass != :LogEvent)   # keep the most specific type
}
```
This query collects every log event associated with a specific user, via their identity, session ID, or username, along with session status and host context, to reconstruct a chronological timeline of that user's session activity.

### Application, system, and security tracing 
## CQ07 - Which container lifecycle events are linked to application errors?
```sparql
SELECT ?containerEvent ?containerTime ?membershipStatus ?errorEvent ?errorTime ?exceptionType
WHERE {
  ?containerEvent a :ContainerLogEvent ;
                   :hasEventTimestamp ?containerTime .
  OPTIONAL { ?containerEvent :hasMembershipStatus ?membershipStatus }

  ?errorEvent a :ErrorLogEvent ;
              :hasEventTimestamp ?errorTime .
  OPTIONAL { ?errorEvent :hasExceptionType ?exceptionType }

  # Linked via explicit correlation or the shared next/previous chain
  { ?containerEvent :correlatedWith ?errorEvent }
  UNION
  { ?containerEvent :hasNextLogEvent+ ?errorEvent }
}
ORDER BY ?containerTime
```
This query links container lifecycle events to application errors, via explicit correlation or a shared event sequence chain.

## CQ08 - Which database events correlate with application requests?
```sparql
SELECT ?dbEvent ?dbTime ?exceptionType ?request ?requestURI ?correlatedEvent
WHERE {
  ?dbEvent a :ApplicationLogEvent ;
           :hasEventTimestamp ?dbTime ;
           :belongsToRequest ?request .

  OPTIONAL { ?dbEvent :hasExceptionType ?exceptionType
             FILTER (CONTAINS(LCASE(?exceptionType), "sql")) }

  ?request a :Request .
  OPTIONAL { ?request :hasRequestURI ?requestURI }   # via AccessLogEvent side if present

  OPTIONAL { ?dbEvent :correlatedWith ?correlatedEvent }
}
ORDER BY ?dbTime
```
This query identifies package installation or update events relevant to security analysis by linking them to associated vulnerabilities (e.g., CVEs) through multiple relationship paths, enabling the detection of potentially affected components and their versions.


### Vulnerability analysis and exposure
Consider for the following SPARQL queries the prefixes below.
```sparql
PREFIX : <https://bohlourenco.github.io/AMISecOnto#>
PREFIX rose: <http://rose.com#>
```

## CQ09 - Which installed or observed software components are affected by known vulnerabilities (CVEs)?
```sparql
SELECT ?component ?componentName ?system ?vulnerability ?cveId
WHERE {
  {
    # Installed system packages
    ?component a :SystemPackage ;
               :installedOn ?system .
    OPTIONAL { ?component :hasPackageName ?componentName }
  }
  UNION
  {
    # Software components declared/observed in an application
    ?component a :SoftwareComponent .
    OPTIONAL { ?component :hasVersion ?componentName }
  }

  { ?component :relatedToVulnerability ?vulnerability }
  UNION
  { ?component :exposes ?vulnerability }
  UNION
  { ?component :hasVulnerability ?vulnerability }

  ?vulnerability :hasCVEId ?cveId .
}
ORDER BY ?cveId
```
This query identifies installed system packages or observed software components and links each one to the known CVEs it is affected by, exposed to, or declared to have.

## CQ10 - Which installed or observed software components are affected by known vulnerabilities (CVEs)?
```sparql
SELECT ?vulnerability ?cveId ?product ?vendor ?versionMin ?versionMax ?packageVersion
WHERE {
  ?vulnerability a rose:Vulnerability ;
                 :hasCVEId ?cveId .

  OPTIONAL {
    ?vulnerability :relatedToProduct ?product .
  }
}
```
This query links known vulnerabilities (by CVE ID) to the affected products, their vendors, and the specific version ranges impacted.

### Risk assessment and incident reconstruction (NIS2-aligned)
Consider for the following SPARQL queries the prefixes below.

```sparql
PREFIX :     <http://www.semanticweb.org/AMISecOnto#>
PREFIX rose: <http://rose.com#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
```

## CQ11 - Which combinations of log events and vulnerabilities indicate high-risk situations or potential compromise?
```sparql
SELECT ?riskAssessment ?logEvent ?eventTime ?vulnerability ?cveId ?riskLevel
WHERE {
  ?riskAssessment a :RiskAssessment ;
                  :usesEvidence ?logEvent ;
                  :identifies   ?vulnerability .

  OPTIONAL { ?riskAssessment skos:hasRiskLevel ?riskLevel }
  OPTIONAL { ?riskAssessment :producesRiskLevel ?riskLevel }

  ?logEvent :hasEventTimestamp ?eventTime .
  ?vulnerability :hasCVEId ?cveId .

  # Alternative direct-evidence path: a log event that is itself evidence of the vulnerability
  OPTIONAL { ?logEvent :evidenceByLogEvent ?vulnerability }
}
ORDER BY DESC(?eventTime)
```
Combines log events and identified vulnerabilities within a risk assessment to surface potential high-risk or compromise situations.

## CQ12 - Which combinations of log events and vulnerabilities indicate high-risk situations or potential compromise?
```sparql
SELECT ?riskAssessment ?riskLevel ?logEvent ?eventTime ?logLevel
       ?vulnerability ?cveId ?baseScore ?baseSeverity
WHERE {
  ?riskAssessment a :RiskAssessment ;
                  :usesEvidence ?logEvent ;
                  :considers    ?vulnerability .

  OPTIONAL { ?riskAssessment :producesRiskLevel ?riskLevel }

  ?logEvent :hasEventTimestamp ?eventTime .
  OPTIONAL { ?logEvent :hasLogLevel ?logLevel }

  ?vulnerability :hasCVEId ?cveId .
  OPTIONAL {
    ?vulnerability :hasCVSSMetric ?cvss .
    ?cvss :hasBaseScore    ?baseScore .
    ?cvss :hasBaseSeverity ?baseSeverity .
  }
}
ORDER BY DESC(?baseScore) DESC(?eventTime)
```
This query derives overall risk posture from log evidence, CVSS severity scores, and the risk level produced by the assessment.

---

## Competency Question Traceability Matrix

Establishes traceability between each competency question (CQ) and the
AMISecOnto axioms, classes and object/data properties, needed to satisfy it,
together with the ontological role each mapping plays. This matrix supports
requirements validation by tracing every CQ back to concrete elements of the
ontology.

| CQ | Required Classes | Required Object / Data Properties | Ontological Role |
|---|---|---|---|
| CQ1 | LogEvent | hasEventTimestamp, hasLogLevel, hasHostname, hasEventType | Filters and discovers log events within a given time window matching selected criteria |
| CQ2 | LogEvent, Application, System, Environment | hasHostname, registersLogEvent, runsOn, executedInEnvironment | Scopes log events to the application, host, service, or component that generated them |
| CQ3 | LogEvent, ErrorLogEvent| hasPreviousLogEvent, hasNextLogEvent, hasEventTimestamp| Reconstructs the causal/temporal chain of events that preceded a specific error |
| CQ4 | LogEvent| hasEventTimestamp |Establishes a before/after timeline around a given incident event |
| CQ5 | AuthenticationLogEvent, AccessLogEvent, SudoLogEvent, SuLogEvent| hasEventTimestamp, hasUserName, hasHostname, hasSudoStatus, hasSuStatus | Correlates authentication attempts with subsequent access or privilege-escalation events |
| CQ6 | LogEvent, User, Audit_Log_Event | hasUser, hasSessionID, hasSessionStatus, hasUserName, hasEventTimestamp | Aggregates all events tied to a user/session to reconstruct a session timeline |
| CQ7 | ContainerLogEvent, ErrorLogEvent, ApplicationLogEvent | correlatedWith, hasNextLogEvent, hasMembershipStatus, hasExceptionType | Links container lifecycle activity to application-level errors it may have caused |
| CQ8 | ApplicationLogEvent, Request | belongsToRequest, correlatedWith, hasExceptionType, hasRequestURI | Associates application/database activity with the request that triggered it |
| CQ9 | SystemPackage, SoftwareComponent, System, rose:Vulnerability | installedOn, relatedToVulnerability, exposes, hasVulnerability, hasCVEId | Identifies which deployed software components are exposed to known CVEs |
| CQ10 | rose:Vulnerability, Product, CPE, Vendor, VersionInterval, SystemPackage | relatedToProduct, affectsCPE, hasVendor, hasVersionInterval, hasVersionMinIncluding, hasVersionMaxIncluding, hasPackageVersion | Maps vulnerabilities to the specific packages, versions, or components they affect |
| CQ11 | RiskAssessment, LogEvent, rose:Vulnerability, RiskLevel | usesEvidence, identifies, evidenceByLogEvent, producesRiskLevel / skos:hasRiskLevel | Combines log evidence and identified vulnerabilities to flag high-risk or compromise situations |
| CQ12 | RiskAssessment, LogEvent, rose:Vulnerability, CVSSMetric, RiskLevel | usesEvidence, considers, hasCVSSMetric, hasBaseScore, hasBaseSeverity, producesRiskLevel | Derives overall (NIS2-aligned) risk posture from CVSS severity, log evidence, and observed behavior |

---
## Alignment Classes with External Ontologies

The table below shows how the main AMISecOnto classes are aligned with external ontologies to support interoperability and semantic grounding. Domain classes extend ITSMO for IT service management concepts, PROV-O and FOAF for agents and provenance, and the foundational ontologies DOLCE and gUFO for their ontological nature. The corresponding axioms are defined in [`AMISecOnto-alignments.ttl`](amiseconto/AMISecOnto-alignments.ttl).

| AMISecOnto class | Subclass of | Reference alignment | Rationale |
|---|---|---|---|
| `amisec:Asset` | `itsmo:Asset` | – | Resource of value to protect |
| `amisec:Process` | `amisec:Asset` | `dolce:non-physical-object` | Running program instance; exists while executing |
| `amisec:Account` | `amisec:Asset` | `dolce:non-physical-object` | Exists by system recognition; grants access |
| `amisec:IPAddress` | `amisec:Asset` | `dolce:non-physical-object` | Network identifier assigned to a host |
| `amisec:User` | – | `prov:Agent`, `foaf:Person` | Actor performing actions |
| `amisec:Log` | – | `prov:Entity` | Record of events |
| `amisec:LogEvent` | – | `prov:Activity` | Occurrence recorded in a log |
| `rose:Vulnerability` | `rose:Disposition` | `gufo:IntrinsicMode` | Disposition of the component at risk |
| `amisec:Severity` | – | `dolce:quality` | Quality of a vulnerability |
| `amisec:CVSSMetric` | – | `dolce:abstract-region` | Value in the severity space |


---
## Interoperability Mapping with External Ontologies

The table below presents an excerpt of the explicit mappings between AMISecOnto concepts and corresponding entities in established external ontologies and standards, including DOLCE, ROSE, ITSMO, and FOAF. The table focuses on upper-level entities that ensure semantic alignment across the log analysis, vulnerability assessment, and risk management workflows. Domain-specific subclasses are excluded, such as individual log event types (e.g., SshLogEvent, SudoLogEvent) and specific package or component instances.

Most concepts in this table are modeled as subclasses of classes from an external ontology. Concepts marked with * are reused directly from the external ontology, while those marked with † are defined as equivalent to an existing entity in an external ontology.

This mapping demonstrates how AMISecOnto ensures semantic consistency, data exchangeability, and interoperability across academic institutional systems, cybersecurity threat intelligence sources, and NIS2-aligned risk assessment processes.


| AMISecOnto Concept | External Ontology | External Term | Interoperability Purpose |
|---|---|---|---|
| `CVSSMetric` | DOLCE-Lite | `dolce:abstract-region` | Classifies CVSS metrics as abstract value regions for severity alignment |
| `BuildStep` | DOLCE-Lite | `dolce:event` | Classifies build steps as events for traceable software supply-chain activities |
| `SoftwareBillsOfMaterial` | DOLCE-Lite | `dolce:non-physical-object` | Classifies SBOMs as non-physical objects for component inventory interoperability |
| `Weakness` | DOLCE-Lite | `dolce:non-physical-object` | Classifies root-cause weaknesses as non-physical objects, consistent with CWE semantics |
| `Activity` | PROV-O | `prov:Activity` | Grounds time-bound processes in PROV-O for provenance tracking |
| `Entity` | PROV-O | `prov:Entity` | Grounds supply-chain things (artifacts, packages, configurations) in PROV-O for traceability |
| `Log` | PROV-O | `prov:Activity` (via `Activity`) | Tracks log generation provenance through the PROV Activity hierarchy |
| `LogEvent` | PROV-O | `prov:Activity` (via `Activity`) | Traces individual recorded events through the PROV Activity hierarchy |
| `RiskAssessment` | gUFO | `gufo:Event` | Grounds risk assessment as an event in the UFO foundational ontology |
| `RiskLevel` | gUFO | `gufo:Event` | Grounds risk severity levels in UFO for consistent risk classification |
| `Risk` | ROSE | `rose:Risk` | Direct reuse of ROSE for risk-theoretic grounding of assessed risks |
| `Vulnerability` | ROSE | `rose:Vulnerability` | Direct reuse of the ROSE pattern for vulnerability semantics |
| `SecurityMechanism` | ROSE | `rose:SecurityMechanism` | Direct reuse of ROSE for controls that mitigate vulnerabilities |
| `Asset` | ITSMO | `itsmo:Asset` | Aligns assets with ITSMO, including criticality, priority, and scope |
| `User` | FOAF / PROV-O | `foaf:Person`, `prov:Agent` | Standard representation of human agents for cross-ontology interoperability |
| `Vendor` | PROV-O | `prov:Entity` (via `Entity`) | Represents product vendors as provenance-traceable entities |
| `CPE` | NIST CPE (conceptual) | - | Mirrors CPE fields (vendor, product, version, target hardware) for platform matching |
| `CVSSMetric` (properties) | FIRST CVSS (conceptual) | - | Mirrors CVSS base score, severity, and vector for NVD data ingestion |
| `Vulnerability` (identifier) | MITRE CVE (conceptual) | - | Links vulnerabilities to canonical CVE identifiers via `hasCVEId` |



---
## Ontology Modules
AMISecOnto is organized into interconnected modules:

- **Asset**  
- **Log and Event**  
- **Vulnerability**  
- **Risk Analysis**
- **Software Supply-Chain** 


## Asset Module

This diagram shows a sample excerpt of the Asset module from AMISecOnto, where `Asset` is a subclass of `'ITSMO Asset'`, linking it to the broader ITSMO.

**Key elements:**

- **Subclasses of Asset:** `Application`, `System`, `Process`, `'Software Component'`, `IPAddress`, `Account`
- **Object properties:** `Application` runsOn `System`; `'Software Component'` dependsOn itself (reflexive)
- **Properties on Asset:** hasScope → `'ITSMO Scope'`, hasPriority → `'ITSMO Priority'`, hasCriticality → `'ITSMO Criticality'`

In short: the Asset module defines Asset as the core entity, decomposed into concrete IT asset types (applications, systems, processes, software components, IP addresses, accounts), while attaching scope, priority, and criticality metadata for security and IT service management assessment.

<p align="center">
  <img src="figures/asset-module.png" alt="Asset Relations" width="400"/>
</p>


## Log and Event Module

This diagram shows a sample excerpt of the **Log and Event module** of AMISecOnto, centered on the class `LogEvent`, which is a subclass of `Activity` (itself a subclass of `'PROV Activity'`, tying the module into the PROV-O provenance ontology).

**Key elements:**

- **Subclasses of LogEvent:** `'Security Log Event'`, `'System Log Event'`, `'Application Log Event'` — each with a reflexive `hasPreviousLogEvent` relation.
- **Core object properties on LogEvent:**
  - `hasFirstLogEvent`, `hasCurrentLogEvent`, `hasPreviousLogEvent`, `hasNextLogEvent` → sequencing relations with `Log` and other `LogEvent` instances
  - `correlatedWith`, `hasPreviousCorrelatedEvent`, `hasNextCorrelatedEvent` → reflexive correlation relations between events
  - `containsEvent` → `Log`
  - `hasIndicator` → `Indicator`
  - `registersLogEvent` → `System`
  - `hasSourceIp` / `hasDestinationIp` → `IPAddress`
  - `isObservedIn` → `Vulnerability`
  - `usesEvidence` / `updatedBy` → `'Risk Assessment'`
  - `hasUser` → `User`
  - `hasOutcome` / `generates` → `Outcome`
  - `hasPackage` → `'Software Component'`
- **Log properties:** `storedOn` → `System`, `producedBy` → `Log`, `hasFirstLogEvent`/`hasCurrentLogEvent` (reflexive on `Log`)
- **Other links:** `Logger` connects into the correlation/event cluster.

In short: `LogEvent` acts as the central provenance-aware entity, linking logs, systems, indicators, IP addresses, vulnerabilities, risk assessments, users, outcomes, and software components to model how security-relevant events are generated, sequenced, correlated, and investigated.

<p align="center">
  <img src="figures/log-event-module.png" alt="Log and Event Relations" width="800"/>
</p>


## Vulnerability Module

This diagram shows a sample excerpt of the **Vulnerability module** of AMISecOnto, centered on the class `Vulnerability`, which is a subclass of `Disposition` (itself a subclass of `gufo:IntrinsicMode`, tying the module into the gUFO foundational ontology). `'Control Capability'` and `'Threat Capability'` are also subclasses of `Disposition`. 

**Key elements:**

- **Class hierarchy:**
  - `Disposition` is a subclass of `gufo:IntrinsicMode`
  - `Vulnerability` is a subclass of `Disposition`
  - `'Control Capability'` and `'Threat Capability'` are subclasses of `Disposition`
- **Object properties:**
  - `Vulnerability` isObservedIn → `LogEvent`
  - `Vulnerability` hasReference → `Reference`
  - `'Security Mechanism'` mitigates → `Vulnerability`
  - `Vulnerability` hasCVSSMetric → `'Common Vulnerability S...'` (CVSS)
  - `Vulnerability` affectsCPE → `'Common Platform Enumeration'`
  - `Vulnerability` relatedToProduct → `Product`
  - `Product` hasProduct → `'Common Platform Enumeration'`
  - `Vulnerability` hasWeakness → `Weakness`
  - `Vulnerability` hasVulnerabilityType → `'Vulnerability Type'`

**In short:** the Vulnerability module models `Vulnerability` as an intrinsic disposition of an asset, characterizing it through weaknesses, types, CVSS metrics, affected platforms/products, and references, while linking it to log-based observation and to security mechanisms that mitigate it.

<p align="center">
  <img src="figures/vulnerability-module.png" alt="Vulnerability Relations" width="800"/>
</p>


## Risk Analysis Module

This diagram shows a sample excerpt of the **Risk Analysis module** of AMISecOnto, centered on the class `'Risk Assessment'`, which is a subclass of `gufo:Event` — tying the module into the gUFO foundational ontology. `'Risk Level'` is also a subclass of `gufo:Event`.

**Key elements:**

- **Class hierarchy:**
  - `'Risk Assessment'` is a subclass of `gufo:Event`
  - `'Risk Level'` is a subclass of `gufo:Event`
- **Object properties:**
  - `'Risk Assessment'` recommends → `'Security Mechanism'`
  - `'Security Mechanism'` mitigates → `Vulnerability`
  - `Vulnerability` isObservedIn → `LogEvent`
  - `'Risk Assessment'` updatedBy → `LogEvent`
  - `'Risk Assessment'` usesEvidence → `LogEvent`
  - `'Risk Assessment'` producesRiskLevel → `'Risk Level'`

**In short:** the Risk Analysis module models how `'Risk Assessment'` events use log evidence and observed vulnerabilities to recommend security mechanisms and produce risk levels, linking risk evaluation to concrete log-based evidence and mitigation actions.

<p align="center">
  <img src="figures/risk-analysis-module.png" alt="Risk Analysis Module" width="800"/>
</p>


## Software Supply-Chain Module

This diagram shows a sample excerpt of the **Software Component / SBOM module** of AMISecOnto, rooted in the top-level `'DOLCE Non-physical-object'` class, with `'Asset'`, `'System'`, `'Project'`, and `'Build Configuration'` all specializing it as subclasses.

**Key elements:**

- **Class hierarchy:**
  - `'Software Component'` is a subclass of `'Package Library'`
  - `System` is a subclass of `Asset`
- **Object properties:**
  - `'Class Source'` hasClass → `'Package Library'`
  - `'Package Library'` containsPackage → `Module`
  - `'Software Bills of Material'` isDescribedBySBOM → `'Software Component'`
  - `'Software Component'` dependsOn itself (reflexive)
  - `'Software Component'` hasPackage → `LogEvent`
  - `LogEvent` registersLogEvent → `'Software Component'`
  - `'Software Component'` installedOn → `System`
  - `System` (via `'Package System'`) belongsToPackage → `Artifact`
  - `Artifact` hasRootArtifact → `Project`; `Artifact` is reflexive
  - `Indicator` hasIndicator → `'Package System'`
  - `'Build Configuration'` configuredFor → `System`
  - `Project` hasConfiguration → `'Build Configuration'`

In short: this module models the **software supply chain**, linking software components, packages, SBOMs, artifacts, systems, and build configurations, and connecting them to log events and indicators for traceability and security monitoring.

<p align="center">
  <img src="figures/sbom-module.png" alt="Software Supply-Chain" width="800"/>
</p>

## Citation

If you use AMISecOnto in your research, please cite:

```bibtex
@software{lourenco_amiseconto_2025,
  author = {Bruno Lourenço and Cátia Vaz and Alexandre P. Francisco and Pedro Adão and Antonio Goncalves and Mario Marques and João F. Ferreira},
  title = {AMISecOnto: Ontology-Driven Knowledge Graph Framework for Semantic Log, Vulnerability, and Threat Analysis},
  year = {2025},
  publisher = {Zenodo},
  doi = {10.5281/zenodo.20044615},
  url = {https://doi.org/10.5281/zenodo.20044615}
}
```

