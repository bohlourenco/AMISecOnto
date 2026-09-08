<p align="center">
  <img src="figures/amiseconto-logo.png" alt="AMISecOnto Logo" width="140"/>
</p>

# AMISecOnto
This repository contains all development for the project's ontology/knowledge model, a domain-specific ontology designed to support NIS2-compliant cybersecurity analysis in academic management information systems (AMIS) through standardized and semantically enriched knowledge representation. The ontology formally models the complete cybersecurity monitoring and incident-analysis workflow, integrating heterogeneous log evidence (system, application, and security logs), software supply-chain and asset information, vulnerability intelligence (CVE, CPE, CWE, and CVSS), and risk-aware analysis aligned with NIS2 Article 21 obligations. Built upon foundational upper ontologies, such as DOLCE, and reusing established provenance, actor-identity, IT-service-management, and risk-treatment ontologies (PROV-O, FOAF, ITSMO, and ROSE), AMISecOnto ensures interoperability, extensibility, and compliance with FAIR principles. This repository includes a total of 12 competency questions, the corresponding SPARQL queries, the ontology in OWL/Turtle format, knowledge graph construction scripts, and synthetic example datasets (FénixEdu logs and NVD vulnerability records), as well as supporting documentation demonstrating the interoperability of AMISecOnto with major cybersecurity and Semantic Web standards.

## Table of Contents

- [Overview](#overview)
- [Ontology Scope](#ontology-scope)
- [Ontology Architecture](#ontology-architecture)
- [Repository Structure](#repository-structure)
- [Tools and Technologies](#tools-and-technologies)
- [Usage](#usage)
  - [Load Ontology](#load-ontology)
  - [Query the Knowledge Graph](#query-the-knowledge-graph)
  - [Validate Data with SHACL](#validate-data-with-shacl)
- [Competency Questions (CQs)](#competency-questions-cqs)
  - [Event Discovery and Filtering](#event-discovery-and-filtering)
  - [Event Lineage Tracing](#event-lineage-tracing)
  - [Authentication and Access Tracing](#authentication-and-access-tracing)
  - [Application, System, and Security Tracing](#application-system-and-security-tracing)
  - [Vulnerability Analysis and Exposure](#vulnerability-analysis-and-exposure)
  - [Risk Assessment and Incident Reconstruction (NIS2-aligned)](#risk-assessment-and-incident-reconstruction-nis2-aligned)   
- [SPARQL Query Templates](#sparql-query-templates)
- [Examples](#examples)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
  
## Overview

**AMISecOnto** is a modular cybersecurity ontology that transforms heterogeneous data—such as AMIS system logs and vulnerability intelligence (e.g., NVD)—into a unified semantic knowledge graph for advanced security analysis.

---

## Key Features

- **Integrated data ingestion**: Combines raw logs with vulnerability data for contextual enrichment  
- **Modular design**: Core modules for Entities, Vulnerabilities, and Standards  
- **Semantic enrichment**: Links events to CVE, CPE, and CVSS information  
- **Standards-based**: RDF, OWL, SHACL, PROV-O, FOAF  
- **Interoperability & provenance**: Ensures traceability and cross-system integration  
- **Analytics-ready**:
  - Event correlation  
  - Risk assessment  
  - Incident reconstruction  
  - Evidence tracing  

---
## Ontology Modules

AMISecOnto is organized into interconnected modules:

- **Asset**  
- **Log & Event**  
- **Vulnerability**  
- **Risk Analysis**
- **Software Supply-Chain** 

### Design Principles

- Separation of concerns  
- Reusability  
- Scalable knowledge graph construction  

<p align="center">
  <img src="figures/amiseconto-core-architecture.png" alt="AMISecOnto Architecture" width="900"/>
</p>

---

## Competency Questions (CQs)

The ontology is designed to answer the following competency questions:

### Event Discovery and Filtering
- **CQ1**: Which events occurred within a specific time range and satisfy selected filters?
- **CQ2**: Which events belong to a specific application, service, host, or component?

### Event Lineage Tracing
- **CQ3**: Which sequence of log events led to a specific error event?
- **CQ4**: Which events occurred before and after a given incident?

### Authentication and Access Tracing
- **CQ5**: Which authentication attempts preceded access or privilege-escalation events?
- **CQ66**: Which information is required to reconstruct a user session timeline?

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

## Repository Structure

- **data/**: Demo RDF data, statistics, and logs  
- **queries/**: SPARQL competency questions for evaluation  
- **scripts/**: Data ingestion, querying, validation, and CVE fetching  
- **AMISecOnto.ttl**: Core ontology  

```bash
amiseconto/
├── amiseconto/
│   ├── AMISecOnto.ttl
│   ├── AMISecOnto-alignments.ttl
├── build/
│   ├── amiseconto_demo_stats.json
├── data/
│   ├── amiseconto_demo_data.nt
│   ├── amiseconto_demo_stats.json
├── log_20k_AMISecOnto/
│   ├── access_20k.log
│   ├── autit_20k.log
│   ├── catalina_20k.log
│   ├── dpkg_20k.log
│   ├── error_20k.log
│   ├── fenix.dependencies.txt
│   ├── ssh_20k.log
│   ├── su_20k.log
│   ├── sudo_20k.log
├── queries/
│   └── competency_questions/
│       ├── cq01_time_range_filtering.rq
│       ├── cq05_event_lineage_before_after_error.rq
│       ├── cq09_auth_before_privilege_escalation.rq
│       ├── cq16_package_updates_and_related_vulnerabilities.rq
│       ├── cq18_sensitive_operations.rq
│       ├── cq21_cross_source_correlation.rq
│       ├── cq22_multi_source_attack_patterns.rq
│       ├── cq23_multi_source_attack_patterns.rq
│       ├── cq24_incident_reconstruction.rq
│       └── linux_nvd_vulnerabilities_overview.rq
├── scripts/
│   ├── build_amiseconto_demo_graph.py
│   ├── fetch_nvd_linux_cves.py
│   ├── load_to_virtuoso.py
│   ├── query_virtuoso.py
│   └── validate_shacl_with_pyshacl.py
├── shapes/
│   ├── amiseconto_cq_shapes.py
├── LICENSE
├── README.md
```


---

## Tools and Technologies
- **Protégé** for ontology development
- **OWL / RDF / Turtle**
- **SPARQL** for querying
- Reused vocabularies:
  - PROV-O
  - FOAF

---

## Prerequisites

- **Python 3** (stdlib only for the main scripts)  
  - Optional: `pip install pyshacl` for SHACL validation
- **Virtuoso Open Source** running at:
  - `http://localhost:8890`
  - Endpoints:
    - `/sparql`
    - `/sparql-graph-crud`
- **Log dataset**:
  - Directory: `log_20k_AMISecOnto` under the project root  
  - Or specify a custom path using `--dataset-dir`

---

## Load Data (Full Pipeline)

Run all commands from the repository root:

### 1. Fetch NVD CVEs for Linux

```bash
python3 scripts/fetch_nvd_linux_cves.py --api-key "$NVD_API_KEY" --max-records 1000
```

### 2. Build Instance RDF

```bash
python3 scripts/build_amiseconto_demo_graph.py
```

Outputs:
```bash
build/amiseconto_demo_data.nt
build/amiseconto_demo_stats.json
```
### 3. Load into Virtuoso
```bash
python3 scripts/load_to_virtuoso.py
```

Loads:
AMISecOnto.ttl
```bash
build/amiseconto_demo_data.nt
```

Default graph:
```bash
http://localhost:8890/AMISecOnto
```

To append instead of replacing:
```bash
python3 scripts/load_to_virtuoso.py --keep-existing
```

### 4. Run (Use) the Demo

Execute competency queries:
```bash
python3 scripts/query_virtuoso.py queries/competency_questions/cq24_incident_reconstruction.rq
```
Replace the .rq file with any query under:
```bash
queries/competency_questions/
```

---




## SPARQL Queries
SPARQL queries in AMISSecOnto are designed to retrieve relevant cybersecurity information from the knowledge graph, supporting tasks such as event discovery, filtering, and analysis. This approach ensures that the ontology effectively addresses practical requirements, enabling the extraction of insights related to vulnerabilities, threats, assets, and security events in real-world scenarios.

## Event Discovery and Filtering
### CQ1 – Which events occurred within a specific time range and satisfy selected filters?
```sparql
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

SELECT ?event ?timestamp ?logLevel ?hostname ?eventType
WHERE {
  ?event a :LogEvent ;
         :hasEventTimestamp ?timestamp .

  OPTIONAL { ?event :hasLogLevel  ?logLevel }
  OPTIONAL { ?event :hasHostname  ?hostname }
  OPTIONAL { ?event :hasEventType ?eventType }

  FILTER (?timestamp >= "2026-01-01T00:00:00"^^xsd:dateTime &&
          ?timestamp <  "2026-02-01T00:00:00"^^xsd:dateTime)

  # Optional/selected filters — comment out or adjust as needed
  FILTER (!BOUND(?logLevel)  || ?logLevel  = "ERROR")
  FILTER (!BOUND(?hostname)  || ?hostname  = "app-server-01")
}
ORDER BY ?timestamp
```
### CQ2 — Which events belong to a specific application, service, host, or component? 
```sparql
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

SELECT ?event ?timestamp ?hostname ?application
WHERE {
  ?event a :LogEvent ;
         :hasEventTimestamp ?timestamp .

  OPTIONAL { ?event :hasHostname ?hostname }

  # Path via System → Application (registersLogEvent / runsOn)
  OPTIONAL {
    ?system :registersLogEvent ?event .
    ?application :runsOn ?system .
  }

  # Path via ApplicationLogEvent → Environment (executedInEnvironment)
  OPTIONAL {
    ?event a :ApplicationLogEvent ;
           :executedInEnvironment ?environment .
  }

  FILTER (
    (BOUND(?hostname)    && ?hostname    = "app-server-01") ||
    (BOUND(?application) && ?application = :MyApplication)
  )
}
ORDER BY ?timestamp
```
This query returns a time-ordered list of log events with key information extracted for each event.

### Event Lineage Tracing
## CQ3 — Which sequence of log events led to a specific error event?
```sparql
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

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
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

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
jljljljljljljklk

### Authentication and Access Tracing
## CQ5 - Which authentication attempts preceded access or privilege-escalation events?
```sparql
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

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
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

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

### Application, system, and security tracing 
## CQ07 - Which container lifecycle events are linked to application errors?
```sparql
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

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
## CQ08 - Which database events correlate with application requests?
```sparql
PREFIX : <http://www.semanticweb.org/AMISecOnto#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

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
## CQ09 - Which installed or observed software components are affected by known vulnerabilities (CVEs)?
```sparql
PREFIX :     <http://www.semanticweb.org/AMISecOnto#>
PREFIX rose: <http://rose.com#>

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

## CQ10 - Which installed or observed software components are affected by known vulnerabilities (CVEs)?
```sparql
PREFIX :     <http://www.semanticweb.org/AMISecOnto#>
PREFIX rose: <http://rose.com#>

SELECT ?vulnerability ?cveId ?product ?vendor ?versionMin ?versionMax ?packageVersion
WHERE {
  ?vulnerability a rose:Vulnerability ;
                 :hasCVEId ?cveId .

  OPTIONAL {
    ?vulnerability :relatedToProduct ?product .
  }
}
```
ljkllkjkjghjhfjhfghgs

### Risk assessment and incident reconstruction (NIS2-aligned)
## CQ11 - Which combinations of log events and vulnerabilities indicate high-risk situations or potential compromise?
```sparql
PREFIX :     <http://www.semanticweb.org/AMISecOnto#>
PREFIX rose: <http://rose.com#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

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

## CQ11 - Which combinations of log events and vulnerabilities indicate high-risk situations or potential compromise?
```sparql
PREFIX :     <http://www.semanticweb.org/AMISecOnto#>
PREFIX rose: <http://rose.com#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

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

