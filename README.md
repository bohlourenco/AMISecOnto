# AMISecOnto: An Ontology for Cybersecurity Log and Vulnerability Analysis

## 📌 Overview
**AMISecOnto** is a modular ontology designed to support cybersecurity analysis by integrating system entities, vulnerabilities, and log-based observations into a unified semantic framework.  

The ontology follows established ontology engineering best practices, emphasizing:
- Modular design
- Transparent vocabulary reuse (e.g., PROV-O, FOAF)
- Semantic interoperability
- Support for log analysis, event correlation, and vulnerability assessment

---

## 🧩 Ontology Scope
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

## 🏗️ Ontology Architecture
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

## ❓ Competency Questions (CQs)

The ontology is designed to answer the following competency questions:

### 🔍 Event Discovery and Filtering
- CQ1: How are events filtered within a time range?
- CQ2: How to identify events belonging to a specific system or application?
- CQ3: How to group events within the same execution flow?
- CQ4: Which identifiers support event grouping?

### 🔗 Event Lineage Tracing
- CQ5: What sequence of events led to an error?
- CQ6: How useful is pre/post-event log context?
- CQ7: How to correlate security and system events?
- CQ8: How to link security events with application logs?

### 🔐 Authentication and Access Tracing
- CQ9: How to analyze authentication attempts?
- CQ10: How to reconstruct user sessions?
- CQ11: How to group SSH events into sessions?
- CQ12: Which identifiers are used for session correlation?

### 📦 Application and Container Tracing
- CQ13: How to link container lifecycle events with application errors?
- CQ14: How to correlate database and application events?

### ⚙️ System-Level Tracing
- CQ15: Which events precede system instability?
- CQ16: How to track package installation/update events?
- CQ17: What evidence is used when updates cause failures?

### 🛡️ Security Tracing
- CQ18: What audit data is needed for sensitive operations?
- CQ19: How to correlate access control events?
- CQ20: What challenges exist in trace reconstruction?

### 🔄 Cross-Source Log Correlation
- CQ21: How to correlate Syslog/Journalctl with application logs?
- CQ22: What multi-source patterns are relevant?
- CQ23: What makes cross-system correlation difficult?

### 🚨 Anomaly and Incident Reconstruction
- CQ24: What data is required for anomaly reconstruction?
- CQ25: What are common blockers in incident analysis?

---

## 📁 Repository Structure

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

## 🛠️ Tools and Technologies
- **Protégé** for ontology development
- **OWL / RDF / Turtle**
- **SPARQL** for querying
- Reused vocabularies:
  - PROV-O
  - FOAF

---

## 🚀 Usage

### Load Ontology
You can load the ontology in:
- Protégé
- RDF triple stores (e.g., GraphDB, Fuseki)

### Example Query (SPARQL)
```sparql
SELECT ?event ?vulnerability
WHERE {
  ?event a :LogEvent .
  ?event :hasEvidenceByLogEvent ?vulnerability .
}
