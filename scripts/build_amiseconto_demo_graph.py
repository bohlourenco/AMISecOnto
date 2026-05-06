#!/usr/bin/env python3
"""Build AMISecOnto demo instance data from the log_20k_AMISecOnto dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


AMIS = "http://www.semanticweb.org/AMISecOnto/"
AMIS_HASH = "http://www.semanticweb.org/AMISecOnto#"
PROV = "http://www.w3.org/ns/prov#"
FOAF = "http://xmlns.com/foaf/0.1/"
RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
RDFS = "http://www.w3.org/2000/01/rdf-schema#"
XSD = "http://www.w3.org/2001/XMLSchema#"

# Classes modeled with slash namespace in AMISecOnto.ttl.
SLASH_CLASS_NAMES = {
    "ApplicationLogEvent",
    "Dependency",
    "Indicator",
    "LogEvent",
    "SecurityLogEvent",
    "SoftwareComponent",
    "System",
    "SystemLogEvent",
    "SystemPackage",
    "User",
    "Vulnerability",
}


LOG_CONFIG = {
    "access_20k.log": ("AccessLog", "AccessLogEvent", "ApplicationLog"),
    "audit_20k.log": ("AuditLog", "Audit_Log_Event", "SecurityLog"),
    "catalina_20k.log": ("CatalinaLog", "CatalinaLogEvent", "ApplicationLog"),
    "dpkg_20k.log": ("PackageLog", "InstalledPackageLogEvent", "SystemLog"),
    "error_20k.log": ("Error_Log", "ErrorLogEvent", "ApplicationLog"),
    "ssh_20k.log": ("SshLog", "SshLogEvent", "AuthenticationLog"),
    "su_20k.log": ("SuLog", "SuLogEvent", "SecurityLog"),
    "sudo_20k.log": ("SudoLog", "SudoLogEvent", "SecurityLog"),
}


SUSPICIOUS_PATTERNS = {
    "credential-in-url": re.compile(r"password=|passwd=|token=|api[_-]?key=", re.I),
    "path-traversal": re.compile(r"\.\./\.\.|%2e%2e|/etc/passwd|/etc/shadow", re.I),
    "ssrf": re.compile(r"169\.254\.169\.254|latest/meta-data|computeMetadata", re.I),
    "command-injection": re.compile(r";bash\b|\|\s*sh\b|\$\{jndi:|curl .*?\|sh|RCE attempt", re.I),
    "graphql-introspection": re.compile(r"__schema|graphql", re.I),
    "suspicious-user-agent": re.compile(r"Hydra|DirBuster|Scanner|exfil|Attacker|Exploit", re.I),
    "privilege-escalation": re.compile(r"backdoor|possible_priv_esc|unauthorized privilege escalation|user NOT in sudoers", re.I),
    "bruteforce": re.compile(r"authentication failure|incorrect password|failed authentication|Multiple failed authentication", re.I),
    "vulnerability-probe": re.compile(r"Log4Shell|Spring4Shell|OWASP-A9 vulnerable component|metadata", re.I),
}


ACCESS_RE = re.compile(
    r'^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<service>\S+):\s+'
    r'(?P<client>\S+)\s+-\s+-\s+\[(?P<bracket_ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+HTTP/(?P<http_version>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)
SYSLOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<service>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
CATALINA_RE = re.compile(
    r"^(?P<ts>\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<level>[A-Z]+)\s+\[(?P<thread>[^\]]+)\]\s+(?P<logger>\S+)\s+(?P<message>.*)$"
)
AUDIT_MAIN_RE = re.compile(
    r"^type=(?P<etype>\S+)\s+(?P<rest>.*)$"
)
AUDIT_KV_RE = re.compile(r'(\w+)=(".*?"|\'.*?\'|\S+)')
DPKG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>\S+)(?:\s+(?P<rest>.*))?$"
)
DEPENDENCY_RE = re.compile(
    r"^[\[\]INFO\s|+\\-]*([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z]+):([^: ]+):([A-Za-z]+)"
)


def nt_uri(value: str) -> str:
    return f"<{value}>"


def nt_literal(value: str, datatype: str | None = None) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    literal = f'"{escaped}"'
    if datatype:
        literal += f"^^<{datatype}>"
    return literal


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    return cleaned or "unknown"


def stable_id(prefix: str, payload: str) -> str:
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
    return f"{AMIS}{prefix}/{digest}"


def parse_iso(timestamp: str) -> str | None:
    try:
        dt = datetime.fromisoformat(timestamp)
        return dt.isoformat()
    except ValueError:
        return None


def parse_dpkg_ts(timestamp: str) -> str | None:
    try:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").isoformat()
    except ValueError:
        return None


def parse_catalina_ts(timestamp: str) -> str | None:
    try:
        return datetime.strptime(timestamp, "%d-%b-%Y %H:%M:%S.%f").isoformat()
    except ValueError:
        return None


def parse_dependency_line(line: str) -> tuple[str, str, str, str] | None:
    match = DEPENDENCY_RE.match(line)
    if not match:
        return None
    return match.group(1), match.group(2), match.group(3), match.group(4)


@dataclass
class EventRecord:
    event_uri: str
    timestamp: str | None
    log_name: str
    log_uri: str
    line_no: int
    event_class: str
    extra_classes: tuple[str, ...]
    raw_message: str
    hostname: str | None = None
    service_name: str | None = None
    process_name: str | None = None
    process_id: str | None = None
    user_name: str | None = None
    event_type: str | None = None
    log_level: str | None = None
    request_uri: str | None = None
    status_code: str | None = None
    port: str | None = None
    command: str | None = None
    package_action: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    session_id: str | None = None
    session_status: str | None = None
    message: str | None = None
    indicators: tuple[str, ...] = ()
    related_vulns: tuple[str, ...] = ()


class GraphBuilder:
    def __init__(self, dataset_dir: Path, curated_vulns_path: Path, nvd_cves_path: Path | None = None):
        self.dataset_dir = dataset_dir
        self.curated_vulns = json.loads(curated_vulns_path.read_text())
        self.nvd_cves = {}
        if nvd_cves_path and nvd_cves_path.exists():
            self.nvd_cves = json.loads(nvd_cves_path.read_text())
        self.triples: list[str] = []
        self.seen_entities: set[str] = set()
        self.log_event_sequences: dict[str, list[str]] = defaultdict(list)
        self.indicator_cache: dict[str, str] = {}
        self.user_cache: dict[str, str] = {}
        self.system_cache: dict[str, str] = {}
        self.component_cache: dict[str, str] = {}
        self.request_cache: dict[str, str] = {}
        self.vuln_cache: dict[str, str] = {}
        self.package_cache: dict[str, str] = {}
        self.stats = defaultdict(int)

    def add(self, s: str, p: str, o: str) -> None:
        self.triples.append(f"{nt_uri(s)} {nt_uri(p)} {o} .")

    def add_type(self, entity: str, class_name: str) -> None:
        class_iri_base = AMIS if class_name in SLASH_CLASS_NAMES else AMIS_HASH
        self.add(entity, RDF + "type", nt_uri(class_iri_base + class_name))

    def add_common_event_triples(self, event: EventRecord) -> None:
        self.add_type(event.event_uri, "LogEvent")
        self.add_type(event.event_uri, event.event_class)
        for extra in event.extra_classes:
            self.add_type(event.event_uri, extra)
        self.add(event.log_uri, AMIS_HASH + "containsEvent", nt_uri(event.event_uri))
        self.add(event.event_uri, AMIS_HASH + "belongsToLog", nt_uri(event.log_uri))
        self.add(event.event_uri, AMIS_HASH + "hasRawMessage", nt_literal(event.raw_message))
        self.add(event.event_uri, AMIS_HASH + "hasLogFileName", nt_literal(event.log_name))
        self.add(event.event_uri, AMIS_HASH + "hasLineNumber", nt_literal(str(event.line_no), XSD + "integer"))
        self.add(event.event_uri, RDFS + "label", nt_literal(f"{event.log_name}:{event.line_no}"))
        if event.timestamp:
            self.add(event.event_uri, AMIS_HASH + "hasTimestamp", nt_literal(event.timestamp, XSD + "string"))
        if event.hostname:
            self.add(event.event_uri, AMIS_HASH + "hasHostname", nt_literal(event.hostname))
            self.add(event.event_uri, AMIS_HASH + "hasSource", nt_uri(self.get_or_create_system(event.hostname)))
        if event.service_name:
            component_uri = self.get_or_create_component(event.service_name)
            self.add(event.event_uri, AMIS_HASH + "hasSource", nt_uri(component_uri))
            self.add(component_uri, AMIS_HASH + "registersLogEvent", nt_uri(event.event_uri))
        if event.process_name:
            self.add(event.event_uri, AMIS_HASH + "hasProcessName", nt_literal(event.process_name))
        if event.process_id:
            self.add(event.event_uri, AMIS_HASH + "hasProcessID", nt_literal(event.process_id))
        if event.user_name:
            user_uri = self.get_or_create_user(event.user_name)
            self.add(event.event_uri, AMIS + "hasUser", nt_uri(user_uri))
            self.add(event.event_uri, AMIS_HASH + "hasUserName", nt_literal(event.user_name))
        if event.event_type:
            self.add(event.event_uri, AMIS_HASH + "hasEventType", nt_literal(event.event_type))
        if event.log_level:
            self.add(event.event_uri, AMIS_HASH + "hasLogLevel", nt_literal(event.log_level))
        if event.request_uri:
            self.add(event.event_uri, AMIS_HASH + "hasRequestURI", nt_literal(event.request_uri))
            request_uri = self.get_or_create_request(event.request_uri)
            self.add(event.event_uri, AMIS_HASH + "belongsToRequest", nt_uri(request_uri))
        if event.status_code:
            self.add(event.event_uri, AMIS + "hasStatusCode", nt_literal(event.status_code))
            self.add(event.event_uri, AMIS_HASH + "hasHttpSatusCode", nt_literal(event.status_code))
        if event.port:
            self.add(event.event_uri, AMIS_HASH + "hasPort", nt_literal(event.port))
        if event.command:
            self.add(event.event_uri, AMIS_HASH + "hasCommand", nt_literal(event.command))
        if event.package_action:
            self.add(event.event_uri, AMIS_HASH + "hasPackageAction", nt_literal(event.package_action))
        if event.package_name:
            self.add(event.event_uri, AMIS_HASH + "hasPackageName", nt_literal(event.package_name))
            package_uri = self.get_or_create_package(event.package_name, event.package_version)
            self.add(event.event_uri, AMIS_HASH + "hasPackage", nt_uri(package_uri))
            self.add(package_uri, AMIS_HASH + "updatedBy", nt_uri(event.event_uri))
        if event.package_version:
            self.add(event.event_uri, AMIS_HASH + "hasPackageVersion", nt_literal(event.package_version))
        if event.session_id:
            self.add(event.event_uri, AMIS_HASH + "hasSessionID", nt_literal(event.session_id))
        if event.session_status:
            self.add(event.event_uri, AMIS_HASH + "hasSessionStatus", nt_literal(event.session_status))
        if event.message:
            self.add(event.event_uri, AMIS_HASH + "hasMessage", nt_literal(event.message))
        for indicator_name in event.indicators:
            indicator_uri = self.get_or_create_indicator(indicator_name)
            self.add(event.event_uri, AMIS + "hasIndicator", nt_uri(indicator_uri))
        for vuln_uri in event.related_vulns:
            self.add(event.event_uri, AMIS_HASH + "evidenceByLogEvent", nt_uri(vuln_uri))
            self.add(event.event_uri, AMIS_HASH + "relatedToVulnerability", nt_uri(vuln_uri))
            self.add(vuln_uri, AMIS + "isObservedIn", nt_uri(event.event_uri))
        if event.event_class == "InstalledPackageLogEvent" and event.package_name:
            self._link_dpkg_event_to_nvd_cve(event)
        self.log_event_sequences[event.log_name].append(event.event_uri)
        self.stats["events"] += 1

    def get_or_create_user(self, username: str) -> str:
        if username in self.user_cache:
            return self.user_cache[username]
        user_uri = stable_id("user", username)
        self.user_cache[username] = user_uri
        self.add_type(user_uri, "User")
        self.add(user_uri, RDF + "type", nt_uri(FOAF + "Person"))
        self.add(user_uri, RDFS + "label", nt_literal(username))
        self.add(user_uri, AMIS_HASH + "hasUserName", nt_literal(username))
        self.stats["users"] += 1
        return user_uri

    def get_or_create_system(self, hostname: str) -> str:
        if hostname in self.system_cache:
            return self.system_cache[hostname]
        system_uri = stable_id("system", hostname)
        self.system_cache[hostname] = system_uri
        self.add_type(system_uri, "System")
        self.add(system_uri, RDF + "type", nt_uri(PROV + "Entity"))
        self.add(system_uri, RDFS + "label", nt_literal(hostname))
        self.add(system_uri, AMIS_HASH + "hasHostname", nt_literal(hostname))
        self.stats["systems"] += 1
        return system_uri

    def get_or_create_component(self, name: str) -> str:
        if name in self.component_cache:
            return self.component_cache[name]
        component_uri = stable_id("component", name)
        self.component_cache[name] = component_uri
        self.add_type(component_uri, "SoftwareComponent")
        self.add(component_uri, RDF + "type", nt_uri(PROV + "Entity"))
        self.add(component_uri, RDFS + "label", nt_literal(name))
        self.stats["components"] += 1
        return component_uri

    def get_or_create_request(self, request_uri: str) -> str:
        if request_uri in self.request_cache:
            return self.request_cache[request_uri]
        req_uri = stable_id("request", request_uri)
        self.request_cache[request_uri] = req_uri
        self.add_type(req_uri, "Request")
        self.add(req_uri, RDFS + "label", nt_literal(request_uri))
        self.stats["requests"] += 1
        return req_uri

    def get_or_create_indicator(self, name: str) -> str:
        if name in self.indicator_cache:
            return self.indicator_cache[name]
        indicator_uri = stable_id("indicator", name)
        self.indicator_cache[name] = indicator_uri
        self.add_type(indicator_uri, "Indicator")
        self.add(indicator_uri, RDFS + "label", nt_literal(name))
        self.stats["indicators"] += 1
        return indicator_uri

    @staticmethod
    def effective_severity(
        severity: str | None,
        cvss_score: float,
        *,
        severity_detail: dict | None = None,
    ) -> str:
        """Qualitative label: prefer API/NVD baseSeverity, then flat severity string, else CVSS bands."""
        if severity_detail:
            api = (severity_detail.get("baseSeverity") or "").strip().upper()
            if api and api != "UNKNOWN":
                return api
        s = (severity or "").strip().upper()
        if s and s != "UNKNOWN":
            return s
        score = float(cvss_score)
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "UNKNOWN"

    def get_or_create_vuln(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        *,
        severity_detail: dict | None = None,
    ) -> str:
        if cve_id in self.vuln_cache:
            return self.vuln_cache[cve_id]
        vuln_uri = f"{AMIS}vulnerability/{slugify(cve_id)}"
        self.vuln_cache[cve_id] = vuln_uri
        self.add_type(vuln_uri, "Vulnerability")
        self.add(vuln_uri, RDFS + "label", nt_literal(cve_id))
        self.add(vuln_uri, AMIS_HASH + "hasMessage", nt_literal(description))
        self.add(vuln_uri, RDFS + "comment", nt_literal(f"{description} CVSS {cvss_score:.1f}."))
        eff = self.effective_severity(severity, cvss_score, severity_detail=severity_detail)
        self.add(vuln_uri, AMIS_HASH + "hasSeverityCode", nt_literal(eff))
        self.add(vuln_uri, AMIS + "hasBaseScore", nt_literal(f"{float(cvss_score):.1f}", XSD + "decimal"))
        if severity_detail:
            ver = severity_detail.get("cvssVersion")
            if ver:
                try:
                    vnum = float(str(ver).strip())
                    self.add(vuln_uri, AMIS + "hasCVSSVersion", nt_literal(f"{vnum:.1f}", XSD + "decimal"))
                except ValueError:
                    pass
            code = severity_detail.get("cvssCode")
            if code:
                self.add(vuln_uri, AMIS + "hasCVSScode", nt_literal(str(code)))
        self.stats["vulnerabilities"] += 1
        return vuln_uri

    def get_or_create_package(self, package_name: str, package_version: str | None = None) -> str:
        key = f"{package_name}:{package_version or 'unknown'}"
        if key in self.package_cache:
            return self.package_cache[key]
        package_uri = stable_id("package", key)
        self.package_cache[key] = package_uri
        self.add_type(package_uri, "SystemPackage")
        self.add(package_uri, RDFS + "label", nt_literal(key))
        self.add(package_uri, AMIS_HASH + "hasPackageName", nt_literal(package_name))
        if package_version:
            self.add(package_uri, AMIS_HASH + "hasPackageVersion", nt_literal(package_version))
        self.stats["packages"] += 1
        return package_uri

    def create_logs(self) -> dict[str, str]:
        log_uris = {}
        for filename, (log_class, _, top_class) in LOG_CONFIG.items():
            log_uri = f"{AMIS}log/{slugify(filename)}"
            log_uris[filename] = log_uri
            self.add_type(log_uri, "Log")
            self.add_type(log_uri, log_class)
            self.add_type(log_uri, top_class)
            self.add(log_uri, RDFS + "label", nt_literal(filename))
            self.add(log_uri, AMIS_HASH + "hasLogFileName", nt_literal(filename))
            self.add(log_uri, AMIS_HASH + "hasLogFilePath", nt_literal(str(self.dataset_dir / filename)))
        return log_uris

    def detect_indicators(self, text: str) -> tuple[str, ...]:
        hits = [name for name, pattern in SUSPICIOUS_PATTERNS.items() if pattern.search(text)]
        return tuple(hits)

    def detect_related_vulns(self, text: str) -> tuple[str, ...]:
        related = []
        checks = {
            "log4shell": "CVE-2021-4104",
            "spring4shell": "CVE-2017-5638",
            "vulnerable component": "CVE-2023-24998",
        }
        lower = text.lower()
        for marker, cve in checks.items():
            if marker in lower and cve in self.vuln_cache:
                related.append(self.vuln_cache[cve])
        return tuple(related)

    def parse_access_log(self, line: str, log_uri: str, line_no: int) -> None:
        match = ACCESS_RE.match(line)
        if not match:
            return
        message = f"{match.group('method')} {match.group('uri')} -> {match.group('status')}"
        indicators = self.detect_indicators(line)
        event = EventRecord(
            event_uri=stable_id("event/access", f"{line_no}:{line}"),
            timestamp=parse_iso(match.group("ts")),
            log_name="access_20k.log",
            log_uri=log_uri,
            line_no=line_no,
            event_class="AccessLogEvent",
            extra_classes=("ApplicationLogEvent",),
            raw_message=line,
            hostname=match.group("host"),
            service_name=match.group("service"),
            process_name=match.group("service"),
            event_type=match.group("method"),
            request_uri=match.group("uri"),
            status_code=match.group("status"),
            message=message,
            indicators=indicators,
        )
        self.add_common_event_triples(event)

    def parse_syslog_family(self, filename: str, line: str, log_uri: str, line_no: int, event_class: str, extra: tuple[str, ...]) -> None:
        match = SYSLOG_RE.match(line)
        if not match:
            return
        message = match.group("message")
        indicators = self.detect_indicators(line)
        user_name = self.extract_user(message)
        session_id = match.group("pid")
        session_status = self.extract_session_status(message)
        port = self.extract_port(message)
        command = self.extract_command(message)
        event = EventRecord(
            event_uri=stable_id(f"event/{slugify(filename)}", f"{line_no}:{line}"),
            timestamp=parse_iso(match.group("ts")),
            log_name=filename,
            log_uri=log_uri,
            line_no=line_no,
            event_class=event_class,
            extra_classes=extra,
            raw_message=line,
            hostname=match.group("host"),
            service_name=match.group("service"),
            process_name=match.group("service"),
            process_id=match.group("pid"),
            user_name=user_name,
            event_type=match.group("service"),
            port=port,
            command=command,
            session_id=session_id,
            session_status=session_status,
            message=message,
            indicators=indicators,
            related_vulns=self.detect_related_vulns(line),
        )
        self.add_common_event_triples(event)

    def parse_catalina_log(self, line: str, log_uri: str, line_no: int) -> None:
        match = CATALINA_RE.match(line)
        if not match:
            return
        message = match.group("message")
        user_name = self.extract_user(message)
        event = EventRecord(
            event_uri=stable_id("event/catalina", f"{line_no}:{line}"),
            timestamp=parse_catalina_ts(match.group("ts")),
            log_name="catalina_20k.log",
            log_uri=log_uri,
            line_no=line_no,
            event_class="CatalinaLogEvent",
            extra_classes=("ApplicationLogEvent",),
            raw_message=line,
            hostname="fenix-app",
            service_name="tomcat",
            process_name=match.group("thread"),
            log_level=match.group("level"),
            user_name=user_name,
            event_type=match.group("logger"),
            message=message,
            indicators=self.detect_indicators(line),
            related_vulns=self.detect_related_vulns(line),
        )
        self.add_common_event_triples(event)

    def parse_audit_log(self, line: str, log_uri: str, line_no: int) -> None:
        match = AUDIT_MAIN_RE.match(line)
        if not match:
            return
        event_type = match.group("etype")
        rest = match.group("rest")
        attrs = {}
        for key, value in AUDIT_KV_RE.findall(rest):
            attrs[key] = value.strip("\"'")
        timestamp = None
        audit_ts = re.search(r"audit\(([\d.]+):\d+\)", rest)
        if audit_ts:
            timestamp = datetime.fromtimestamp(float(audit_ts.group(1))).isoformat()
        user_name = attrs.get("acct") or attrs.get("auid") or attrs.get("uid")
        message = attrs.get("msg", rest)
        event = EventRecord(
            event_uri=stable_id("event/audit", f"{line_no}:{line}"),
            timestamp=timestamp,
            log_name="audit_20k.log",
            log_uri=log_uri,
            line_no=line_no,
            event_class="Audit_Log_Event",
            extra_classes=("SecurityLogEvent",),
            raw_message=line,
            hostname="fenix-host",
            service_name="auditd",
            process_name=attrs.get("comm"),
            process_id=attrs.get("pid"),
            user_name=user_name,
            event_type=event_type,
            port=attrs.get("DPT"),
            command=attrs.get("cmdline"),
            session_id=attrs.get("ses"),
            message=message,
            indicators=self.detect_indicators(line),
            related_vulns=self.detect_related_vulns(line),
        )
        self.add_common_event_triples(event)

    def parse_dpkg_log(self, line: str, log_uri: str, line_no: int) -> None:
        match = DPKG_RE.match(line)
        if not match:
            return
        rest = match.group("rest") or ""
        tokens = rest.split()
        package_name = None
        version = None
        if tokens:
            package_name = tokens[0].split(":")[0]
        if len(tokens) > 1:
            version = tokens[-1] if tokens[-1] != "<none>" else None
        event = EventRecord(
            event_uri=stable_id("event/dpkg", f"{line_no}:{line}"),
            timestamp=parse_dpkg_ts(match.group("ts")),
            log_name="dpkg_20k.log",
            log_uri=log_uri,
            line_no=line_no,
            event_class="InstalledPackageLogEvent",
            extra_classes=("SystemLogEvent",),
            raw_message=line,
            hostname="fenix-host",
            service_name="dpkg",
            process_name="dpkg",
            event_type="package-management",
            package_action=match.group("action"),
            package_name=package_name,
            package_version=version,
            message=rest,
        )
        self.add_common_event_triples(event)

    def parse_dependencies(self) -> None:
        dependency_file = self.dataset_dir / "fenix.dependencies.txt"
        if not dependency_file.exists():
            return
        root_system = self.get_or_create_system("fenixedu-platform")
        for line_no, line in enumerate(dependency_file.read_text().splitlines(), start=1):
            parsed = parse_dependency_line(line)
            if not parsed:
                continue
            group_id, artifact_id, packaging, version = parsed
            gav = f"{group_id}:{artifact_id}"
            component_uri = stable_id("dependency", f"{gav}:{version}")
            self.add_type(component_uri, "Dependency")
            self.add_type(component_uri, "SoftwareComponent")
            self.add(component_uri, RDFS + "label", nt_literal(f"{gav}:{version}"))
            self.add(component_uri, AMIS_HASH + "hasPackageName", nt_literal(artifact_id))
            self.add(component_uri, AMIS_HASH + "hasPackageVersion", nt_literal(version))
            self.add(root_system, AMIS_HASH + "containsPackage", nt_uri(component_uri))
            self.stats["dependencies"] += 1

            for vuln in self.curated_vulns["artifacts"].get(gav, []):
                vuln_uri = self.get_or_create_vuln(
                    vuln["cve_id"], vuln["description"], vuln["severity"], vuln["cvss_score"]
                )
                self.add(component_uri, AMIS + "exposes", nt_uri(vuln_uri))
                self.add(root_system, AMIS + "hasVulnerability", nt_uri(vuln_uri))
                self.add(component_uri, AMIS_HASH + "relatedToVulnerability", nt_uri(vuln_uri))
                self.add(vuln_uri, AMIS_HASH + "affectsSystem", nt_uri(root_system))

    def ingest_nvd_linux_cves(self) -> None:
        cves = self.nvd_cves.get("cves", []) if isinstance(self.nvd_cves, dict) else []
        if not cves:
            return
        linux_system = self.get_or_create_system("linux-platform")
        self.add(linux_system, RDFS + "label", nt_literal("Linux Platform"))
        self.add(linux_system, RDFS + "comment", nt_literal("Synthetic system node for Linux-associated NVD vulnerabilities."))
        for item in cves:
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            description = item.get("description") or "NVD vulnerability entry."
            sev_field = item.get("severity")
            severity_detail = sev_field if isinstance(sev_field, dict) else None
            if isinstance(sev_field, dict):
                severity = (sev_field.get("baseSeverity") or "") or "UNKNOWN"
            elif isinstance(sev_field, str):
                severity = sev_field
            else:
                severity = "UNKNOWN"
            score = item.get("cvss_score")
            if score is None and severity_detail and severity_detail.get("baseScore") is not None:
                score = severity_detail["baseScore"]
            score_value = float(score) if isinstance(score, (int, float)) else 0.0
            vuln_uri = self.get_or_create_vuln(
                cve_id, description, severity, score_value, severity_detail=severity_detail
            )
            if item.get("published"):
                self.add(vuln_uri, AMIS_HASH + "hasCreationDate", nt_literal(item["published"]))
            if item.get("last_modified"):
                self.add(vuln_uri, AMIS_HASH + "hasLastModified", nt_literal(item["last_modified"]))
            self.add(vuln_uri, AMIS_HASH + "affectsSystem", nt_uri(linux_system))
            self.add(linux_system, AMIS + "hasVulnerability", nt_uri(vuln_uri))
            self.stats["nvd_linux_vulnerabilities"] += 1

    @staticmethod
    def extract_user(message: str) -> str | None:
        patterns = [
            r"\buser '?([A-Za-z0-9_.@-]+)'?",
            r"\bfor ([A-Za-z0-9_.@-]+) from",
            r"\bacct=\"([^\"]+)\"",
            r"\bby ([A-Za-z0-9_.@-]+)\(",
        ]
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def extract_port(message: str) -> str | None:
        match = re.search(r"\bport (\d+)\b|\bDPT=(\d+)\b", message)
        if not match:
            return None
        return match.group(1) or match.group(2)

    @staticmethod
    def extract_command(message: str) -> str | None:
        match = re.search(r"COMMAND=([^;]+)|cmdline=\"([^\"]+)\"", message)
        if not match:
            return None
        return (match.group(1) or match.group(2) or "").strip()

    @staticmethod
    def extract_session_status(message: str) -> str | None:
        lowered = message.lower()
        if "session opened" in lowered:
            return "opened"
        if "session closed" in lowered:
            return "closed"
        if "authentication failure" in lowered or "failed" in lowered:
            return "failed"
        if "accepted" in lowered:
            return "accepted"
        return None

    def link_event_sequences(self) -> None:
        for events in self.log_event_sequences.values():
            for prev, curr in zip(events, events[1:]):
                self.add(prev, AMIS + "hasNextLogEvent", nt_uri(curr))
                self.add(curr, AMIS + "hasPreviousLogEvent", nt_uri(prev))

    def _link_dpkg_event_to_nvd_cve(self, event: EventRecord) -> None:
        """Attach NVD CVEs whose text mentions the Debian package name (CQ16 demo join)."""
        pkg = (event.package_name or "").strip().lower()
        if len(pkg) < 3:
            return
        for item in self.nvd_cves.get("cves", []):
            desc = (item.get("description") or "").lower()
            if pkg not in desc:
                continue
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            vuln_uri = self.vuln_cache.get(cve_id)
            if not vuln_uri:
                continue
            self.add(event.event_uri, AMIS_HASH + "relatedToVulnerability", nt_uri(vuln_uri))
            self.add(vuln_uri, AMIS + "isObservedIn", nt_uri(event.event_uri))
            self.stats["dpkg_nvd_links"] += 1
            break

    def build(self) -> None:
        log_uris = self.create_logs()
        self.ingest_nvd_linux_cves()
        for filename, (_, event_class, top_class) in LOG_CONFIG.items():
            path = self.dataset_dir / filename
            if not path.exists():
                continue
            extra = ()
            if top_class == "ApplicationLog":
                extra = ("ApplicationLogEvent",)
            elif top_class == "SecurityLog":
                extra = ("SecurityLogEvent",)
            elif top_class == "SystemLog":
                extra = ("SystemLogEvent",)
            elif top_class == "AuthenticationLog":
                extra = ("AuthenticationLogEvent",)

            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_no, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    if not line:
                        continue
                    if filename == "access_20k.log":
                        self.parse_access_log(line, log_uris[filename], line_no)
                    elif filename == "audit_20k.log":
                        self.parse_audit_log(line, log_uris[filename], line_no)
                    elif filename == "catalina_20k.log":
                        self.parse_catalina_log(line, log_uris[filename], line_no)
                    elif filename == "dpkg_20k.log":
                        self.parse_dpkg_log(line, log_uris[filename], line_no)
                    else:
                        self.parse_syslog_family(filename, line, log_uris[filename], line_no, event_class, extra)
        self.parse_dependencies()
        self.link_event_sequences()


def write_stats(path: Path, stats: dict[str, int]) -> None:
    path.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset-dir",
        default="log_20k_AMISecOnto",
        help="Directory containing the input log files",
    )
    parser.add_argument(
        "--output-file",
        default="build/amiseconto_demo_data.nt",
        help="Path to the generated N-Triples file",
    )
    parser.add_argument(
        "--stats-file",
        default="build/amiseconto_demo_stats.json",
        help="Path to the generated JSON stats file",
    )
    parser.add_argument(
        "--curated-vulns",
        default="data/curated_vulnerabilities.json",
        help="Curated vulnerability mapping for demo enrichment",
    )
    parser.add_argument(
        "--nvd-file",
        default="data/nvd_linux_cves.json",
        help="Local JSON cache of Linux-associated NVD CVEs",
    )
    args = parser.parse_args()

    root = Path.cwd()
    dataset_dir = (root / args.dataset_dir).resolve()
    output_file = (root / args.output_file).resolve()
    stats_file = (root / args.stats_file).resolve()
    curated_vulns = (root / args.curated_vulns).resolve()
    nvd_file = (root / args.nvd_file).resolve()

    output_file.parent.mkdir(parents=True, exist_ok=True)
    stats_file.parent.mkdir(parents=True, exist_ok=True)

    builder = GraphBuilder(
        dataset_dir=dataset_dir,
        curated_vulns_path=curated_vulns,
        nvd_cves_path=nvd_file,
    )
    builder.build()

    output_file.write_text("\n".join(builder.triples) + "\n", encoding="utf-8")
    write_stats(stats_file, dict(builder.stats))

    print(f"Wrote {len(builder.triples):,} triples to {output_file}")
    print(f"Wrote stats to {stats_file}")


if __name__ == "__main__":
    main()
