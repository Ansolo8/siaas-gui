#!/usr/bin/env python3
"""SIAAS Web UI built with Streamlit."""

from __future__ import annotations

import os
from datetime import datetime

import streamlit as st

import aiaavsraw_aux as siaas_aux

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAR_DIR = os.path.join(BASE_DIR, "siaas-agent", "var")
PORTSCANNER_DB = os.path.join(VAR_DIR, "portscanner.db")
WEBSCANNER_DB = os.path.join(VAR_DIR, "webscanner.db")
METASPLOIT_DB = os.path.join(VAR_DIR, "metasploit.db")
REMEDIATION_DB = os.path.join(VAR_DIR, "remediation.db")

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "unknown": 0,
    "n/a": 0,
    "": 0,
}


@st.cache_data(ttl=30)
def load_data() -> tuple[dict, dict, dict, dict]:
    port_data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
    web_data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
    metasploit_data = siaas_aux.read_from_local_file(METASPLOIT_DB) or {}
    remediation_data = siaas_aux.read_from_local_file(REMEDIATION_DB) or {}
    return port_data, web_data, metasploit_data, remediation_data


def normalize_severity(value) -> str:
    severity = str(value or "unknown").strip().lower()
    if severity == "informational":
        return "info"
    return severity or "unknown"


def severity_score(value) -> int:
    return SEVERITY_ORDER.get(normalize_severity(value), 0)


def find_first_key(value, wanted_keys: tuple[str, ...]):
    if isinstance(value, dict):
        for key in wanted_keys:
            if key in value and value[key] not in [None, ""]:
                return value[key]
        for nested in value.values():
            found = find_first_key(nested, wanted_keys)
            if found not in [None, ""]:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = find_first_key(nested, wanted_keys)
            if found not in [None, ""]:
                return found
    return None


def count_stat(info: dict, *names: str) -> int:
    stats = info.get("stats", {}) if isinstance(info, dict) else {}
    for name in names:
        try:
            return int(stats.get(name, 0) or 0)
        except (TypeError, ValueError):
            continue
    return 0


def format_modules(modules: list[dict]) -> str:
    return ", ".join(module.get("module", "") for module in modules if isinstance(module, dict) and module.get("module"))


def extract_port_vulnerabilities(host_info: dict) -> list[dict]:
    """Flatten Nmap/portscanner findings from current and older DB shapes."""
    vulnerabilities = []
    for port, port_info in host_info.get("scanned_ports", {}).items():
        service = port_info.get("service", "unknown")
        product = port_info.get("product", "")
        result_sources = []
        if isinstance(port_info.get("scan_results"), dict):
            result_sources.append(("scan_results", port_info.get("scan_results", {})))
        if isinstance(port_info.get("scripts"), dict):
            result_sources.append(("scripts", port_info.get("scripts", {})))

        for source_name, scripts in result_sources:
            for script_name, script_output in scripts.items():
                if isinstance(script_output, dict):
                    for vuln_id, vuln_info in script_output.items():
                        if isinstance(vuln_info, dict):
                            state = str(vuln_info.get("state", "")).upper()
                            severity = find_first_key(vuln_info, ("severity", "risk", "cvss")) or "unknown"
                            description = find_first_key(vuln_info, ("description", "title", "summary", "output"))
                            if state == "NOT VULNERABLE" and severity_score(severity) == 0:
                                continue
                            vulnerabilities.append(
                                {
                                    "Port": port,
                                    "Service": service,
                                    "Product": product,
                                    "Script": script_name,
                                    "ID": vuln_id,
                                    "Severity": normalize_severity(severity),
                                    "State": state or vuln_info.get("is_exploit", ""),
                                    "Description": description or str(vuln_info)[:500],
                                    "Source": source_name,
                                }
                            )
                        elif isinstance(vuln_info, (str, int, float)) and str(vuln_info).strip():
                            vulnerabilities.append(
                                {
                                    "Port": port,
                                    "Service": service,
                                    "Product": product,
                                    "Script": script_name,
                                    "ID": vuln_id,
                                    "Severity": "unknown",
                                    "State": "",
                                    "Description": str(vuln_info)[:500],
                                    "Source": source_name,
                                }
                            )
                elif isinstance(script_output, str) and script_output.strip():
                    vulnerabilities.append(
                        {
                            "Port": port,
                            "Service": service,
                            "Product": product,
                            "Script": script_name,
                            "ID": script_name,
                            "Severity": "unknown",
                            "State": "",
                            "Description": script_output[:500],
                            "Source": source_name,
                        }
                    )
    vulnerabilities.sort(key=lambda item: (-severity_score(item.get("Severity")), item.get("Port", "")))
    return vulnerabilities


def extract_web_vulnerabilities(web_info: dict) -> list[dict]:
    """Flatten OWASP ZAP findings from current and older DB shapes."""
    vulnerabilities = []
    for port, port_info in web_info.get("scanned_ports", {}).items():
        service = port_info.get("service", "http")
        for scan_name, scan_result in port_info.get("scan_results", {}).items():
            vuln_bucket = scan_result.get("zap_scan", {}).get("vuln", {}) if isinstance(scan_result, dict) else {}
            for vuln_id, vuln in vuln_bucket.items():
                if not isinstance(vuln, dict):
                    continue
                vulnerabilities.append(
                    {
                        "Port": port,
                        "Service": service,
                        "Scan": scan_name,
                        "ID": vuln_id,
                        "Severity": normalize_severity(vuln.get("severity", "unknown")),
                        "CWE": vuln.get("cwe", ""),
                        "Description": vuln.get("description", "OWASP ZAP finding"),
                        "Solution": vuln.get("solution", ""),
                        "Reference": vuln.get("reference", ""),
                    }
                )

    for source, source_info in web_info.get("scanned_sources", {}).items():
        if not isinstance(source_info, dict):
            continue
        for vuln_type, vuln_entries in source_info.items():
            if isinstance(vuln_entries, list):
                for entry in vuln_entries:
                    if isinstance(entry, dict):
                        vulnerabilities.append(
                            {
                                "Port": source,
                                "Service": "web",
                                "Scan": vuln_type,
                                "ID": entry.get("id", vuln_type),
                                "Severity": normalize_severity(entry.get("severity", "unknown")),
                                "CWE": entry.get("cwe", ""),
                                "Description": entry.get("description", "OWASP ZAP finding"),
                                "Solution": entry.get("solution", ""),
                                "Reference": entry.get("reference", ""),
                            }
                        )
    vulnerabilities.sort(key=lambda item: (-severity_score(item.get("Severity")), item.get("Port", "")))
    return vulnerabilities


def extract_metasploit_services(metasploit_data: dict) -> list[dict]:
    rows = []
    for target, target_info in metasploit_data.get("targets", {}).items():
        for port, service_info in target_info.get("services", {}).items():
            modules = service_info.get("metasploit_modules", []) or []
            cves = service_info.get("cves", []) or []
            rows.append(
                {
                    "Target": target,
                    "Port": port,
                    "Service": service_info.get("service", "unknown"),
                    "Product": service_info.get("product", ""),
                    "CVEs": ", ".join(cves),
                    "Modules": len(modules),
                    "Module Names": format_modules(modules),
                    "Confidence": service_info.get("confidence", "unknown"),
                    "Action": service_info.get("recommended_action", "review"),
                    "Errors": service_info.get("errors", ""),
                }
            )
    rows.sort(key=lambda item: (-item.get("Modules", 0), item.get("Target", ""), item.get("Port", "")))
    return rows


def extract_remediation_findings(remediation_data: dict) -> list[dict]:
    rows = []
    for finding in remediation_data.get("remediation_plan", []) if isinstance(remediation_data, dict) else []:
        if not isinstance(finding, dict):
            continue
        rows.append(
            {
                "Severity": normalize_severity(finding.get("severity", "unknown")),
                "Score": finding.get("score", 0),
                "Status": finding.get("status", "open"),
                "Target": finding.get("target", "unknown"),
                "Port": finding.get("port", ""),
                "Service": finding.get("service", "unknown"),
                "Source": finding.get("source", "unknown"),
                "Title": finding.get("title", "Untitled finding"),
                "CVEs": ", ".join(finding.get("cves", []) or []),
                "Recommendation": finding.get("recommendation", ""),
                "Last Seen": finding.get("last_seen", ""),
                "ID": finding.get("id", ""),
            }
        )
    rows.sort(key=lambda item: (-severity_score(item.get("Severity")), -int(item.get("Score", 0) or 0), item.get("Target", "")))
    return rows


def filter_by_severity(rows: list[dict], severity_filter: list[str]) -> list[dict]:
    if not severity_filter:
        return rows
    wanted = {normalize_severity(severity) for severity in severity_filter}
    return [row for row in rows if normalize_severity(row.get("Severity")) in wanted]


def build_dashboard(port_data: dict, web_data: dict, metasploit_data: dict, remediation_data: dict):
    consolidated = {}

    for host, info in port_data.items():
        stats = info.get("stats", {})
        last_check = info.get("last_check", "")
        consolidated.setdefault(host, {"vulns": 0, "exploits": 0, "msf": 0, "remediation": 0, "last_scan": "", "scanners": set()})
        consolidated[host]["vulns"] += int(stats.get("total_num_vulnerabilities", 0) or 0)
        consolidated[host]["exploits"] += int(stats.get("total_num_exploits", 0) or 0)
        consolidated[host]["scanners"].add("Port")
        if last_check > consolidated[host]["last_scan"]:
            consolidated[host]["last_scan"] = last_check

    for target_key, info in web_data.items():
        host = target_key.split(":", 1)[0]
        stats = info.get("stats", {})
        last_check = info.get("last_check", "")
        consolidated.setdefault(host, {"vulns": 0, "exploits": 0, "msf": 0, "remediation": 0, "last_scan": "", "scanners": set()})
        consolidated[host]["vulns"] += int(stats.get("total_num_vulnerabilities", 0) or 0)
        consolidated[host]["exploits"] += int(stats.get("total_num_exploits", 0) or 0)
        consolidated[host]["scanners"].add("Web")
        if last_check > consolidated[host]["last_scan"]:
            consolidated[host]["last_scan"] = last_check

    for row in extract_metasploit_services(metasploit_data):
        host = row["Target"]
        consolidated.setdefault(host, {"vulns": 0, "exploits": 0, "msf": 0, "remediation": 0, "last_scan": "", "scanners": set()})
        consolidated[host]["msf"] += row.get("Modules", 0)
        consolidated[host]["scanners"].add("Metasploit")

    for row in extract_remediation_findings(remediation_data):
        host = row["Target"]
        consolidated.setdefault(host, {"vulns": 0, "exploits": 0, "msf": 0, "remediation": 0, "last_scan": "", "scanners": set()})
        consolidated[host]["remediation"] += 1
        consolidated[host]["scanners"].add("Remediation")
        if row.get("Last Seen", "") > consolidated[host]["last_scan"]:
            consolidated[host]["last_scan"] = row.get("Last Seen", "")

    rows = []
    for host, data in consolidated.items():
        rows.append(
            {
                "Host": host,
                "Vulnerabilities": data["vulns"],
                "Exploits": data["exploits"],
                "Metasploit Modules": data["msf"],
                "Remediation Items": data["remediation"],
                "Last Scan": data["last_scan"][:19] if data["last_scan"] else "N/A",
                "Scanners": ", ".join(sorted(data["scanners"])),
            }
        )

    rows.sort(key=lambda x: (x["Vulnerabilities"] + x["Metasploit Modules"] + x["Remediation Items"]), reverse=True)
    st.dataframe(rows[:25], use_container_width=True, hide_index=True)


def render_vulnerability_explorer(title: str, rows: list[dict], raw_lookup: dict | None = None) -> None:
    st.subheader(title)
    severity_filter = st.multiselect(
        "Severity",
        ["critical", "high", "medium", "low", "info", "unknown"],
        default=[],
        key=f"{title}_severity",
    )
    filtered = filter_by_severity(rows, severity_filter)
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    if not filtered:
        return

    labels = [f"{row.get('Target', row.get('Port', 'item'))} | {row.get('Port', '')} | {row.get('Title', row.get('Description', row.get('ID', 'finding')))[:80]}" for row in filtered]
    selected_label = st.selectbox("Open finding details", labels, key=f"{title}_details")
    selected = filtered[labels.index(selected_label)]
    st.json(selected, expanded=True)
    if raw_lookup and selected.get("ID") in raw_lookup:
        with st.expander("Raw finding data"):
            st.json(raw_lookup[selected["ID"]], expanded=False)


def main() -> None:
    st.set_page_config(page_title="SIAAS Web", layout="wide")
    st.title("🔒 SIAAS - Security Audit System (Web)")
    st.caption(f"Last refresh: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    if st.button("Refresh data"):
        st.cache_data.clear()

    port_data, web_data, metasploit_data, remediation_data = load_data()
    remediation_rows = extract_remediation_findings(remediation_data)
    metasploit_rows = extract_metasploit_services(metasploit_data)

    tabs = st.tabs(["Dashboard", "Port Scanner", "Web Scanner", "Metasploit", "Remediation"])

    with tabs[0]:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.subheader("Port Scanner")
            st.metric("Total Hosts", len(port_data))
            st.metric("Open Ports", sum(len(i.get("scanned_ports", {})) for i in port_data.values()))
            st.metric("Vulnerabilities", sum(count_stat(i, "total_num_vulnerabilities") for i in port_data.values()))

        with col2:
            st.subheader("Web Scanner")
            st.metric("Web Hosts", len(web_data))
            st.metric("Scanned Targets", len(web_data))
            st.metric("Vulnerabilities", sum(count_stat(i, "total_num_vulnerabilities") for i in web_data.values()))

        with col3:
            st.subheader("Metasploit")
            st.metric("Targets", metasploit_data.get("stats", {}).get("num_targets", 0))
            st.metric("Services", metasploit_data.get("stats", {}).get("num_services", len(metasploit_rows)))
            st.metric("Candidate Modules", metasploit_data.get("stats", {}).get("num_candidate_modules", sum(r.get("Modules", 0) for r in metasploit_rows)))

        with col4:
            st.subheader("Remediation")
            summary = remediation_data.get("executive_summary", {}) if isinstance(remediation_data, dict) else {}
            severity_counts = summary.get("severity_counts", {})
            st.metric("Open Findings", summary.get("total_open_findings", len(remediation_rows)))
            st.metric("Critical/High", int(severity_counts.get("critical", 0) or 0) + int(severity_counts.get("high", 0) or 0))
            st.metric("Sources", len(remediation_data.get("stats", {}).get("sources", [])) if isinstance(remediation_data, dict) else 0)

        if remediation_data.get("executive_summary", {}).get("recommended_next_step"):
            st.info(remediation_data["executive_summary"]["recommended_next_step"])

        st.subheader("Top Risk Hosts (Consolidated)")
        build_dashboard(port_data, web_data, metasploit_data, remediation_data)

    with tabs[1]:
        st.subheader("Port Scanner Results")
        host_filter = st.text_input("Filter hosts", key="port_filter")

        rows = []
        for host, info in port_data.items():
            if host_filter and host_filter.lower() not in host.lower():
                continue
            rows.append(
                {
                    "Host": host,
                    "OS": info.get("system_info", {}).get("os_name", "Unknown"),
                    "Open Ports": len(info.get("scanned_ports", {})),
                    "Vulnerabilities": info.get("stats", {}).get("total_num_vulnerabilities", len(extract_port_vulnerabilities(info))),
                    "Exploits": info.get("stats", {}).get("total_num_exploits", 0),
                    "Last Check": (info.get("last_check") or "")[:19] or "N/A",
                }
            )

        st.dataframe(rows, use_container_width=True, hide_index=True)

        if rows:
            selected_host = st.selectbox("Host details", [r["Host"] for r in rows], key="port_details")
            selected = port_data[selected_host]
            detail_tabs = st.tabs(["Vulnerabilities", "Open Ports", "System Info", "Raw JSON"])
            with detail_tabs[0]:
                vulnerabilities = extract_port_vulnerabilities(selected)
                render_vulnerability_explorer(f"Port vulnerabilities for {selected_host}", vulnerabilities)
            with detail_tabs[1]:
                ports = []
                for port, port_info in selected.get("scanned_ports", {}).items():
                    ports.append(
                        {
                            "Port": port,
                            "State": port_info.get("state", "unknown"),
                            "Service": port_info.get("service", "unknown"),
                            "Product": port_info.get("product", ""),
                            "Version": port_info.get("version", ""),
                        }
                    )
                st.dataframe(ports, use_container_width=True, hide_index=True)
            with detail_tabs[2]:
                st.json(selected.get("system_info", {}), expanded=True)
            with detail_tabs[3]:
                st.json(selected, expanded=False)

    with tabs[2]:
        st.subheader("Web Scanner Results")
        target_filter = st.text_input("Filter targets", key="web_filter")

        rows = []
        filtered_keys = []
        for target_key, info in web_data.items():
            if target_filter and target_filter.lower() not in target_key.lower():
                continue
            filtered_keys.append(target_key)
            rows.append(
                {
                    "Target": target_key,
                    "URL": info.get("system_info", {}).get("scanned_url", "N/A"),
                    "Server": info.get("system_info", {}).get("server", "Unknown"),
                    "Vulnerabilities": info.get("stats", {}).get("total_num_vulnerabilities", len(extract_web_vulnerabilities(info))),
                    "Exploits": info.get("stats", {}).get("total_num_exploits", 0),
                    "Last Check": (info.get("last_check") or "")[:19] or "N/A",
                }
            )

        st.dataframe(rows, use_container_width=True, hide_index=True)

        if filtered_keys:
            selected_key = st.selectbox("Target details", filtered_keys, key="web_details")
            selected = web_data[selected_key]
            detail_tabs = st.tabs(["Vulnerabilities", "System Info", "Raw JSON"])
            with detail_tabs[0]:
                vulnerabilities = extract_web_vulnerabilities(selected)
                render_vulnerability_explorer(f"Web vulnerabilities for {selected_key}", vulnerabilities)
            with detail_tabs[1]:
                st.json(selected.get("system_info", {}), expanded=True)
            with detail_tabs[2]:
                st.json(selected, expanded=False)

    with tabs[3]:
        st.subheader("Metasploit Assistant")
        st.caption("Defensive correlation only: shows CVEs/services/products mapped to local Metasploit module candidates.")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Targets", metasploit_data.get("stats", {}).get("num_targets", 0))
        with col2:
            st.metric("Services", metasploit_data.get("stats", {}).get("num_services", len(metasploit_rows)))
        with col3:
            st.metric("Candidate Modules", metasploit_data.get("stats", {}).get("num_candidate_modules", sum(r.get("Modules", 0) for r in metasploit_rows)))

        target_filter = st.text_input("Filter targets/services/modules", key="metasploit_filter")
        filtered = [row for row in metasploit_rows if not target_filter or target_filter.lower() in " ".join(str(v).lower() for v in row.values())]
        st.dataframe(filtered, use_container_width=True, hide_index=True)
        if filtered:
            labels = [f"{row['Target']} | {row['Port']} | {row['Service']} | {row['Modules']} modules" for row in filtered]
            selected_label = st.selectbox("Service correlation details", labels, key="metasploit_details")
            st.json(filtered[labels.index(selected_label)], expanded=True)
        with st.expander("Raw Metasploit assistant DB"):
            st.json(metasploit_data, expanded=False)

    with tabs[4]:
        st.subheader("Remediation Advisor")
        summary = remediation_data.get("executive_summary", {}) if isinstance(remediation_data, dict) else {}
        if summary:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Open Findings", summary.get("total_open_findings", len(remediation_rows)))
            with col2:
                counts = summary.get("severity_counts", {})
                st.metric("Critical/High", int(counts.get("critical", 0) or 0) + int(counts.get("high", 0) or 0))
            with col3:
                st.metric("Affected Targets", len(summary.get("most_affected_targets", [])))
            st.info(summary.get("recommended_next_step", "Review the prioritized remediation plan below."))

        source_filter = st.multiselect("Source", sorted({row.get("Source", "unknown") for row in remediation_rows}), default=[])
        severity_filter = st.multiselect("Severity", ["critical", "high", "medium", "low", "info", "unknown"], default=[], key="remediation_severity")
        text_filter = st.text_input("Filter remediation plan", key="remediation_filter")
        filtered = filter_by_severity(remediation_rows, severity_filter)
        if source_filter:
            filtered = [row for row in filtered if row.get("Source") in source_filter]
        if text_filter:
            filtered = [row for row in filtered if text_filter.lower() in " ".join(str(v).lower() for v in row.values())]

        st.dataframe(filtered, use_container_width=True, hide_index=True)
        if filtered:
            labels = [f"{row['Severity'].upper()} | {row['Target']} | {row['Title'][:90]}" for row in filtered]
            selected_label = st.selectbox("Remediation details", labels, key="remediation_details")
            selected = filtered[labels.index(selected_label)]
            st.json(selected, expanded=True)
            st.markdown("**Recommendation**")
            st.write(selected.get("Recommendation", ""))
        with st.expander("Raw remediation DB"):
            st.json(remediation_data, expanded=False)


if __name__ == "__main__":
    main()
