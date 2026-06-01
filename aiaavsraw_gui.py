#!/usr/bin/env python3
"""SIAAS Web UI built with Streamlit."""

from __future__ import annotations

import os
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st

import aiaavsraw_aux as siaas_aux

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAR_DIR = os.path.join(BASE_DIR, "siaas-agent", "var")
PORTSCANNER_DB = os.path.join(VAR_DIR, "portscanner.db")
WEBSCANNER_DB = os.path.join(VAR_DIR, "webscanner.db")
METASPLOIT_DB = os.path.join(VAR_DIR, "metasploit.db")
REMEDIATION_DB = os.path.join(VAR_DIR, "remediation.db")
AUDIT_DB = os.path.join(VAR_DIR, "audit.db")

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
def load_data() -> tuple[dict, dict, dict, dict, dict]:
    port_data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
    web_data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
    metasploit_data = siaas_aux.read_from_local_file(METASPLOIT_DB) or {}
    remediation_data = siaas_aux.read_from_local_file(REMEDIATION_DB) or {}
    audit_data = siaas_aux.read_from_local_file(AUDIT_DB) or {}
    return port_data, web_data, metasploit_data, remediation_data, audit_data


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


def format_module_platform(platform) -> str:
    if isinstance(platform, list):
        return ", ".join(str(p) for p in platform if p)
    return str(platform or "")


PORT_VULNERABILITY_DETAIL_KEYS = {
    "description",
    "title",
    "summary",
    "output",
    "severity",
    "risk",
    "cvss",
    "state",
    "is_exploit",
    "cve",
    "cves",
}


def is_port_vulnerability_record(value: dict) -> bool:
    return any(str(key).lower() in PORT_VULNERABILITY_DETAIL_KEYS for key in value.keys())


def list_to_description(value: list) -> str:
    descriptions = []
    for item in value:
        if isinstance(item, (dict, list)):
            descriptions.append(str(item))
        elif item not in [None, ""]:
            descriptions.append(str(item))
    return "; ".join(descriptions)


def script_path_label(path: list[str]) -> str:
    return " > ".join(str(part) for part in path if str(part))


def make_port_vulnerability_row(
    port: str,
    service: str,
    product: str,
    source_name: str,
    script_name: str,
    path: list[str],
    vulnerability_id: str,
    vulnerability_info,
) -> dict | None:
    if isinstance(vulnerability_info, dict):
        state = str(vulnerability_info.get("state", "")).upper()
        severity = find_first_key(vulnerability_info, ("severity", "risk", "cvss")) or "unknown"
        description = find_first_key(vulnerability_info, ("description", "title", "summary", "output")) or str(vulnerability_info)
        if state == "NOT VULNERABLE" and severity_score(severity) == 0:
            return None
    elif isinstance(vulnerability_info, list):
        state = ""
        severity = "unknown"
        description = list_to_description(vulnerability_info)
        if not description:
            return None
    elif isinstance(vulnerability_info, (str, int, float)):
        state = ""
        severity = "unknown"
        description = str(vulnerability_info)
        if not description.strip():
            return None
    else:
        return None

    database = path[0] if script_name == "vulscan" and len(path) > 1 else ""
    return {
        "Port": port,
        "Service": service,
        "Product": product,
        "Script": script_name,
        "Database": database,
        "ID": vulnerability_id,
        "Severity": normalize_severity(severity),
        "State": state,
        "Description": description,
        "Source": source_name,
        "Path": script_path_label(path),
    }


def flatten_port_script_findings(
    port: str,
    service: str,
    product: str,
    source_name: str,
    script_name: str,
    script_output,
    path: list[str] | None = None,
) -> list[dict]:
    path = path or []
    rows = []

    if isinstance(script_output, dict):
        if is_port_vulnerability_record(script_output):
            row = make_port_vulnerability_row(
                port, service, product, source_name, script_name, path, path[-1] if path else script_name, script_output
            )
            return [row] if row else []

        for key, nested_value in script_output.items():
            nested_path = path + [str(key)]
            if isinstance(nested_value, dict):
                rows.extend(
                    flatten_port_script_findings(
                        port, service, product, source_name, script_name, nested_value, nested_path
                    )
                )
            else:
                row = make_port_vulnerability_row(
                    port, service, product, source_name, script_name, nested_path, str(key), nested_value
                )
                if row:
                    rows.append(row)
        return rows

    row = make_port_vulnerability_row(port, service, product, source_name, script_name, path, script_name, script_output)
    return [row] if row else []


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
                vulnerabilities.extend(
                    flatten_port_script_findings(
                        port, service, product, source_name, script_name, script_output, path=[]
                    )
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
            matched_cves = service_info.get("matched_cves", []) or []
            rows.append(
                {
                    "Target": target,
                    "Port": port,
                    "Service": service_info.get("service", "unknown"),
                    "Product": service_info.get("product", ""),
                    "CVEs": ", ".join(cves),
                    "Matched CVEs": ", ".join(matched_cves),
                    "Correlation": service_info.get("correlation_method", ""),
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
                "First Seen": finding.get("first_seen", ""),
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
        scanned_url = info.get("system_info", {}).get("scanned_url", "")
        if scanned_url:
            parsed = urlparse(scanned_url)
            host = parsed.hostname or target_key.split(":", 1)[0]
        else:
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


def truncate_text(value, limit: int = 220) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def table_height(num_rows: int) -> int:
    return min(720, max(220, 40 + (min(num_rows, 18) * 35)))


def render_finding_card(index: int, row: dict, raw_lookup: dict | None = None) -> None:
    title = row.get("Title") or row.get("ID") or row.get("Description") or "Finding"
    severity = str(row.get("Severity", "unknown")).upper()
    location = " / ".join(str(row.get(key, "")) for key in ("Target", "Port") if row.get(key))

    with st.container(border=True):
        st.markdown(f"**{index}. [{severity}] {title}**")
        if location:
            st.caption(location)

        metadata = {
            key: row.get(key)
            for key in (
                "Port",
                "Service",
                "Product",
                "Script",
                "Database",
                "Path",
                "Scan",
                "ID",
                "State",
                "Source",
                "CWE",
                "CVEs",
                "Status",
                "Score",
            )
            if row.get(key) not in [None, ""]
        }
        if metadata:
            st.dataframe([metadata], use_container_width=True, hide_index=True)

        description = row.get("Description") or row.get("Recommendation") or "No description was provided by the scanner."
        st.markdown("**Description**")
        st.write(description)

        for field in ("Solution", "Recommendation", "Reference"):
            if row.get(field):
                st.markdown(f"**{field}**")
                st.write(row[field])

        if raw_lookup and row.get("ID") in raw_lookup:
            with st.expander("Raw finding data"):
                st.json(raw_lookup[row["ID"]], expanded=False)


def render_vulnerability_explorer(title: str, rows: list[dict], raw_lookup: dict | None = None) -> None:
    st.subheader(title)
    st.caption("Select a host/target above, then use these filters to list every matching vulnerability with its full description.")
    col1, col2 = st.columns([1, 2])
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low", "info", "unknown"],
            default=[],
            key=f"{title}_severity",
        )
    with col2:
        text_filter = st.text_input("Search vulnerability text", key=f"{title}_search")

    filtered = filter_by_severity(rows, severity_filter)
    if text_filter:
        filtered = [row for row in filtered if text_filter.lower() in " ".join(str(value).lower() for value in row.values())]

    st.write(f"Showing {len(filtered)} of {len(rows)} vulnerabilities for this selection.")
    if not filtered:
        st.info("No vulnerabilities match the current filters.")
        return

    table_rows = []
    for row in filtered:
        preview = dict(row)
        preview["Description Preview"] = truncate_text(row.get("Description") or row.get("Recommendation"))
        preview.pop("Description", None)
        preview.pop("Solution", None)
        preview.pop("Recommendation", None)
        preview.pop("Reference", None)
        table_rows.append(preview)

    st.dataframe(
        table_rows,
        use_container_width=True,
        hide_index=True,
        height=table_height(len(table_rows)),
        column_config={"Description Preview": st.column_config.TextColumn(width="large")},
    )

    show_full_descriptions = st.toggle(
        "Show full descriptions for all listed vulnerabilities",
        value=True,
        key=f"{title}_show_full",
    )
    if show_full_descriptions:
        for index, row in enumerate(filtered, start=1):
            render_finding_card(index, row, raw_lookup=raw_lookup)
    else:
        labels = [
            f"{row.get('Severity', 'unknown').upper()} | {row.get('Port', row.get('Target', 'item'))} | "
            f"{row.get('Title', row.get('Description', row.get('ID', 'finding')))[:100]}"
            for row in filtered
        ]
        selected_label = st.selectbox("Open one finding details", labels, key=f"{title}_details")
        render_finding_card(labels.index(selected_label) + 1, filtered[labels.index(selected_label)], raw_lookup=raw_lookup)


def render_metasploit_service_detail(row: dict, raw_service: dict) -> None:
    with st.container(border=True):
        st.markdown(f"**{row['Target']} : {row['Port']} / {row['Service']}**")
        if row.get("Product"):
            st.caption(row["Product"])

        meta = {k: row[k] for k in ("Confidence", "Action", "Correlation") if row.get(k) not in [None, ""]}
        if row.get("CVEs"):
            meta["CVEs"] = row["CVEs"]
        if row.get("Matched CVEs"):
            meta["Matched CVEs"] = row["Matched CVEs"]
        if meta:
            st.dataframe([meta], use_container_width=True, hide_index=True)

        if row.get("Errors"):
            st.warning(f"Errors: {row['Errors']}")

        modules = raw_service.get("metasploit_modules", []) or []
        if modules:
            st.markdown(f"**Candidate Modules ({len(modules)})**")
            module_rows = []
            for m in modules:
                if not isinstance(m, dict):
                    continue
                module_rows.append(
                    {
                        "Module": m.get("module", ""),
                        "Rank": m.get("rank", ""),
                        "Platform": format_module_platform(m.get("platform")),
                        "Matched CVE": m.get("matched_cve", ""),
                    }
                )
            st.dataframe(module_rows, use_container_width=True, hide_index=True)
        else:
            st.info("No candidate modules found for this service.")


def render_remediation_detail(row: dict, raw_finding: dict) -> None:
    with st.container(border=True):
        severity = str(row.get("Severity", "unknown")).upper()
        st.markdown(f"**[{severity}] {row.get('Title', 'Finding')}**")
        location = " / ".join(str(row.get(k, "")) for k in ("Target", "Port") if row.get(k))
        if location:
            st.caption(location)

        meta = {k: row[k] for k in ("Service", "Source", "Score", "Status", "CVEs", "First Seen", "Last Seen", "ID") if row.get(k) not in [None, ""]}
        if raw_finding.get("notes"):
            meta["Notes"] = raw_finding["notes"]
        if raw_finding.get("ai_model"):
            meta["AI Model"] = raw_finding["ai_model"]
        if meta:
            st.dataframe([meta], use_container_width=True, hide_index=True)

        if raw_finding.get("ai_error"):
            st.warning(f"AI Error: {raw_finding['ai_error']}")

        ai_rem = raw_finding.get("ai_remediation")
        if isinstance(ai_rem, dict):
            st.markdown("#### AI-Assisted Remediation")
            if ai_rem.get("risk_summary"):
                st.markdown("**Risk Summary**")
                st.write(ai_rem["risk_summary"])
            if ai_rem.get("likely_impact"):
                st.markdown("**Likely Impact**")
                st.write(ai_rem["likely_impact"])
            if ai_rem.get("priority_reasoning"):
                st.markdown("**Priority Reasoning**")
                st.write(ai_rem["priority_reasoning"])
            steps = ai_rem.get("remediation_steps") or []
            if steps:
                st.markdown("**Remediation Steps**")
                for i, step in enumerate(steps, 1):
                    st.markdown(f"{i}. {step}")
            val_steps = ai_rem.get("validation_steps") or []
            if val_steps:
                st.markdown("**Validation Steps**")
                for i, step in enumerate(val_steps, 1):
                    st.markdown(f"{i}. {step}")
        elif row.get("Recommendation"):
            st.markdown("**Recommendation**")
            st.write(row["Recommendation"])

        with st.expander("Raw finding data"):
            st.json(raw_finding, expanded=False)


RISK_LEVEL_COLOURS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "🔵",
    "unknown": "⚪",
}


def risk_badge(level: str) -> str:
    level = str(level or "unknown").lower()
    return f"{RISK_LEVEL_COLOURS.get(level, '⚪')} {level.upper()}"


def render_audit_tab(audit_data: dict) -> None:
    if not audit_data:
        st.info("No audit report found. Run the audit module to generate one.")
        return

    narrative = audit_data.get("narrative", {})
    org = audit_data.get("org_metrics", {})
    host_metrics = audit_data.get("host_metrics", [])
    web_metrics = audit_data.get("web_metrics", [])
    sev_counts = org.get("remediation_severity_counts", {})

    # ── Posture banner ────────────────────────────────────────────────────────
    risk_level = str(org.get("org_risk_level", "unknown")).lower()
    risk_score = org.get("org_risk_score", "N/A")
    badge_colour = {"critical": "red", "high": "orange", "medium": "#e6b800", "low": "green"}.get(risk_level, "grey")
    st.markdown(
        f"<div style='padding:12px 18px;border-radius:8px;background:{badge_colour}22;border-left:5px solid {badge_colour}'>"
        f"<span style='font-size:1.3em;font-weight:700;color:{badge_colour}'>{risk_badge(risk_level)}</span>"
        f"&nbsp;&nbsp;<span style='font-size:1.1em'>Overall Risk Score: <b>{risk_score}</b></span>"
        f"&nbsp;&nbsp;<span style='opacity:.7'>{narrative.get('overall_posture','')}</span>"
        "</div>",
        unsafe_allow_html=True,
    )
    st.write("")

    # ── Org stats bar ─────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Hosts Scanned", org.get("total_hosts_scanned", 0))
    c2.metric("Web Targets", org.get("total_web_targets_scanned", 0))
    c3.metric("Open Ports", org.get("total_open_ports", 0))
    c4.metric("Unique CVEs", org.get("total_unique_cves", 0))
    c5.metric("Exploitable Hosts", org.get("exploitable_hosts", 0))

    st.divider()

    # ── Executive summary + severity breakdown ────────────────────────────────
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("#### Executive Summary")
        st.write(narrative.get("executive_summary", ""))

        if narrative.get("key_risks"):
            st.markdown("**Key Risks**")
            for risk in narrative["key_risks"]:
                st.markdown(f"- {risk}")

        if narrative.get("positive_observations"):
            st.markdown("**Positive Observations**")
            for obs in narrative["positive_observations"]:
                st.markdown(f"- ✅ {obs}")

    with col_right:
        st.markdown("#### Severity Breakdown")
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        sev_rows = [
            {"Severity": s.capitalize(), "Count": int(sev_counts.get(s, 0) or 0)}
            for s in sev_order
            if int(sev_counts.get(s, 0) or 0) > 0
        ]
        if sev_rows:
            st.bar_chart(
                {r["Severity"]: r["Count"] for r in sev_rows},
                use_container_width=True,
                height=220,
            )
        else:
            st.info("No severity data.")

    st.divider()

    # ── Priority actions ──────────────────────────────────────────────────────
    if narrative.get("priority_actions"):
        st.markdown("#### Priority Actions")
        for i, action in enumerate(narrative["priority_actions"], 1):
            st.markdown(f"{i}. {action}")

    st.divider()

    # ── Host & web metrics tables ─────────────────────────────────────────────
    col_h, col_w = st.columns(2)

    with col_h:
        st.markdown("#### Host Risk Summary")
        if host_metrics:
            host_rows = []
            for h in host_metrics:
                host_rows.append({
                    "Host": h.get("host", ""),
                    "Risk": risk_badge(h.get("risk_level", "unknown")),
                    "Risk Score": h.get("risk_score", 0),
                    "Open Ports": h.get("num_open_ports", 0),
                    "CVEs": h.get("num_cves", 0),
                    "Exploitable": "⚠️ Yes" if h.get("exploitable") else "No",
                    "OS": h.get("os_family", ""),
                })
            st.dataframe(host_rows, use_container_width=True, hide_index=True)

            with st.expander("Host details"):
                for h in host_metrics:
                    with st.container(border=True):
                        st.markdown(f"**{h.get('host','')}** — {risk_badge(h.get('risk_level','unknown'))} (score: {h.get('risk_score',0)})")
                        if h.get("cves"):
                            st.caption("CVEs: " + ", ".join(h["cves"]))
                        if h.get("open_ports"):
                            st.caption("Ports: " + ", ".join(h["open_ports"]))
                        if h.get("metasploit_modules"):
                            st.markdown("**Metasploit modules:** " + ", ".join(h["metasploit_modules"]))
                        findings = h.get("remediation_findings", [])
                        if findings:
                            st.markdown("**Remediation findings:**")
                            for f in findings:
                                sev = str(f.get("severity", "")).upper()
                                st.markdown(f"- [{sev}] {f.get('description', f.get('id', ''))}")
        else:
            st.info("No host metrics available.")

    with col_w:
        st.markdown("#### Web Target Risk Summary")
        if web_metrics:
            web_rows = []
            for w in web_metrics:
                web_rows.append({
                    "Target": w.get("target", ""),
                    "Risk": risk_badge(w.get("risk_level", "unknown")),
                    "Risk Score": w.get("risk_score", 0),
                    "Unique Findings": w.get("total_unique_findings", 0),
                    "Instances": w.get("total_instances", 0),
                    "High Findings": w.get("high_findings", 0),
                    "Scan Mode": w.get("scan_mode", ""),
                })
            st.dataframe(web_rows, use_container_width=True, hide_index=True)
        else:
            st.info("No web metrics available.")

    st.divider()

    # ── Remediation roadmap ───────────────────────────────────────────────────
    roadmap = narrative.get("remediation_roadmap", [])
    if roadmap:
        st.markdown("#### Remediation Roadmap")
        phase_cols = st.columns(len(roadmap))
        for col, phase in zip(phase_cols, roadmap):
            with col:
                with st.container(border=True):
                    st.markdown(f"**{phase.get('phase', '')}**")
                    for action in phase.get("actions", []):
                        st.markdown(f"- {action}")

    st.divider()

    # ── Footer ────────────────────────────────────────────────────────────────
    footer_parts = []
    if audit_data.get("last_check"):
        footer_parts.append(f"Generated: {audit_data['last_check'][:19]}")
    if audit_data.get("module_mode"):
        footer_parts.append(f"Mode: `{audit_data['module_mode']}`")
    if audit_data.get("narrative_source"):
        footer_parts.append(f"AI: `{audit_data['narrative_source']}`")
    stats = audit_data.get("stats", {})
    if stats.get("time_taken_sec") is not None:
        footer_parts.append(f"Time: {stats['time_taken_sec']}s")
    if footer_parts:
        st.caption("  ·  ".join(footer_parts))

    with st.expander("Raw audit DB"):
        st.json(audit_data, expanded=False)


def main() -> None:
    st.set_page_config(page_title="SIAAS Web", layout="wide")
    st.title("🔒 SIAAS - Security Audit System (Web)")
    st.caption(f"Last refresh: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    if st.button("Refresh data"):
        st.cache_data.clear()

    port_data, web_data, metasploit_data, remediation_data, audit_data = load_data()
    remediation_rows = extract_remediation_findings(remediation_data)
    metasploit_rows = extract_metasploit_services(metasploit_data)

    tabs = st.tabs(["Audit Report", "Dashboard", "Port Scanner", "Web Scanner", "Metasploit", "Remediation"])

    with tabs[0]:
        render_audit_tab(audit_data)

    with tabs[1]:
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

    with tabs[2]:
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
            host_options = {
                f"{r['Host']} | {r['Open Ports']} open ports | {r['Vulnerabilities']} vulnerabilities": r["Host"]
                for r in rows
            }
            selected_label = st.selectbox("Select a host to list every vulnerability", list(host_options), key="port_details")
            selected_host = host_options[selected_label]
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

    with tabs[3]:
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
            target_options = {
                f"{row['Target']} | {row['Vulnerabilities']} vulnerabilities | {row['URL']}": row["Target"]
                for row in rows
            }
            selected_label = st.selectbox("Select a web target to list every vulnerability", list(target_options), key="web_details")
            selected_key = target_options[selected_label]
            selected = web_data[selected_key]
            detail_tabs = st.tabs(["Vulnerabilities", "System Info", "Raw JSON"])
            with detail_tabs[0]:
                vulnerabilities = extract_web_vulnerabilities(selected)
                render_vulnerability_explorer(f"Web vulnerabilities for {selected_key}", vulnerabilities)
            with detail_tabs[1]:
                st.json(selected.get("system_info", {}), expanded=True)
            with detail_tabs[2]:
                st.json(selected, expanded=False)

    with tabs[4]:
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
            selected_row = filtered[labels.index(selected_label)]
            raw_service = (
                metasploit_data.get("targets", {})
                .get(selected_row["Target"], {})
                .get("services", {})
                .get(selected_row["Port"], {})
            )
            render_metasploit_service_detail(selected_row, raw_service)
        with st.expander("Raw Metasploit assistant DB"):
            st.json(metasploit_data, expanded=False)

    with tabs[5]:
        st.subheader("Remediation Advisor")
        rem_stats = remediation_data.get("stats", {}) if isinstance(remediation_data, dict) else {}
        module_mode = remediation_data.get("module_mode", "") if isinstance(remediation_data, dict) else ""
        ai_stats = rem_stats.get("ai", {}) if isinstance(rem_stats, dict) else {}

        summary = remediation_data.get("executive_summary", {}) if isinstance(remediation_data, dict) else {}
        if summary:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Open Findings", summary.get("total_open_findings", len(remediation_rows)))
            with col2:
                counts = summary.get("severity_counts", {})
                st.metric("Critical/High", int(counts.get("critical", 0) or 0) + int(counts.get("high", 0) or 0))
            with col3:
                st.metric("Affected Targets", len(summary.get("most_affected_targets", [])))
            with col4:
                ai_succeeded = int(ai_stats.get("succeeded", 0) or 0)
                ai_failed = int(ai_stats.get("failed", 0) or 0)
                ai_cached = int(ai_stats.get("cached", 0) or 0)
                st.metric("AI Remediations", ai_succeeded, delta=f"{ai_cached} cached" if ai_cached else None)
            st.info(summary.get("recommended_next_step", "Review the prioritized remediation plan below."))

        if module_mode or ai_stats:
            info_parts = []
            if module_mode:
                label = "AI-assisted" if "ai" in module_mode else "Local rules"
                info_parts.append(f"**Mode:** {label} (`{module_mode}`)")
            if ai_stats.get("provider") or ai_stats.get("model"):
                model_str = " / ".join(str(v) for v in (ai_stats.get("provider"), ai_stats.get("model")) if v)
                info_parts.append(f"**AI Model:** {model_str}")
            if ai_failed:
                info_parts.append(f"**AI Failures:** {ai_failed}")
            st.caption("  ·  ".join(info_parts))

        remediation_by_id = {
            f.get("id", ""): f
            for f in (remediation_data.get("remediation_plan", []) if isinstance(remediation_data, dict) else [])
            if isinstance(f, dict)
        }

        col1, col2, col3 = st.columns(3)
        with col1:
            source_filter = st.multiselect("Source", sorted({row.get("Source", "unknown") for row in remediation_rows}), default=[])
        with col2:
            severity_filter = st.multiselect("Severity", ["critical", "high", "medium", "low", "info", "unknown"], default=[], key="remediation_severity")
        with col3:
            status_filter = st.multiselect("Status", sorted({row.get("Status", "open") for row in remediation_rows if row.get("Status")}), default=[])
        text_filter = st.text_input("Filter remediation plan", key="remediation_filter")

        filtered = filter_by_severity(remediation_rows, severity_filter)
        if source_filter:
            filtered = [row for row in filtered if row.get("Source") in source_filter]
        if status_filter:
            filtered = [row for row in filtered if row.get("Status") in status_filter]
        if text_filter:
            filtered = [row for row in filtered if text_filter.lower() in " ".join(str(v).lower() for v in row.values())]

        st.dataframe(filtered, use_container_width=True, hide_index=True)
        if filtered:
            labels = [f"{row['Severity'].upper()} | {row['Target']} | {row['Title'][:90]}" for row in filtered]
            selected_label = st.selectbox("Remediation details", labels, key="remediation_details")
            selected = filtered[labels.index(selected_label)]
            raw_finding = remediation_by_id.get(selected.get("ID", ""), selected)
            render_remediation_detail(selected, raw_finding)
        with st.expander("Raw remediation DB"):
            st.json(remediation_data, expanded=False)


if __name__ == "__main__":
    main()
