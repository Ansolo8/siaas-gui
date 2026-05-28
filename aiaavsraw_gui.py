#!/usr/bin/env python3
"""SIAAS Web UI built with Streamlit."""

from __future__ import annotations

import os
from datetime import datetime

import streamlit as st

import siaas_aux

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAR_DIR = os.path.join(BASE_DIR, "siaas-agent", "var")
PORTSCANNER_DB = os.path.join(VAR_DIR, "portscanner.db")
WEBSCANNER_DB = os.path.join(VAR_DIR, "webscanner.db")


@st.cache_data(ttl=30)
def load_data() -> tuple[dict, dict]:
    port_data = siaas_aux.read_from_local_file(PORTSCANNER_DB) or {}
    web_data = siaas_aux.read_from_local_file(WEBSCANNER_DB) or {}
    return port_data, web_data


def extract_port_vulnerabilities(host_info: dict) -> list[dict]:
    vulnerabilities = []
    for port, port_info in host_info.get("scanned_ports", {}).items():
        scripts = port_info.get("scripts", {})
        for script_name, script_output in scripts.items():
            if isinstance(script_output, dict):
                for vuln_id, vuln_info in script_output.items():
                    if isinstance(vuln_info, dict):
                        vulnerabilities.append(
                            {
                                "port": port,
                                "script": script_name,
                                "id": vuln_id,
                                "severity": vuln_info.get("severity", "N/A"),
                                "description": vuln_info.get("description", "N/A"),
                            }
                        )
    return vulnerabilities


def extract_web_vulnerabilities(web_info: dict) -> list[dict]:
    vulnerabilities = []
    for source, source_info in web_info.get("scanned_sources", {}).items():
        if not isinstance(source_info, dict):
            continue

        for vuln_type, vuln_entries in source_info.items():
            if isinstance(vuln_entries, list):
                for entry in vuln_entries:
                    if isinstance(entry, dict):
                        vulnerabilities.append(
                            {
                                "source": source,
                                "type": vuln_type,
                                "severity": entry.get("severity", "N/A"),
                                "description": entry.get("description", "N/A"),
                            }
                        )
    return vulnerabilities


def build_dashboard(port_data: dict, web_data: dict):
    consolidated = {}

    for host, info in port_data.items():
        stats = info.get("stats", {})
        last_check = info.get("last_check", "")
        consolidated.setdefault(host, {"vulns": 0, "exploits": 0, "last_scan": "", "scanners": set()})
        consolidated[host]["vulns"] += stats.get("total_num_vulnerabilities", 0)
        consolidated[host]["exploits"] += stats.get("total_num_exploits", 0)
        consolidated[host]["scanners"].add("Port")
        if last_check > consolidated[host]["last_scan"]:
            consolidated[host]["last_scan"] = last_check

    for target_key, info in web_data.items():
        host = target_key.split(":", 1)[0]
        stats = info.get("stats", {})
        last_check = info.get("last_check", "")
        consolidated.setdefault(host, {"vulns": 0, "exploits": 0, "last_scan": "", "scanners": set()})
        consolidated[host]["vulns"] += stats.get("total_num_vulnerabilities", 0)
        consolidated[host]["exploits"] += stats.get("total_num_exploits", 0)
        consolidated[host]["scanners"].add("Web")
        if last_check > consolidated[host]["last_scan"]:
            consolidated[host]["last_scan"] = last_check

    rows = []
    for host, data in consolidated.items():
        rows.append(
            {
                "Host": host,
                "Vulnerabilities": data["vulns"],
                "Exploits": data["exploits"],
                "Last Scan": data["last_scan"][:19] if data["last_scan"] else "N/A",
                "Scanners": ", ".join(sorted(data["scanners"])),
            }
        )

    rows.sort(key=lambda x: x["Vulnerabilities"], reverse=True)
    st.dataframe(rows[:10], use_container_width=True)


def main() -> None:
    st.set_page_config(page_title="SIAAS Web", layout="wide")
    st.title("🔒 SIAAS - Security Audit System (Web)")
    st.caption(f"Last refresh: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    if st.button("Refresh data"):
        st.cache_data.clear()

    port_data, web_data = load_data()

    tabs = st.tabs(["Dashboard", "Port Scanner", "Web Scanner"])

    with tabs[0]:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Port Scanner")
            st.metric("Total Hosts", len(port_data))
            st.metric("Open Ports", sum(len(i.get("scanned_ports", {})) for i in port_data.values()))
            st.metric(
                "Vulnerabilities",
                sum(i.get("stats", {}).get("total_num_vulnerabilities", 0) for i in port_data.values()),
            )

        with col2:
            st.subheader("Web Scanner")
            st.metric("Web Hosts", len(web_data))
            st.metric("Scanned Targets", len(web_data))
            st.metric(
                "Vulnerabilities",
                sum(i.get("stats", {}).get("total_num_vulnerabilities", 0) for i in web_data.values()),
            )

        st.subheader("Top Vulnerable Hosts (Consolidated)")
        build_dashboard(port_data, web_data)

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
                    "Vulnerabilities": info.get("stats", {}).get("total_num_vulnerabilities", 0),
                    "Exploits": info.get("stats", {}).get("total_num_exploits", 0),
                    "Last Check": (info.get("last_check") or "")[:19] or "N/A",
                }
            )

        st.dataframe(rows, use_container_width=True)

        if rows:
            selected_host = st.selectbox("Host details", [r["Host"] for r in rows], key="port_details")
            selected = port_data[selected_host]
            st.json(selected.get("system_info", {}), expanded=False)
            vulnerabilities = extract_port_vulnerabilities(selected)
            st.write(f"Vulnerabilities found: {len(vulnerabilities)}")
            if vulnerabilities:
                st.dataframe(vulnerabilities[:50], use_container_width=True)

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
                    "Vulnerabilities": info.get("stats", {}).get("total_num_vulnerabilities", 0),
                    "Exploits": info.get("stats", {}).get("total_num_exploits", 0),
                    "Last Check": (info.get("last_check") or "")[:19] or "N/A",
                }
            )

        st.dataframe(rows, use_container_width=True)

        if filtered_keys:
            selected_key = st.selectbox("Target details", filtered_keys, key="web_details")
            selected = web_data[selected_key]
            st.json(selected.get("system_info", {}), expanded=False)
            vulnerabilities = extract_web_vulnerabilities(selected)
            st.write(f"Vulnerabilities found: {len(vulnerabilities)}")
            if vulnerabilities:
                st.dataframe(vulnerabilities[:100], use_container_width=True)


if __name__ == "__main__":
    main()
