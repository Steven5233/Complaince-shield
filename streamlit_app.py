import streamlit as st
import pandas as pd
import time
import plotly.express as px
import subprocess
import re
import json
import requests
import os
from ipaddress import ip_address, AddressValueError
from io import BytesIO
from fpdf import FPDF
import datetime
import random

# ───────────────────────────────────────────────
# MODE CONFIGURATION (AUTO SWITCH)
# ───────────────────────────────────────────────
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

# ───────────────────────────────────────────────
# Page configuration
# ───────────────────────────────────────────────
st.set_page_config(
    page_title="ComplianceShield – Ethical Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
)

# ───────────────────────────────────────────────
# Helper functions
# ───────────────────────────────────────────────
def is_valid_target(target: str) -> bool:
    target = target.strip().lower()
    if target.startswith("http"):
        target = target.split("//")[-1].split("/")[0]
    try:
        ip_address(target)
        return True
    except AddressValueError:
        return bool(re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', target))

def do_http_check(target: str) -> dict:
    if DEMO_MODE:
        return {"misconfigs": [], "http_status": 200, "title": "Demo Site"}

    if not target.startswith("http"):
        url = f"http://{target}"
    else:
        url = target

    misconfigs = []
    try:
        r = requests.get(url, timeout=10, verify=False)
        headers = r.headers

        if "Server" in headers:
            misconfigs.append(f"Server header exposed: {headers['Server']}")
        if "X-Powered-By" in headers:
            misconfigs.append("X-Powered-By header exposed")
        if "Strict-Transport-Security" not in headers:
            misconfigs.append("Missing HSTS header")

        return {
            "misconfigs": misconfigs,
            "http_status": r.status_code,
            "title": "N/A"
        }
    except:
        return {"misconfigs": ["HTTP check failed"], "http_status": 0, "title": "N/A"}

def calculate_risk_score(vulns, misconfigs):
    score = 0
    for v in vulns:
        sev = v["severity"].lower()
        if sev in ["critical", "high"]:
            score += 9
        elif sev == "medium":
            score += 5
        else:
            score += 2
    score += len(misconfigs) * 1.5
    return round(min(score / 2, 10), 1)

def generate_business_impact(score, vulns):
    if score >= 8:
        return "CRITICAL: High risk of full compromise and major data breach."
    elif score >= 5:
        return "HIGH: Risk of unauthorized access and data exposure."
    elif score >= 3:
        return "MEDIUM: Moderate exposure."
    return "LOW: Minor issues."

def generate_recommendations(vulns, misconfigs):
    recs = []
    for v in vulns:
        recs.append(f"Fix {v['id']} immediately")
    for m in misconfigs:
        recs.append(f"Fix: {m}")
    return list(set(recs))

# ───────────────────────────────────────────────
# DEMO DATA GENERATOR
# ───────────────────────────────────────────────
def generate_demo_data(target, scan_type):
    ports = [
        "80/tcp – http Apache",
        "443/tcp – https nginx",
        "22/tcp – ssh OpenSSH"
    ]

    vulns = [
        {"id": "CVE-2024-0001", "severity": "High", "description": "Demo vulnerability"},
        {"id": "CVE-2023-2222", "severity": "Medium", "description": "Information disclosure"}
    ]

    misconfigs = [
        "Missing HSTS header",
        "Server header exposed"
    ]

    result = {
        "target": target,
        "scan_id": f"DEMO-{random.randint(1000,9999)}",
        "scan_type": scan_type,
        "timestamp": str(datetime.datetime.now()),
        "duration": round(random.uniform(1, 3), 1),
        "vulnerabilities": vulns,
        "misconfigs": misconfigs,
        "ports": ports,
        "compliance": [],
        "risk_score": 0,
        "overall_risk": "",
        "business_impact": "",
        "recommendations": []
    }

    result["risk_score"] = calculate_risk_score(vulns, misconfigs)
    result["overall_risk"] = "High" if result["risk_score"] > 5 else "Medium"
    result["business_impact"] = generate_business_impact(result["risk_score"], vulns)
    result["recommendations"] = generate_recommendations(vulns, misconfigs)

    return result

# ───────────────────────────────────────────────
# REAL + DEMO SCAN ENGINE
# ───────────────────────────────────────────────
def run_scan(target, scan_type):

    if not is_valid_target(target):
        st.error("Invalid target")
        return None

    # DEMO MODE
    if DEMO_MODE:
        st.info("Running in DEMO MODE")
        return generate_demo_data(target, scan_type)

    # REAL MODE
    result = {
        "target": target,
        "scan_id": f"REAL-{int(time.time())}",
        "scan_type": scan_type,
        "timestamp": str(datetime.datetime.now()),
        "duration": 0,
        "vulnerabilities": [],
        "misconfigs": [],
        "ports": [],
        "compliance": [],
        "risk_score": 0,
        "overall_risk": "",
        "business_impact": "",
        "recommendations": []
    }

    start = time.time()

    try:
        output = subprocess.check_output(["nmap", "-sV", target]).decode()
        ports = re.findall(r'(\d+)/tcp\s+open\s+([^\s]+)', output)
        result["ports"] = [f"{p[0]}/tcp – {p[1]}" for p in ports]
    except:
        result["misconfigs"].append("Nmap failed")

    http = do_http_check(target)
    result["misconfigs"].extend(http["misconfigs"])

    result["risk_score"] = calculate_risk_score(result["vulnerabilities"], result["misconfigs"])
    result["overall_risk"] = "High" if result["risk_score"] > 5 else "Medium"
    result["business_impact"] = generate_business_impact(result["risk_score"], result["vulnerabilities"])
    result["recommendations"] = generate_recommendations(result["vulnerabilities"], result["misconfigs"])

    result["duration"] = round(time.time() - start, 2)

    return result

# ───────────────────────────────────────────────
# UI
# ───────────────────────────────────────────────
st.title("🛡️ ComplianceShield")

st.sidebar.write(f"Mode: {'DEMO' if DEMO_MODE else 'REAL'}")

target = st.text_input("Enter target")
scan_type = st.selectbox("Scan Type", ["Quick", "Full"])

if st.button("Start Scan"):
    res = run_scan(target, scan_type)

    if res:
        st.success("Scan Completed")

        st.metric("Risk Score", res["risk_score"])
        st.write("Ports:", res["ports"])
        st.write("Misconfigs:", res["misconfigs"])
        st.write("Recommendations:", res["recommendations"])
