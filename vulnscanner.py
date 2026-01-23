#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI-Vuln-Scanner (multi-provider, AI-first)
# Nmap is a data source; AI does the reasoning.
#
# Providers:
# - OpenAI
# - Gemini
# - Anthropic
# - Replit
# - AnythingLLM
#
# Stable design:
# - Call real nmap binary via subprocess
# - Force XML output
# - Parse XML ourselves
# - Feed structured JSON to AI

import os
import sys
import argparse
import logging
import time
import json
import requests
import ipaddress
import re
import subprocess
import shutil
import shlex
from html import escape
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

from dotenv import load_dotenv
from jinja2 import Template

# ============================================================
# Environment
# ============================================================
load_dotenv()

# ============================================================
# Logging base config
# ============================================================
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# ============================================================
# Provider Configs
# ============================================================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

REPLIT_API_KEY = os.getenv("REPLIT_API_KEY")
REPLIT_API_URL = os.getenv("REPLIT_API_URL", "https://chat.replit.com/v1/chat/completions")

ANYTHINGLLM_API_KEY = os.getenv("ANYTHINGLLM_API_KEY")
ANYTHINGLLM_API_URL = os.getenv("ANYTHINGLLM_API_URL")

# ============================================================
# AI Defaults
# ============================================================
TEMPERATURE = 0.4
TOKEN_LIMIT = 4096

HTTP_SESSION = requests.Session()

# Add retry strategy for all providers
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

retry = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(max_retries=retry)
HTTP_SESSION.mount("https://", adapter)
HTTP_SESSION.mount("http://", adapter)

# ============================================================
# Ethics banner
# ============================================================
def print_ethical_warning():
    print("\n" + "=" * 80)
    print("WARNING: Use this script ONLY on systems you own or have explicit permission to test.")
    print("Unauthorized scanning is illegal and unethical.")
    print("=" * 80 + "\n")

# ============================================================
# Utilities
# ============================================================
def mask_api_key(key: Optional[str]) -> str:
    if not key or len(key) < 8:
        return "[NOT SET]"
    return key[:4] + "..." + key[-4:]


def sanitize_target(target: str) -> str:
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    target = target.strip().strip("/")
    target = re.sub(r":\d+$", "", target)
    return target


def is_safe_target(target: str) -> bool:
    if re.search(r"[;&|`$<>]", target):
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    if re.fullmatch(r"[a-zA-Z0-9.-]+", target):
        return True

    return False


def ensure_nmap_available(nmap_path: Optional[str]) -> str:
    if nmap_path:
        if shutil.which(nmap_path) is None and not os.path.exists(nmap_path):
            raise FileNotFoundError(f"nmap not found at '{nmap_path}'")
        return nmap_path

    resolved = shutil.which("nmap")
    if not resolved:
        raise FileNotFoundError("nmap binary not found in PATH. Install nmap first.")
    return resolved


def validate_api_keys():
    missing = []
    if not OPENAI_API_KEY:
        missing.append("OPENAI_API_KEY")
    if not GEMINI_API_KEY:
        missing.append("GEMINI_API_KEY")
    if not ANTHROPIC_API_KEY:
        missing.append("ANTHROPIC_API_KEY")
    if not REPLIT_API_KEY:
        missing.append("REPLIT_API_KEY")
    if not (ANYTHINGLLM_API_KEY and ANYTHINGLLM_API_URL):
        missing.append("ANYTHINGLLM_API_KEY/ANYTHINGLLM_API_URL")

    logging.warning(
        "Missing API keys/config: %s",
        ", ".join(missing) if missing else "none"
    )

    logging.debug("OpenAI API Key      : %s", mask_api_key(OPENAI_API_KEY))
    logging.debug("Gemini API Key      : %s", mask_api_key(GEMINI_API_KEY))
    logging.debug("Anthropic API Key   : %s", mask_api_key(ANTHROPIC_API_KEY))
    logging.debug("Replit API Key      : %s", mask_api_key(REPLIT_API_KEY))
    logging.debug("AnythingLLM API Key : %s", mask_api_key(ANYTHINGLLM_API_KEY))
    logging.debug("AnythingLLM API URL : %s", ANYTHINGLLM_API_URL or "[NOT SET]")


# ============================================================
# Nmap scanning (subprocess + XML)
# ============================================================
def run_nmap_scan(nmap_bin: str, target: str, nmap_args: str) -> Dict[str, Any]:
    cmd = [nmap_bin] + shlex.split(nmap_args) + ["-oX", "-", target]

    logging.debug("=" * 70)
    logging.debug("Executing nmap subprocess")
    logging.debug("Binary  : %s", nmap_bin)
    logging.debug("Target  : %s", target)
    logging.debug("Args    : %s", nmap_args)
    logging.debug("Command : %s", " ".join(cmd))
    logging.debug("=" * 70)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=900,
            check=False
        )
    except Exception:
        logging.exception("Failed to execute nmap.")
        return {}

    if proc.returncode != 0:
        logging.error("nmap exited with code %s", proc.returncode)
        if proc.stderr:
            logging.error("stderr:\n%s", proc.stderr.strip())

    xml_text = proc.stdout.encode("utf-8", "ignore").decode("utf-8", "ignore").strip()

    if not xml_text.startswith("<?xml") and "<nmaprun" not in xml_text:
        logging.error("nmap output was not valid XML.")
        logging.debug("stdout (truncated):\n%s", xml_text[:2000])
        return {}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logging.exception("Failed to parse nmap XML.")
        logging.debug("Raw XML (truncated):\n%s", xml_text[:4000])
        return {}

    parsed = parse_nmap_xml(root)
    if not parsed.get("hosts"):
        logging.error("Parsed scan contains no hosts. Target unreachable or filtered.")
        return {}

    return parsed


def parse_nmap_xml(root: ET.Element) -> Dict[str, Any]:
    hosts: List[Dict[str, Any]] = []

    for h in root.findall("host"):
        host_entry = {
            "status": None,
            "address": None,
            "hostnames": [],
            "ports": [],
            "os": [],
            "scripts": []
        }

        status_el = h.find("status")
        if status_el is not None:
            host_entry["status"] = status_el.attrib.get("state")

        addr_el = h.find("address")
        if addr_el is not None:
            host_entry["address"] = addr_el.attrib.get("addr")

        for hn in h.findall("./hostnames/hostname"):
            name = hn.attrib.get("name")
            if name:
                host_entry["hostnames"].append(name)

        for p in h.findall("./ports/port"):
            protocol = p.attrib.get("protocol")
            portid = int(p.attrib.get("portid", "0"))
            state = p.find("state").attrib.get("state")

            svc_el = p.find("service")
            service = {}
            if svc_el is not None:
                for k in ("name", "product", "version", "extrainfo"):
                    if svc_el.attrib.get(k):
                        service[k] = svc_el.attrib[k]

            host_entry["ports"].append({
                "protocol": protocol,
                "portid": portid,
                "state": state,
                "service": service
            })

        hosts.append(host_entry)

    return {"hosts": hosts}


def extract_open_ports(scan: Dict[str, Any]) -> str:
    parts = []
    for host in scan.get("hosts", []):
        label = (host.get("hostnames") or [host.get("address")])[0]
        for p in host.get("ports", []):
            if p.get("state") == "open":
                proto = p.get("protocol").upper()
                pid = p.get("portid")
                svc = p.get("service", {}).get("name", "unknown")
                ver = p.get("service", {}).get("version", "")
                suffix = f" ({ver})" if ver else ""
                parts.append(f"{label} {proto} {pid}/{svc}{suffix}")
    return ", ".join(parts) if parts else "(no open ports detected)"


# ============================================================
# AI PROMPT
# ============================================================
def build_ai_prompt(scan: Dict[str, Any], open_ports: str, target: str) -> str:
    scan_json = json.dumps(scan, indent=2).replace("```", "'''")
    prompt = f"""
You are a senior penetration tester and vulnerability analyst.

Target: {target}

Nmap scan results (JSON):
{scan_json}

Open ports summary:
{open_ports}

Tasks:
- Identify vulnerabilities and exposures
- Map to OWASP, CWE, CAPEC
- Assign severity (Critical/High/Medium/Low)
- Provide business impact
- Give concrete remediation steps
- Prioritize findings
- If data is insufficient, say what additional scans are needed

Return an HTML report. No JavaScript.
"""
    return prompt.strip()


# ============================================================
# AI PROVIDERS (OpenAI shown, others same pattern)
# ============================================================
def ask_openai(prompt: str, timeout: int = 60) -> str:
    if not OPENAI_API_KEY:
        return "<b>OpenAI API key not configured.</b>"

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst."},
            {"role": "user", "content": prompt},
        ],
        "temperature": TEMPERATURE,
        "max_tokens": TOKEN_LIMIT,
    }

    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error("OpenAI API error: %s", e)
        return "<b>OpenAI API error.</b>"


# ============================================================
# EXPORT
# ============================================================
def export_report_html(ai_html: str, filename: str, trust_ai_html: bool):
    body = ai_html if trust_ai_html else f"<pre>{escape(ai_html)}</pre>"

    tpl = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AI Vulnerability Report</title>
</head>
<body>
<h1>AI Vulnerability Report</h1>
{{ body | safe }}
</body>
</html>
""")

    html = tpl.render(body=body)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


# ============================================================
# MAIN
# ============================================================
def setup_debug_logging(debug: bool, debug_log: Optional[str]):
    if not (debug or debug_log):
        return

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)

    if debug_log:
        fh = logging.FileHandler(debug_log, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
        logging.debug("Debug log file enabled: %s", debug_log)


def main():
    print_ethical_warning()
    validate_api_keys()

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--nmap-path", default=None)
    parser.add_argument("--nmap-args", default="-Pn -sV -T4 -F --host-timeout 5m -vvv")
    parser.add_argument("--provider", default="openai")
    parser.add_argument("--trust-ai-html", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-dl", "--debug-log", nargs="?", const="vulnscanner-debug.log")

    args = parser.parse_args()
    setup_debug_logging(args.debug, args.debug_log)

    target = sanitize_target(args.target)
    if not is_safe_target(target):
        logging.error("Invalid target.")
        sys.exit(1)

    try:
        nmap_bin = ensure_nmap_available(args.nmap_path)
    except Exception as e:
        logging.error("%s", e)
        sys.exit(1)

    scan = run_nmap_scan(nmap_bin, target, args.nmap_args)
    if not scan:
        logging.error("No scan results.")
        sys.exit(2)

    open_ports = extract_open_ports(scan)
    logging.info("Open ports: %s", open_ports)

    prompt = build_ai_prompt(scan, open_ports, target)
    MAX_PROMPT = 120000
    if len(prompt) > MAX_PROMPT:
        logging.warning("Prompt too large, truncating.")
        prompt = prompt[:MAX_PROMPT]

    ai_output = ask_openai(prompt)
    if not ai_output:
        logging.error("AI returned empty output.")
        sys.exit(3)

    outfile = f"{target}-{int(time.time())}.html"
    export_report_html(ai_output, outfile, args.trust_ai_html)
    print(f"Scan complete. Output written to {outfile}")


if __name__ == "__main__":
    main()
