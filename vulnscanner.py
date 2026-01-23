#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI-Vuln-Scanner
# Refactored to be AI-first: Nmap is only a data source, AI does all reasoning.
# No XML handling, no scan_command, no NmapScanTechniques, no low-level hacks.

import os
import sys
import argparse
import logging
import time
import json
import requests
import ipaddress
import re
from html import escape

try:
    import nmap3
    from jinja2 import Template
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Missing dependency: {e.name}. Please install it with pip.")
    sys.exit(1)

# ============================================================
# Environment
# ============================================================
load_dotenv()

# Use only the high-level API
nm = nmap3.Nmap()

# ============================================================
# Logging
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

# ============================================================
# AI Provider Configs
# ============================================================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

MODEL_ENGINE = "gpt-4o"
TEMPERATURE = 0.4
TOKEN_LIMIT = 4096

HTTP_SESSION = requests.Session()

# ============================================================
# Utilities
# ============================================================
def mask_api_key(key):
    if not key or len(key) < 8:
        return "[NOT SET]"
    return key[:4] + "..." + key[-4:]


def validate_api_keys():
    missing = []
    if not OPENAI_API_KEY:
        missing.append("OPENAI_API_KEY")
    if not GEMINI_API_KEY:
        missing.append("GEMINI_API_KEY")

    if missing:
        logging.warning(
            f"Missing API keys: {', '.join(missing)}. Some functionality may be unavailable."
        )

    logging.debug(f"OpenAI API Key : {mask_api_key(OPENAI_API_KEY)}")
    logging.debug(f"Gemini API Key : {mask_api_key(GEMINI_API_KEY)}")


def print_ethical_warning():
    print("\n" + "=" * 80)
    print("WARNING: Use this script ONLY on systems you own or have explicit permission to test.")
    print("Unauthorized scanning is illegal and unethical.")
    print("=" * 80 + "\n")


def sanitize_target(target):
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    target = target.strip("/")
    target = re.sub(r":\d+$", "", target)
    return target


def is_safe_target(target):
    if re.search(r"[;&|`$<>]", target):
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    if re.match(r"^[a-zA-Z0-9.-]+$", target):
        return True
    return False


# ============================================================
# Nmap handling (DUMB + STABLE)
# ============================================================
def run_nmap_scan(target, arguments):
    """
    AI-first design:
    - No XML
    - No scan_command
    - No NmapScanTechniques
    - Only structured Python dictionaries
    """
    try:
        logging.debug("=" * 60)
        logging.debug("Executing Nmap version detection scan")
        logging.debug(f"Target   : {target}")
        logging.debug(f"Arguments: {arguments}")
        logging.debug("=" * 60)

        # This returns a Python dict directly
        result = nm.nmap_version_detection(target=target, args=arguments)

        if not isinstance(result, dict) or not result:
            logging.error("Nmap returned invalid or empty data.")
            return {}

        # Cap debug output to avoid terminal / log flooding
        debug_dump = json.dumps(result, indent=2)
        logging.debug("Raw Nmap structured output (truncated):")
        logging.debug(debug_dump[:8000])

        return result

    except Exception:
        logging.exception("Nmap scan crashed:")
        return {}


def extract_open_ports(analyze):
    open_ports_info = []
    for host, host_data in analyze.items():
        for port in host_data.get("ports", []):
            if port.get("state") == "open":
                proto = port.get("protocol", "tcp")
                pid = port.get("portid")
                svc = port.get("service", {}).get("name", "unknown")
                ver = port.get("service", {}).get("version", "")
                extra = f" ({ver})" if ver else ""
                open_ports_info.append(f"{proto.upper()} {pid}/{svc}{extra}")
    return ", ".join(open_ports_info)


# ============================================================
# AI Providers
# ============================================================
def ask_openai(prompt):
    import openai
    openai.api_key = OPENAI_API_KEY

    try:
        response = openai.ChatCompletion.create(
            model=MODEL_ENGINE,
            messages=[
                {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=TOKEN_LIMIT,
            temperature=TEMPERATURE,
        )
        return response.choices[0].message.content
    except Exception as e:
        logging.error(f"OpenAI API error: {e}")
        return "<b>OpenAI API error. No vulnerability analysis available.</b>"


def ask_gemini(prompt):
    if not GEMINI_API_KEY:
        logging.error("Gemini API key not set.")
        return "<b>No Gemini API key configured.</b>"

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": GEMINI_API_KEY}

    data = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ]
    }

    try:
        response = HTTP_SESSION.post(
            url, headers=headers, params=params, json=data, timeout=60
        )
        response.raise_for_status()
        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        logging.error(f"Gemini API error: {e}")
        return "<b>Gemini API error. No vulnerability analysis available.</b>"


# ============================================================
# AI Router
# ============================================================
def ask_ai_vuln_analysis(analyze, open_ports, provider=None):
    # Prevent prompt injection
    safe_analyze = json.dumps(analyze, indent=2).replace("```", "'''")

    prompt = f"""
You are a senior penetration tester.

Analyze the following Nmap scan results:

{safe_analyze}

Detected open ports summary:
{open_ports}

For each significant finding:
- Explain the vulnerability
- Map to OWASP Top 10, CWE, and CAPEC
- Assign severity (Critical, High, Medium, Low)
- Explain business impact
- Provide concrete remediation steps
- Mention if exploitation is known in the wild

Return a structured HTML report with headings, bullet points and clear sections.
No JavaScript. No inline scripts.
"""

    providers = []
    if OPENAI_API_KEY:
        providers.append("OpenAI")
    if GEMINI_API_KEY:
        providers.append("Gemini")

    if not provider:
        if not providers:
            return "<b>No AI provider configured.</b>"
        provider = providers[0] if len(providers) == 1 else providers[
            int(input("Select AI provider (1 = OpenAI, 2 = Gemini): ")) - 1
        ]

    if provider == "OpenAI":
        return ask_openai(prompt)
    elif provider == "Gemini":
        return ask_gemini(prompt)
    else:
        return "<b>No valid AI provider selected.</b>"


# ============================================================
# Export
# ============================================================
def export_to_html(html_snippet, filename):
    # Escape everything, then trust nothing except very basic formatting
    sanitized = escape(html_snippet)

    template = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AI Vulnerability Report</title>
<style>
body { font-family: Arial; margin: 40px; }
h1, h2, h3 { color: #222; }
</style>
</head>
<body>
<h1>AI Vulnerability Report</h1>
<pre>{{ content }}</pre>
</body>
</html>
""")
    html_content = template.render(content=sanitized)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)


# ============================================================
# Main
# ============================================================
def main():
    print_ethical_warning()
    validate_api_keys()

    parser = argparse.ArgumentParser(
        description="AI-Vuln-Scanner (AI-first vulnerability analysis tool)"
    )
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-dl", "--debug-log", nargs="?", const="vulnscanner-debug.log")

    args = parser.parse_args()

    if args.debug or args.debug_log:
        logging.getLogger().setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
        root = logging.getLogger()

        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        root.addHandler(ch)

        if args.debug_log:
            fh = logging.FileHandler(args.debug_log)
            fh.setFormatter(formatter)
            root.addHandler(fh)
            logging.debug(f"Debug log file enabled: {args.debug_log}")

    target = sanitize_target(args.target)
    if not is_safe_target(target):
        logging.error("Invalid target.")
        sys.exit(1)

    nmap_args = "-Pn -T4 -F --host-timeout 5m -vvv"
    analyze = run_nmap_scan(target, nmap_args)

    if not analyze:
        logging.error("No scan results.")
        return

    open_ports = extract_open_ports(analyze)
    logging.info(f"Open ports summary: {open_ports}")

    vuln_html = ask_ai_vuln_analysis(analyze, open_ports)
    if not vuln_html:
        logging.error("AI returned empty response.")
        return

    outfile = f"{target}-{int(time.time())}.html"
    export_to_html(vuln_html, outfile)
    print(f"Scan complete. Report written to {outfile}")


if __name__ == "__main__":
    main()
