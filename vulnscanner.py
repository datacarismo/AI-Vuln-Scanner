#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914 (refactored and hardened)

import os
import sys
import argparse
import logging
import time
import json
import requests
import ipaddress
import re

try:
    import nmap3
    from jinja2 import Template
    from dotenv import load_dotenv
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing dependency: {e.name}. Please install it with pip.")
    sys.exit(1)

# =========================
# Environment
# =========================
load_dotenv()

# IMPORTANT:
# Use ONLY NmapScanTechniques. Do NOT overwrite this later.
nm = nmap3.NmapScanTechniques()

# =========================
# Logging base config
# =========================
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

# =========================
# AI Provider Configs
# =========================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

MODEL_ENGINE = "gpt-4o"
TEMPERATURE = 0.5
TOKEN_LIMIT = 4096

# Shared HTTP session (performance + reliability)
HTTP_SESSION = requests.Session()


# =========================
# Utilities
# =========================
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

    logging.debug(f"OpenAI API Key: {mask_api_key(OPENAI_API_KEY)}")
    logging.debug(f"Gemini API Key: {mask_api_key(GEMINI_API_KEY)}")


def print_ethical_warning():
    print("\n" + "=" * 80)
    print("WARNING: Use this script ONLY on systems you own or have explicit permission to test.")
    print("Unauthorized scanning is illegal and unethical.")
    print("=" * 80 + "\n")


def sanitize_target(target):
    # Remove protocol
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    # Remove trailing slash
    target = target.strip("/")
    # Remove port if present
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


# =========================
# Nmap handling
# =========================
def run_nmap_scan(target, arguments):
    try:
        logging.debug("=" * 60)
        logging.debug("Executing nmap scan (raw scan_command)")
        logging.debug(f"Target   : {target}")
        logging.debug(f"Arguments: {arguments}")
        logging.debug("=" * 60)

        # This returns XML ElementTree
        xml_result = nm.scan_command(target, arguments)

        logging.debug(f"Type of raw result: {type(xml_result)}")

        # Convert XML → Python dict using nmap3 parser
        from nmap3 import NmapParser
        parser = NmapParser()
        result = parser.parse(xml_result)

        logging.debug("Parsed Nmap result (dict):")
        logging.debug(json.dumps(result, indent=2))

        if not isinstance(result, dict):
            logging.error("Parsed Nmap result is not a dictionary.")
            return {}

        if not result:
            logging.error("Parsed Nmap result is empty.")
            return {}

        scanned_host = next(iter(result.keys()))
        logging.debug(f"Using scanned host: {scanned_host}")

        host_data = result[scanned_host]

        if not isinstance(host_data, dict):
            logging.error("Host data is not a dictionary.")
            logging.debug(f"Host data: {host_data}")
            return {}

        logging.debug("Host data successfully parsed.")
        logging.debug(json.dumps(host_data, indent=2))

        return {scanned_host: host_data}

    except Exception:
        logging.exception("Nmap scan crashed with exception:")
        return {}

def extract_open_ports(analyze):
    open_ports_info = []
    for host, host_data in analyze.items():
        ports = host_data.get("ports", [])
        for port_entry in ports:
            if port_entry.get("state") == "open":
                portid = port_entry.get("portid")
                service = port_entry.get("service", {}).get("name", "unknown")
                protocol = port_entry.get("protocol", "tcp")
                open_ports_info.append(f"{protocol.upper()} Port {portid}: {service}")
    return ", ".join(open_ports_info)


def print_scan_results(analyze):
    for host, host_data in analyze.items():
        logging.info(f"Host: {host}")
        if "ports" in host_data:
            logging.info("Ports:")
            for port_entry in host_data["ports"]:
                portid = port_entry.get("portid")
                protocol = port_entry.get("protocol", "tcp")
                state = port_entry.get("state")
                service = port_entry.get("service", {}).get("name", "unknown")
                logging.info(f"  {protocol.upper()} Port {portid}: {service} ({state})")
        print()


# =========================
# AI Providers
# =========================
def ask_openai(prompt):
    import openai
    openai.api_key = OPENAI_API_KEY
    try:
        response = openai.ChatCompletion.create(
            model=MODEL_ENGINE,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
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
            {
                "parts": [
                    {"text": "You are a cybersecurity expert.\n" + prompt}
                ]
            }
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


# =========================
# AI Router
# =========================
def ask_ai_vuln_analysis(analyze, open_ports, asset_context, threat_intel, provider=None):
    prompt = f"""
You are a cybersecurity expert. Analyze the following nmap scan results:

{analyze}

Asset context: {asset_context if asset_context else 'Auto-deduce and enrich context based on open ports/services.'}
Threat intelligence: {threat_intel if threat_intel else 'Auto-enrich with current threat intelligence and recent CVEs.'}

Open ports:
{open_ports}

Return HTML.
"""

    available_providers = []
    if OPENAI_API_KEY:
        available_providers.append("OpenAI")
    if GEMINI_API_KEY:
        available_providers.append("Gemini")

    if not provider:
        if not available_providers:
            return "<b>No AI provider configured. Set OPENAI_API_KEY or GEMINI_API_KEY.</b>"
        if len(available_providers) == 1:
            provider = available_providers[0]
        else:
            print("\nAvailable AI providers:")
            for i, p in enumerate(available_providers, 1):
                print(f"{i}. {p}")
            provider = available_providers[int(input("Select AI provider: ")) - 1]

    if provider == "OpenAI":
        return ask_openai(prompt)
    elif provider == "Gemini":
        return ask_gemini(prompt)
    else:
        return "<b>No valid AI provider selected.</b>"


# =========================
# Export helpers
# =========================
def export_to_html(html_snippet, filename):
    template = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vulnerability Report</title>
</head>
<body>
<h1>Vulnerability Report</h1>
{{ html_snippet | safe }}
</body>
</html>
""")
    html_content = template.render(html_snippet=html_snippet)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)


# =========================
# Main
# =========================
def main():
    print_ethical_warning()
    validate_api_keys()

    parser = argparse.ArgumentParser(
        description="Python-Nmap3 and Multi-AI (OpenAI, Gemini) Vulnerability Scanner"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        '-dl', '--debug-log',
        nargs='?',
        const='vulnscanner-debug.log',
        metavar='file',
        help='Write debug output to file (default: vulnscanner-debug.log)'
    )

    args = parser.parse_args()

    if args.debug or args.debug_log:
        logging.getLogger().setLevel(logging.DEBUG)

        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
        root_logger = logging.getLogger()

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)

        if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
            root_logger.addHandler(console_handler)

        # File handler
        if args.debug_log:
            file_handler = logging.FileHandler(args.debug_log, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)

            if not any(
                isinstance(h, logging.FileHandler) and h.baseFilename == file_handler.baseFilename
                for h in root_logger.handlers
            ):
                root_logger.addHandler(file_handler)

            logging.debug(f"Debug log file enabled: {args.debug_log}")

    target = sanitize_target(args.target)
    if not is_safe_target(target):
        logging.error("Invalid target.")
        sys.exit(1)

    # Host timeout avoids infinite scans
    nmap_args = "-Pn -T4 -F --host-timeout 5m -vvv"
    analyze = run_nmap_scan(target, nmap_args)
    if not analyze:
        logging.error("No scan results.")
        return

    print_scan_results(analyze)
    open_ports = extract_open_ports(analyze)

    vuln_html = ask_ai_vuln_analysis(analyze, open_ports, "", "")
    if not vuln_html or len(vuln_html.strip()) < 20:
        logging.error("AI returned empty or invalid response.")
        return

    output_file = f"{target}-{int(time.time())}.html"
    export_to_html(vuln_html, output_file)
    print(f"Scan complete. Report written to {output_file}")


if __name__ == "__main__":
    main()
