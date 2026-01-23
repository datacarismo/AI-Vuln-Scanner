#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914 (refactored by Perplexity AI)

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

load_dotenv()
nm = nmap3.NmapScanTechniques()

# Logging setup (default to INFO, set to DEBUG in main if needed)
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

# =========================
# AI Provider Configs
# =========================
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
ANYTHINGLLM_API_KEY = os.getenv('ANYTHINGLLM_API_KEY')
ANYTHINGLLM_API_URL = os.getenv('ANYTHINGLLM_API_URL')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
REPLIT_API_KEY = os.getenv('REPLIT_API_KEY')
REPLIT_API_URL = os.getenv('REPLIT_API_URL', 'https://chat.replit.com/v1/chat/completions')

# FIX 1: Gemini key was missing
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

MODEL_ENGINE = "gpt-4o"
TEMPERATURE = 0.5
TOKEN_LIMIT = 4096

nm = nmap3.Nmap()


# =========================
# Utilities
# =========================
def mask_api_key(key):
    if not key or len(key) < 8:
        return "[NOT SET]"
    return key[:4] + "..." + key[-4:]


def validate_api_keys():
    missing_keys = []
    if not OPENAI_API_KEY:
        missing_keys.append("OPENAI_API_KEY")
    if not ANYTHINGLLM_API_KEY:
        missing_keys.append("ANYTHINGLLM_API_KEY")
    if not ANTHROPIC_API_KEY:
        missing_keys.append("ANTHROPIC_API_KEY")
    if not REPLIT_API_KEY:
        missing_keys.append("REPLIT_API_KEY")
    if not GEMINI_API_KEY:
        missing_keys.append("GEMINI_API_KEY")

    if missing_keys:
        logging.warning(f"Missing API keys: {', '.join(missing_keys)}. Some functionality may be unavailable.")

    logging.debug(f"OpenAI API Key: {mask_api_key(OPENAI_API_KEY)}")
    logging.debug(f"AnythingLLM API Key: {mask_api_key(ANYTHINGLLM_API_KEY)}")
    logging.debug(f"Anthropic API Key: {mask_api_key(ANTHROPIC_API_KEY)}")
    logging.debug(f"Replit API Key: {mask_api_key(REPLIT_API_KEY)}")
    logging.debug(f"Gemini API Key: {mask_api_key(GEMINI_API_KEY)}")


def print_ethical_warning():
    print("\n" + "=" * 80)
    print("WARNING: Use this script ONLY on systems you own or have explicit permission to test.")
    print("Unauthorized scanning is illegal and unethical.")
    print("=" * 80 + "\n")


def sanitize_target(target):
    target = re.sub(r'^https?://', '', target, flags=re.IGNORECASE)
    return target.strip('/')


def is_safe_target(target):
    if re.search(r'[;&|`$<>]', target):
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    if re.match(r'^[a-zA-Z0-9.-]+$', target):
        return True
    return False


# =========================
# Nmap handling
# =========================
def run_nmap_scan(target, arguments):
    try:
        logging.debug("=" * 60)
        logging.debug("Executing nmap3 version detection scan")
        logging.debug(f"Target   : {target}")
        logging.debug(f"Arguments: {arguments}")
        logging.debug("=" * 60)

        # This returns a proper Python dictionary (JSON-compatible)
        result = nm.nmap_version_detection(target, args=arguments)

        logging.debug(f"Type of result: {type(result)}")
        logging.debug("Full raw result:")
        logging.debug(json.dumps(result, indent=2))

        if not isinstance(result, dict):
            logging.error("Nmap did not return a dictionary structure.")
            return {}

        if not result:
            logging.error("Nmap returned an empty result.")
            return {}

        # nmap3 already returns per-host dictionaries here
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

    except Exception as e:
        logging.exception("Nmap scan crashed with exception:")
        return {}

def extract_open_ports(analyze):
    open_ports_info = []
    for host, host_data in analyze.items():
        ports = host_data.get("ports", [])
        for port_entry in ports:
            if port_entry.get('state') == 'open':
                portid = port_entry.get('portid')
                service = port_entry.get('service', {}).get('name', 'unknown')
                protocol = port_entry.get('protocol', 'tcp')
                open_ports_info.append(f"{protocol.upper()} Port {portid}: {service}")
    return ', '.join(open_ports_info)


def print_scan_results(analyze):
    for host, host_data in analyze.items():
        logging.info(f"Host: {host}")
        if "ports" in host_data:
            logging.info("Ports:")
            for port_entry in host_data["ports"]:
                portid = port_entry.get('portid')
                protocol = port_entry.get('protocol', 'tcp')
                state = port_entry.get('state')
                service = port_entry.get('service', {}).get('name', 'unknown')
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
                {"role": "user", "content": prompt}
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
        response = requests.post(url, headers=headers, params=params, json=data, timeout=60)
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
def is_valid_json(json_string):
    try:
        data = json.loads(json_string)
        return isinstance(data, dict) or (isinstance(data, list) and len(data) > 0)
    except json.JSONDecodeError:
        return False


def export_to_html(html_snippet, filename):
    template = Template("""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Vulnerability Report</title></head>
<body>
<h1>Vulnerability Report</h1>
{{ html_snippet }}
</body>
</html>
""")
    html_content = template.render(html_snippet=html_snippet)
    with open(filename, "w", encoding='utf-8') as f:
        f.write(html_content)


# =========================
# Main
# =========================
def main():
    print_ethical_warning()
    validate_api_keys()

    parser = argparse.ArgumentParser(
        description='Python-Nmap3 and Multi-AI (OpenAI, Gemini) Vulnerability Scanner'
    )
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    target = sanitize_target(args.target)
    if not is_safe_target(target):
        logging.error("Invalid target.")
        sys.exit(1)

    analyze = run_nmap_scan(target, "-Pn -sV -T4 -F -vvv")
    if not analyze:
        logging.error("No scan results.")
        return

    print_scan_results(analyze)
    open_ports = extract_open_ports(analyze)

    vuln_html = ask_ai_vuln_analysis(analyze, open_ports, "", "")
    export_to_html(vuln_html, f"{target}-{int(time.time())}.html")
    print("Scan complete.")


if __name__ == "__main__":
    main()
