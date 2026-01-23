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
from html import escape as html_escape

try:
    import nmap3
    from jinja2 import Template
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Missing dependency: {e.name}. Please install it with pip.")
    sys.exit(1)

# =========================
# Environment
# =========================
load_dotenv()

# IMPORTANT:
# Use Nmap() wrapper methods (stable dict output), not raw scan_command.
NM = nmap3.Nmap()

# Shared HTTP session (performance + reliability)
HTTP_SESSION = requests.Session()

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


# =========================
# Utilities
# =========================
def mask_api_key(key: str | None) -> str:
    if not key or len(key) < 8:
        return "[NOT SET]"
    return key[:4] + "..." + key[-4:]


def validate_api_keys() -> None:
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


def print_ethical_warning() -> None:
    print("\n" + "=" * 80)
    print("WARNING: Use this script ONLY on systems you own or have explicit permission to test.")
    print("Unauthorized scanning is illegal and unethical.")
    print("=" * 80 + "\n")


def sanitize_target(target: str) -> str:
    # Remove protocol
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    # Remove trailing slash
    target = target.strip().strip("/")
    # Remove :port if present
    target = re.sub(r":\d+$", "", target)
    return target


def _is_reasonable_hostname(hostname: str) -> bool:
    """
    Stricter-but-not-insane hostname validation.
    - Allows letters, digits, hyphen, dot
    - No empty labels, no consecutive dots
    - Labels can't start/end with hyphen
    - Total length <= 253, label length <= 63
    """
    if len(hostname) == 0 or len(hostname) > 253:
        return False
    if hostname.startswith(".") or hostname.endswith("."):
        return False
    if ".." in hostname:
        return False
    if not re.fullmatch(r"[A-Za-z0-9.-]+", hostname):
        return False

    labels = hostname.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def is_safe_target(target: str) -> bool:
    # Reject obvious shell metacharacters
    if re.search(r"[;&|`$<>]", target):
        return False

    # IP address?
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Hostname?
    return _is_reasonable_hostname(target)


def configure_logging(enable_debug: bool, debug_log_path: str | None) -> None:
    """
    Ensure debug level + consistent formatter on ALL existing handlers,
    and optionally add a file handler without duplication.
    """
    root_logger = logging.getLogger()

    if enable_debug or debug_log_path:
        root_logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

        # Apply formatter to existing handlers (basicConfig likely created one)
        for h in root_logger.handlers:
            h.setLevel(logging.DEBUG)
            h.setFormatter(formatter)

        # If no stream handler exists (rare), add one
        if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
            sh = logging.StreamHandler()
            sh.setLevel(logging.DEBUG)
            sh.setFormatter(formatter)
            root_logger.addHandler(sh)

        # Add file handler if requested (avoid duplicates)
        if debug_log_path:
            abs_path = os.path.abspath(debug_log_path)
            already = False
            for h in root_logger.handlers:
                if isinstance(h, logging.FileHandler):
                    try:
                        if os.path.abspath(h.baseFilename) == abs_path:
                            already = True
                            break
                    except Exception:
                        pass

            if not already:
                fh = logging.FileHandler(debug_log_path, encoding="utf-8")
                fh.setLevel(logging.DEBUG)
                fh.setFormatter(formatter)
                root_logger.addHandler(fh)

            logging.debug(f"Debug log file enabled: {debug_log_path}")


# =========================
# Nmap handling
# =========================
def _safe_debug_dump(obj, max_chars: int = 15000) -> str:
    """
    Avoid crashing debug logs on non-JSON objects or huge blobs.
    """
    try:
        s = json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception:
        s = str(obj)
    if len(s) > max_chars:
        return s[:max_chars] + "\n... [TRUNCATED] ..."
    return s


def run_nmap_scan(target: str, arguments: str) -> dict:
    """
    Use nmap3 wrappers that return dicts. This avoids scan_command XML crashes and
    version-specific method signatures.
    """
    try:
        logging.debug("=" * 60)
        logging.debug("Executing nmap version detection scan (stable wrapper)")
        logging.debug(f"Target   : {target}")
        logging.debug(f"Arguments: {arguments}")
        logging.debug("=" * 60)

        # nmap_version_detection runs: nmap -sV ... (plus args you provide)
        # It returns a dict keyed by host.
        result = NM.nmap_version_detection(target=target, args=arguments)

        logging.debug("Raw parsed result:")
        logging.debug(_safe_debug_dump(result))

        if not isinstance(result, dict):
            logging.error(f"Nmap returned non-dict structure: {type(result)}")
            return {}
        if not result:
            logging.error("Nmap returned empty result dict.")
            return {}

        # Some nmap3 outputs include keys like "runtime", "stats", etc.
        # Prefer a key that looks like a host with ports data.
        host_key = None
        for k, v in result.items():
            if isinstance(v, dict) and ("ports" in v or "hostname" in v or "addresses" in v):
                host_key = k
                break

        if not host_key:
            # fallback: first key
            host_key = next(iter(result.keys()))

        host_data = result.get(host_key)
        if not isinstance(host_data, dict):
            logging.error("Host data is not a dictionary.")
            logging.debug(f"Host key: {host_key}")
            logging.debug(f"Host data: {host_data}")
            return {}

        return {host_key: host_data}

    except Exception:
        logging.exception("Nmap scan crashed with exception:")
        return {}


def extract_open_ports(analyze: dict) -> str:
    open_ports_info = []
    for host, host_data in analyze.items():
        ports = host_data.get("ports", []) if isinstance(host_data, dict) else []
        for port_entry in ports:
            if isinstance(port_entry, dict) and port_entry.get("state") == "open":
                portid = port_entry.get("portid")
                service = (port_entry.get("service") or {}).get("name", "unknown")
                protocol = port_entry.get("protocol", "tcp")
                open_ports_info.append(f"{protocol.upper()} Port {portid}: {service}")
    return ", ".join(open_ports_info)


def print_scan_results(analyze: dict) -> None:
    for host, host_data in analyze.items():
        logging.info(f"Host: {host}")
        if isinstance(host_data, dict) and "ports" in host_data:
            logging.info("Ports:")
            for port_entry in host_data.get("ports", []):
                if not isinstance(port_entry, dict):
                    continue
                portid = port_entry.get("portid")
                protocol = port_entry.get("protocol", "tcp")
                state = port_entry.get("state")
                service = (port_entry.get("service") or {}).get("name", "unknown")
                logging.info(f"  {protocol.upper()} Port {portid}: {service} ({state})")
        print()


# =========================
# AI Providers
# =========================
def ask_openai(prompt: str) -> str:
    if not OPENAI_API_KEY:
        return "<b>No OpenAI API key configured.</b>"

    try:
        import openai
    except Exception as e:
        logging.error(f"OpenAI library not available: {e}")
        return "<b>OpenAI library missing. Install 'openai' package.</b>"

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


def ask_gemini(prompt: str) -> str:
    if not GEMINI_API_KEY:
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
        response = HTTP_SESSION.post(url, headers=headers, params=params, json=data, timeout=60)
        response.raise_for_status()
        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        logging.error(f"Gemini API error: {e}")
        return "<b>Gemini API error. No vulnerability analysis available.</b>"


# =========================
# AI Router
# =========================
def ask_ai_vuln_analysis(analyze: dict, open_ports: str, provider: str | None = None) -> str:
    prompt = f"""
Analyze the following nmap scan results and produce a vulnerability-oriented report.

Scan results (parsed):
{analyze}

Open ports summary:
{open_ports}

For each exposed service, provide:
- What it is and why it matters
- Likely vulnerability classes (not fake CVEs)
- Practical attack surface / misconfig checks
- Severity (Critical/High/Medium/Low) with rationale
- Remediation steps
- References to OWASP/ASVS/WSTG/CWE/CAPEC (links)

Return output as HTML (but do not include scripts).
"""

    available = []
    if OPENAI_API_KEY:
        available.append("OpenAI")
    if GEMINI_API_KEY:
        available.append("Gemini")

    if not provider:
        if not available:
            return "<b>No AI provider configured. Set OPENAI_API_KEY or GEMINI_API_KEY.</b>"
        provider = available[0] if len(available) == 1 else None

    if provider is None and len(available) > 1:
        print("\nAvailable AI providers:")
        for i, p in enumerate(available, 1):
            print(f"{i}. {p}")
        try:
            idx = int(input("Select AI provider: ").strip())
            provider = available[idx - 1]
        except Exception:
            provider = available[0]

    if provider == "OpenAI":
        return ask_openai(prompt)
    if provider == "Gemini":
        return ask_gemini(prompt)
    return "<b>No valid AI provider selected.</b>"


# =========================
# Export helpers
# =========================
def export_to_html(html_snippet: str, filename: str) -> None:
    """
    Security: escape by default to avoid script injection.
    We'll keep minimal formatting: convert newlines to <br>.
    """
    safe_body = html_escape(html_snippet).replace("\n", "<br>\n")

    template = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vulnerability Report</title>
</head>
<body>
<h1>Vulnerability Report</h1>
<div style="white-space: normal; font-family: Arial, sans-serif;">
{{ body | safe }}
</div>
</body>
</html>
""")
    html_content = template.render(body=safe_body)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)


# =========================
# Main
# =========================
def main():
    print_ethical_warning()

    parser = argparse.ArgumentParser(
        description="Python-Nmap3 and Multi-AI (OpenAI, Gemini) Vulnerability Scanner"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "-dl", "--debug-log",
        nargs="?",
        const="vulnscanner-debug.log",
        metavar="file",
        help="Write debug output to file (default: vulnscanner-debug.log)",
    )
    parser.add_argument(
        "--nmap-args",
        default="-Pn -T4 -F --host-timeout 5m -sV -vvv",
        help="Custom nmap arguments (passed to nmap_version_detection)",
    )

    args = parser.parse_args()

    configure_logging(args.debug, args.debug_log)
    validate_api_keys()

    target = sanitize_target(args.target)
    if not is_safe_target(target):
        logging.error(f"Invalid target: {target}")
        sys.exit(1)

    analyze = run_nmap_scan(target, args.nmap_args)
    if not analyze:
        logging.error("No scan results.")
        return

    print_scan_results(analyze)
    open_ports = extract_open_ports(analyze)

    vuln_html = ask_ai_vuln_analysis(analyze, open_ports)
    if not vuln_html or len(vuln_html.strip()) < 20:
        logging.error("AI returned empty or invalid response.")
        return

    output_file = f"{target}-{int(time.time())}.html"
    export_to_html(vuln_html, output_file)
    print(f"Scan complete. Report written to {output_file}")


if __name__ == "__main__":
    main()
