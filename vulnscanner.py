#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI-Vuln-Scanner (multi-provider, AI-first)
# Nmap is a data source; AI does the reasoning.
#
# Providers implemented (as originally intended):
# - OpenAI (HTTP, no openai SDK dependency)
# - Gemini (Google Generative Language API)
# - Anthropic (Claude Messages API)
# - Replit (OpenAI-compatible endpoint)
# - AnythingLLM (workspace API; models + chat)
#
# Key design goals:
# - Stable scanning: call the local `nmap` binary via subprocess (most reliable).
# - Structured scan output: parse Nmap XML into a Python dict (no nmap3 weirdness).
# - Strong debug: -d for verbose console, -dl to write debug log to file.
# - Safe-by-default report export: HTML is escaped unless --trust-ai-html.
#
# Usage examples:
#   python3 vulnscanner.py -t example.com
#   python3 vulnscanner.py -t example.com -d
#   python3 vulnscanner.py -t example.com -dl debug.log
#   python3 vulnscanner.py -t example.com --provider openai
#   python3 vulnscanner.py -t example.com --provider anythingllm --anythingllm-model llama3
#   python3 vulnscanner.py -t 10.0.0.0/24 --nmap-args "-Pn -sV -T4 -p- --host-timeout 10m"
#
# Environment variables (recommended):
#   OPENAI_API_KEY
#   OPENAI_MODEL (optional, default: gpt-4o)
#   GEMINI_API_KEY
#   ANTHROPIC_API_KEY
#   REPLIT_API_KEY
#   REPLIT_API_URL (optional, default: https://chat.replit.com/v1/chat/completions)
#   ANYTHINGLLM_API_KEY
#   ANYTHINGLLM_API_URL   (e.g. https://your-anythingllm.example/api)
#
# NOTE:
# - This tool requires a working local `nmap` installation.

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
from html import escape
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

try:
    from dotenv import load_dotenv
    from jinja2 import Template
except ImportError as e:
    print(f"Missing dependency: {e.name}. Install it with pip.")
    sys.exit(1)

# ============================================================
# Environment
# ============================================================
load_dotenv()

# ============================================================
# Logging base config (handlers are finalized in main())
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
ANYTHINGLLM_API_URL = os.getenv("ANYTHINGLLM_API_URL")  # e.g. https://host/api

# ============================================================
# AI Defaults
# ============================================================
TEMPERATURE = 0.4
TOKEN_LIMIT = 4096  # some providers ignore this or have different limits

HTTP_SESSION = requests.Session()

# ============================================================
# Ethics banner
# ============================================================
def print_ethical_warning() -> None:
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
    # If user pasted hostname:port, strip port (Nmap target should be host/IP/CIDR)
    target = re.sub(r":\d+$", "", target)
    return target


def is_safe_target(target: str) -> bool:
    # reject shell metacharacters to avoid any surprise
    if re.search(r"[;&|`$<>]", target):
        return False

    # allow IP, CIDR, hostname
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

    # simplified RFC1123-ish hostname check
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


def validate_api_keys() -> None:
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
        # treat these as a pair
        missing.append("ANYTHINGLLM_API_KEY/ANYTHINGLLM_API_URL")

    # This warning is informational; we don't hard-fail because user may use only one provider.
    logging.warning(
        "Missing API keys/config: %s. Some providers may be unavailable.",
        ", ".join(missing) if missing else "none"
    )

    logging.debug("OpenAI API Key        : %s", mask_api_key(OPENAI_API_KEY))
    logging.debug("Gemini API Key        : %s", mask_api_key(GEMINI_API_KEY))
    logging.debug("Anthropic API Key     : %s", mask_api_key(ANTHROPIC_API_KEY))
    logging.debug("Replit API Key        : %s", mask_api_key(REPLIT_API_KEY))
    logging.debug("AnythingLLM API Key   : %s", mask_api_key(ANYTHINGLLM_API_KEY))
    logging.debug("AnythingLLM API URL   : %s", ANYTHINGLLM_API_URL or "[NOT SET]")


# ============================================================
# Nmap scanning (robust: subprocess + XML parsing)
# ============================================================
def run_nmap_scan(nmap_bin: str, target: str, nmap_args: str) -> Dict[str, Any]:
    """
    Runs: nmap <args> -oX - <target>
    Parses XML into a stable dict structure:
      {
        "hosts": [
          {
            "address": "x.x.x.x",
            "hostnames": ["example.com"],
            "status": "up",
            "ports": [
              {
                "protocol": "tcp",
                "portid": 443,
                "state": "open",
                "service": {"name": "https", "product": "...", "version": "...", "extrainfo": "..."}
              },
              ...
            ]
          },
          ...
        ],
        "runstats": {...}
      }
    """
    cmd = [nmap_bin] + nmap_args.split() + ["-oX", "-", target]

    logging.debug("=" * 70)
    logging.debug("Executing nmap subprocess")
    logging.debug("Binary   : %s", nmap_bin)
    logging.debug("Target   : %s", target)
    logging.debug("Args     : %s", nmap_args)
    logging.debug("Command  : %s", " ".join(cmd))
    logging.debug("=" * 70)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
    except Exception:
        logging.exception("Failed to execute nmap process.")
        return {}

    if proc.returncode != 0:
        logging.error("nmap failed with exit code %s", proc.returncode)
        if proc.stderr:
            logging.error("nmap stderr:\n%s", proc.stderr.strip())
        # sometimes nmap returns nonzero but still outputs XML; we still try parse if stdout exists
        if not proc.stdout.strip():
            return {}

    xml_text = proc.stdout.strip()
    if not xml_text.startswith("<?xml") and "<nmaprun" not in xml_text:
        logging.error("nmap output did not look like XML. stdout (truncated):\n%s", xml_text[:2000])
        if proc.stderr:
            logging.error("nmap stderr (truncated):\n%s", proc.stderr[:2000])
        return {}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logging.exception("Failed to parse nmap XML.")
        logging.debug("Raw XML (truncated):\n%s", xml_text[:4000])
        return {}

    parsed = parse_nmap_xml(root)
    if not parsed.get("hosts"):
        logging.error("Parsed nmap output has no hosts. Check target resolution/permissions/network.")
    return parsed


def _xml_text(el: Optional[ET.Element]) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def parse_nmap_xml(root: ET.Element) -> Dict[str, Any]:
    hosts: List[Dict[str, Any]] = []

    for h in root.findall("host"):
        host_entry: Dict[str, Any] = {
            "status": None,
            "address": None,
            "hostnames": [],
            "ports": [],
            "os": [],
            "scripts": [],
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

        # Ports
        for p in h.findall("./ports/port"):
            protocol = p.attrib.get("protocol")
            portid_raw = p.attrib.get("portid")
            try:
                portid = int(portid_raw) if portid_raw is not None else None
            except ValueError:
                portid = None

            state_el = p.find("state")
            state = state_el.attrib.get("state") if state_el is not None else None

            svc_el = p.find("service")
            service: Dict[str, Any] = {}
            if svc_el is not None:
                # common attributes
                for k in ("name", "product", "version", "extrainfo", "ostype", "tunnel", "method", "conf"):
                    v = svc_el.attrib.get(k)
                    if v:
                        service[k] = v

            scripts: List[Dict[str, Any]] = []
            for s in p.findall("script"):
                scripts.append({
                    "id": s.attrib.get("id"),
                    "output": s.attrib.get("output", "")
                })

            host_entry["ports"].append({
                "protocol": protocol,
                "portid": portid,
                "state": state,
                "service": service,
                "scripts": scripts
            })

        # Host scripts
        for s in h.findall("./hostscript/script"):
            host_entry["scripts"].append({
                "id": s.attrib.get("id"),
                "output": s.attrib.get("output", "")
            })

        # OS detection (if present)
        for osmatch in h.findall("./os/osmatch"):
            host_entry["os"].append({
                "name": osmatch.attrib.get("name"),
                "accuracy": osmatch.attrib.get("accuracy")
            })

        hosts.append(host_entry)

    # Runstats
    runstats: Dict[str, Any] = {}
    finished = root.find("./runstats/finished")
    if finished is not None:
        runstats["finished"] = dict(finished.attrib)

    summary = root.find("./runstats/hosts")
    if summary is not None:
        runstats["hosts"] = dict(summary.attrib)

    return {"hosts": hosts, "runstats": runstats}


def extract_open_ports(scan: Dict[str, Any]) -> str:
    parts: List[str] = []
    for host in scan.get("hosts", []):
        hn = host.get("hostnames") or []
        addr = host.get("address") or "unknown-host"
        label = hn[0] if hn else addr

        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            proto = (p.get("protocol") or "tcp").upper()
            portid = p.get("portid")
            svc = (p.get("service") or {}).get("name", "unknown")
            product = (p.get("service") or {}).get("product", "")
            version = (p.get("service") or {}).get("version", "")
            ver = " ".join([x for x in [product, version] if x]).strip()
            suffix = f" ({ver})" if ver else ""
            parts.append(f"{label} {proto} {portid}/{svc}{suffix}")

    return ", ".join(parts) if parts else "(no open ports detected)"


def print_scan_results(scan: Dict[str, Any]) -> None:
    for host in scan.get("hosts", []):
        hn = host.get("hostnames") or []
        addr = host.get("address") or "unknown"
        status = host.get("status") or "unknown"
        label = hn[0] if hn else addr

        logging.info("Host: %s (%s) status=%s", label, addr, status)
        ports = host.get("ports", [])
        if not ports:
            logging.info("  No ports section in results.")
            continue

        logging.info("  Ports:")
        for p in ports:
            proto = (p.get("protocol") or "tcp").upper()
            portid = p.get("portid")
            state = p.get("state")
            svc = (p.get("service") or {}).get("name", "unknown")
            logging.info("    %s %s: %s (%s)", proto, portid, svc, state)

        if host.get("os"):
            logging.info("  OS guesses: %s", ", ".join([o.get("name", "") for o in host["os"] if o.get("name")]))

        if host.get("scripts"):
            logging.info("  Host scripts: %s", ", ".join([s.get("id", "") for s in host["scripts"] if s.get("id")]))
        print()


# ============================================================
# AI Provider Implementations
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
            {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst. Be precise and evidence-driven."},
            {"role": "user", "content": prompt},
        ],
        "temperature": TEMPERATURE,
        "max_tokens": TOKEN_LIMIT,
    }

    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error("OpenAI API error: %s", e)
        return "<b>OpenAI API error. No vulnerability analysis available.</b>"


def ask_gemini(prompt: str, timeout: int = 60) -> str:
    if not GEMINI_API_KEY:
        return "<b>Gemini API key not configured.</b>"

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": GEMINI_API_KEY}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    try:
        r = HTTP_SESSION.post(url, headers=headers, params=params, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        logging.error("Gemini API error: %s", e)
        return "<b>Gemini API error. No vulnerability analysis available.</b>"


def ask_anthropic(prompt: str, timeout: int = 60, model: str = "claude-3-sonnet-20240229") -> str:
    if not ANTHROPIC_API_KEY:
        return "<b>Anthropic API key not configured.</b>"

    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": TOKEN_LIMIT,
        "temperature": TEMPERATURE,
        "system": "You are a senior penetration tester and vulnerability analyst. Be precise and evidence-driven.",
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        # Anthropic returns list in "content": [{"type":"text","text":"..."}]
        content = data.get("content", [])
        if isinstance(content, list) and content:
            # concatenate text blocks
            return "\n".join([c.get("text", "") for c in content if isinstance(c, dict)])
        return str(content)
    except Exception as e:
        logging.error("Anthropic API error: %s", e)
        return "<b>Anthropic API error. No vulnerability analysis available.</b>"


def ask_replit(prompt: str, timeout: int = 60, model: str = "replit-code-v1-3b") -> str:
    if not REPLIT_API_KEY:
        return "<b>Replit API key not configured.</b>"

    headers = {
        "Authorization": f"Bearer {REPLIT_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst. Be precise and evidence-driven."},
            {"role": "user", "content": prompt},
        ],
        "temperature": TEMPERATURE,
        "max_tokens": TOKEN_LIMIT,
    }

    try:
        r = HTTP_SESSION.post(REPLIT_API_URL, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        logging.error("Replit API error: %s", e)
        return "<b>Replit API error. No vulnerability analysis available.</b>"


def anythingllm_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {ANYTHINGLLM_API_KEY}",
        "Content-Type": "application/json",
    }


def list_anythingllm_models(timeout: int = 15) -> List[str]:
    """
    AnythingLLM APIs vary by deployment.
    Common patterns:
      - GET {API_URL}/models
      - GET {API_URL}/v1/models
    We try both.
    """
    if not (ANYTHINGLLM_API_URL and ANYTHINGLLM_API_KEY):
        return []

    candidates = [
        f"{ANYTHINGLLM_API_URL.rstrip('/')}/models",
        f"{ANYTHINGLLM_API_URL.rstrip('/')}/v1/models",
    ]

    for url in candidates:
        try:
            r = HTTP_SESSION.get(url, headers=anythingllm_headers(), timeout=timeout)
            if r.status_code >= 400:
                continue
            data = r.json()
            # normalize possible shapes
            if isinstance(data, dict):
                if "models" in data and isinstance(data["models"], list):
                    # could be list of strings or objects
                    out = []
                    for m in data["models"]:
                        if isinstance(m, str):
                            out.append(m)
                        elif isinstance(m, dict) and m.get("name"):
                            out.append(str(m["name"]))
                    if out:
                        return out
                if "data" in data and isinstance(data["data"], list):
                    out = []
                    for m in data["data"]:
                        if isinstance(m, dict) and m.get("id"):
                            out.append(str(m["id"]))
                    if out:
                        return out
        except Exception:
            continue

    return []


def ask_anythingllm(prompt: str, model: str, timeout: int = 60) -> str:
    """
    AnythingLLM chat endpoints vary. Common patterns:
      - POST {API_URL}/chat
      - POST {API_URL}/v1/chat/completions (OpenAI style)
    We try both, in order.
    """
    if not (ANYTHINGLLM_API_URL and ANYTHINGLLM_API_KEY):
        return "<b>AnythingLLM not configured (API URL/key missing).</b>"

    endpoints = [
        (f"{ANYTHINGLLM_API_URL.rstrip('/')}/chat", "native"),
        (f"{ANYTHINGLLM_API_URL.rstrip('/')}/v1/chat/completions", "openai"),
    ]

    for url, kind in endpoints:
        try:
            if kind == "native":
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst. Be precise and evidence-driven."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": TEMPERATURE,
                    "max_tokens": TOKEN_LIMIT,
                }
                r = HTTP_SESSION.post(url, headers=anythingllm_headers(), json=payload, timeout=timeout)
                if r.status_code >= 400:
                    continue
                data = r.json()
                # try several shapes
                # - {"choices":[{"message":{"content":"..."}}]}
                # - {"text":"..."} or {"content":"..."}
                if isinstance(data, dict):
                    if "choices" in data:
                        return data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    if "content" in data and isinstance(data["content"], str):
                        return data["content"]
                    if "text" in data and isinstance(data["text"], str):
                        return data["text"]

            else:
                # OpenAI-compatible
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst. Be precise and evidence-driven."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": TEMPERATURE,
                    "max_tokens": TOKEN_LIMIT,
                }
                r = HTTP_SESSION.post(url, headers=anythingllm_headers(), json=payload, timeout=timeout)
                if r.status_code >= 400:
                    continue
                data = r.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")

        except Exception:
            continue

    logging.error("AnythingLLM API error: could not use any known endpoint successfully.")
    return "<b>AnythingLLM API error. No vulnerability analysis available.</b>"


# ============================================================
# AI Router + Prompting
# ============================================================
def build_ai_prompt(scan: Dict[str, Any], open_ports_summary: str, target: str) -> str:
    # Prevent accidental triple-backtick injection in downstream renderers
    scan_dump = json.dumps(scan, indent=2).replace("```", "'''")

    prompt = f"""
You are a senior penetration tester and vulnerability analyst.

You are given Nmap scan results for target: {target}

Nmap structured results (JSON):
{scan_dump}

Open ports summary:
{open_ports_summary}

Task:
1) Identify likely vulnerabilities, misconfigurations, and exposures based on detected services, versions, and scripts.
2) For each issue, include:
   - Title
   - Affected endpoint (host/IP, port, protocol, service)
   - Evidence (quote the relevant lines/fields from the scan JSON)
   - Severity (Critical/High/Medium/Low) with rationale
   - Business impact
   - Concrete remediation steps (actionable, not vague)
   - References: CWE, CAPEC, OWASP (Top 10 / ASVS / WSTG when relevant)
3) Prioritize findings by risk.
4) If the scan is too shallow to be confident, explicitly say so and propose what additional scan flags/scripts would reduce uncertainty.

Output format:
- Return an HTML report with clear headings (<h2>, <h3>), bullet points (<ul><li>), and sections.
- Do NOT include JavaScript or any <script> tags.
"""
    return prompt.strip()


def available_providers() -> List[str]:
    providers = []
    if OPENAI_API_KEY:
        providers.append("openai")
    if GEMINI_API_KEY:
        providers.append("gemini")
    if ANTHROPIC_API_KEY:
        providers.append("anthropic")
    if REPLIT_API_KEY:
        providers.append("replit")
    if ANYTHINGLLM_API_KEY and ANYTHINGLLM_API_URL:
        providers.append("anythingllm")
    return providers


def ask_ai(provider: str, prompt: str, anythingllm_model: Optional[str], replit_model: str, anthropic_model: str) -> str:
    provider = provider.lower().strip()

    if provider == "openai":
        return ask_openai(prompt)
    if provider == "gemini":
        return ask_gemini(prompt)
    if provider == "anthropic":
        return ask_anthropic(prompt, model=anthropic_model)
    if provider == "replit":
        return ask_replit(prompt, model=replit_model)
    if provider == "anythingllm":
        if not anythingllm_model:
            models = list_anythingllm_models()
            if models:
                # default to first available if user did not set it
                anythingllm_model = models[0]
                logging.info("AnythingLLM model not specified; using first discovered model: %s", anythingllm_model)
            else:
                return "<b>AnythingLLM configured but no models discovered; set --anythingllm-model manually.</b>"
        return ask_anythingllm(prompt, model=anythingllm_model)

    return "<b>No valid AI provider selected.</b>"


# ============================================================
# Export (safe by default)
# ============================================================
def basic_html_template(title: str, body_html: str) -> str:
    tpl = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{{ title }}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.35; }
  code, pre { background: #f4f4f4; padding: 10px; display: block; overflow-x: auto; }
  h1 { margin-bottom: 0.2em; }
  .meta { color: #555; margin-top: 0; }
  .small { font-size: 0.9em; color: #555; }
</style>
</head>
<body>
<h1>{{ title }}</h1>
<p class="meta">{{ meta }}</p>
<hr>
{{ body_html | safe }}
</body>
</html>
""")
    return tpl.render(title=title, meta=time.strftime("%Y-%m-%d %H:%M:%S"), body_html=body_html)


def export_report_html(ai_html: str, filename: str, trust_ai_html: bool) -> None:
    """
    Safe-by-default:
      - If trust_ai_html=False: escape AI output and show in <pre>.
      - If trust_ai_html=True: embed AI HTML as-is (still no scripts guaranteed by prompt, but it's your call).
    """
    if trust_ai_html:
        body = ai_html
    else:
        body = f"<pre>{escape(ai_html)}</pre>"

    html = basic_html_template("AI Vulnerability Report", body)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


def export_report_json(scan: Dict[str, Any], ai_output: str, filename: str) -> None:
    obj = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan": scan,
        "ai_output": ai_output,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def export_report_txt(ai_output: str, filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write(ai_output)


# ============================================================
# Main
# ============================================================
def setup_debug_logging(debug: bool, debug_log: Optional[str]) -> None:
    if not (debug or debug_log):
        return

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

    # Console handler: avoid duplicates
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        root.addHandler(ch)

    # File handler
    if debug_log:
        # default name already handled by argparse const
        fh = logging.FileHandler(debug_log, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == fh.baseFilename for h in root.handlers):
            root.addHandler(fh)

        logging.debug("Debug log file enabled: %s", debug_log)


def main() -> None:
    print_ethical_warning()
    validate_api_keys()

    parser = argparse.ArgumentParser(description="AI-Vuln-Scanner (multi-provider, AI-first)")

    parser.add_argument("-t", "--target", required=True, help="Target IP/hostname/CIDR")
    parser.add_argument("--nmap-path", default=None, help="Path to nmap binary (default: use PATH)")
    parser.add_argument("--nmap-args", default="-Pn -sV -T4 -F --host-timeout 5m -vvv", help="Arguments passed to nmap (excluding -oX - and target)")

    parser.add_argument("--provider", default=None, help="AI provider: openai|gemini|anthropic|replit|anythingllm (default: first available)")
    parser.add_argument("--anthropic-model", default="claude-3-sonnet-20240229", help="Anthropic model name (default: claude-3-sonnet-20240229)")
    parser.add_argument("--replit-model", default="replit-code-v1-3b", help="Replit model name (default: replit-code-v1-3b)")
    parser.add_argument("--anythingllm-model", default=None, help="AnythingLLM model name/id")

    parser.add_argument("-o", "--output", default="html", choices=["html", "json", "txt"], help="Output format")
    parser.add_argument("--trust-ai-html", action="store_true", help="Embed AI HTML directly (unsafe if AI output is untrusted)")

    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging (console)")
    parser.add_argument(
        "-dl", "--debug-log",
        nargs="?",
        const="vulnscanner-debug.log",
        metavar="file",
        help="Write debug output to file (default: vulnscanner-debug.log)"
    )

    args = parser.parse_args()
    setup_debug_logging(args.debug, args.debug_log)

    target = sanitize_target(args.target)
    if not is_safe_target(target):
        logging.error("Invalid target value. Refusing to run.")
        sys.exit(1)

    try:
        nmap_bin = ensure_nmap_available(args.nmap_path)
    except Exception as e:
        logging.error("%s", e)
        sys.exit(1)

    scan = run_nmap_scan(nmap_bin=nmap_bin, target=target, nmap_args=args.nmap_args)
    if not scan:
        logging.error("No scan results. Exiting.")
        sys.exit(2)

    if logging.getLogger().level <= logging.INFO:
        print_scan_results(scan)

    open_ports_summary = extract_open_ports(scan)
    logging.info("Open ports summary: %s", open_ports_summary)

    providers = available_providers()
    if not providers:
        logging.error("No AI providers available. Configure at least one API key.")
        sys.exit(3)

    provider = (args.provider or providers[0]).lower()
    if provider not in providers:
        logging.error("Requested provider '%s' not available. Available: %s", provider, ", ".join(providers))
        sys.exit(4)

    prompt = build_ai_prompt(scan, open_ports_summary, target)
    logging.debug("AI prompt size: %d chars", len(prompt))

    ai_output = ask_ai(
        provider=provider,
        prompt=prompt,
        anythingllm_model=args.anythingllm_model,
        replit_model=args.replit_model,
        anthropic_model=args.anthropic_model,
    )

    if not ai_output or len(ai_output.strip()) < 10:
        logging.error("AI returned empty/invalid response.")
        sys.exit(5)

    ts = int(time.time())
    base = f"{target}-{ts}"
    if args.output == "html":
        out = f"{base}.html"
        export_report_html(ai_output, out, trust_ai_html=args.trust_ai_html)
    elif args.output == "json":
        out = f"{base}.json"
        export_report_json(scan, ai_output, out)
    else:
        out = f"{base}.txt"
        export_report_txt(ai_output, out)

    print(f"Scan complete. Output written to {out} (provider={provider})")


if __name__ == "__main__":
    main()
