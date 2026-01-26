#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI-Vuln-Scanner (multi-provider, AI-first)
# Nmap is a data source; AI does the reasoning.
#
# Providers implemented:
# - OpenAI (HTTP, no openai SDK dependency)
# - Gemini (Google Generative Language API)
# - Anthropic (Claude Messages API)
# - Replit (OpenAI-compatible endpoint)
# - AnythingLLM (workspace API; models + chat)
#
# Key design goals:
# - Stable scanning: call the local `nmap` binary via subprocess (most reliable).
# - Structured scan output: parse Nmap XML into a Python dict.
# - Strong debug: -d for verbose console, -dl to write debug log to file.
# - Safe-by-default report export: HTML is escaped unless --trust-ai-html.
#
# New additions (without removing anything):
# - -o / --output: html, csv, xml, txt, or json (default: html)
# - -p / --profile: scan profile number (1..N). Used only when user did NOT provide --nmap-args.
# - Strips Markdown code fences from AI output to avoid browsers showing escaped markup.
# - If --trust-ai-html and AI output is a full HTML document, write it as-is to avoid nesting docs.

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
from typing import Any, Dict, List, Optional, Tuple
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
# Gemini model name can be overridden; keep default conservative and widely available
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")

REPLIT_API_KEY = os.getenv("REPLIT_API_KEY")
REPLIT_API_URL = os.getenv("REPLIT_API_URL", "https://chat.replit.com/v1/chat/completions")
REPLIT_MODEL = os.getenv("REPLIT_MODEL", "gpt-4o-mini")

ANYTHINGLLM_API_KEY = os.getenv("ANYTHINGLLM_API_KEY")
ANYTHINGLLM_API_URL = os.getenv("ANYTHINGLLM_API_URL")
ANYTHINGLLM_WORKSPACE = os.getenv("ANYTHINGLLM_WORKSPACE", "default")
ANYTHINGLLM_MODEL = os.getenv("ANYTHINGLLM_MODEL")  # optional; AnythingLLM can pick default

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
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
)
adapter = HTTPAdapter(max_retries=retry)
HTTP_SESSION.mount("https://", adapter)
HTTP_SESSION.mount("http://", adapter)

# ============================================================
# Scan Profiles (used by -p/--profile ONLY if user did NOT pass --nmap-args)
# ============================================================
LEGACY_DEFAULT_NMAP_ARGS = "-Pn -sV -T4 -F --host-timeout 5m -vvv"

SCAN_PROFILES: Dict[int, str] = {
    # 1: Legacy default (matches previous default behavior)
    1: LEGACY_DEFAULT_NMAP_ARGS,
    # 2: Full TCP ports, scripts + version detection
    2: "-Pn -p- -sC -sV -T4 --host-timeout 10m -vvv",
    # 3: Top 1000 TCP + UDP top 200 (balanced)
    3: "-Pn -sT -sU -T4 --top-ports 1000 --defeat-rst-ratelimit --host-timeout 15m -vvv",
    # 4: Very fast discovery-ish (still version detection)
    4: "-Pn -sV -T5 -F --host-timeout 3m -vvv",
}

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

            state_el = p.find("state")
            state = state_el.attrib.get("state") if state_el is not None else None

            svc_el = p.find("service")
            service = {}
            if svc_el is not None:
                for k in ("name", "product", "version", "extrainfo"):
                    if svc_el.attrib.get(k):
                        service[k] = svc_el.attrib[k]

            # Port scripts (best-effort)
            scripts = []
            for s in p.findall("script"):
                scripts.append({
                    "id": s.attrib.get("id"),
                    "output": s.attrib.get("output", ""),
                })

            host_entry["ports"].append({
                "protocol": protocol,
                "portid": portid,
                "state": state,
                "service": service,
                "scripts": scripts
            })

        # Host scripts (best-effort)
        for s in h.findall("hostscript/script"):
            host_entry["scripts"].append({
                "id": s.attrib.get("id"),
                "output": s.attrib.get("output", ""),
            })

        hosts.append(host_entry)

    return {"hosts": hosts}


def extract_open_ports(scan: Dict[str, Any]) -> str:
    parts = []
    for host in scan.get("hosts", []):
        label = (host.get("hostnames") or [host.get("address")])[0]
        for p in host.get("ports", []):
            if p.get("state") == "open":
                proto = (p.get("protocol") or "").upper()
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
IMPORTANT: Do NOT wrap the output in Markdown code fences (no ```).
"""
    return prompt.strip()

# ============================================================
# AI OUTPUT NORMALIZATION
# ============================================================
def strip_markdown_fences(text: str) -> str:
    """
    Removes Markdown-style code fences that frequently break HTML rendering
    (e.g., ```html ... ```). Also trims leading/trailing whitespace.
    """
    if not text:
        return ""
    # Remove starting fences like ```html / ```HTML / ``` etc.
    text = re.sub(r"^\s*```[a-zA-Z0-9_-]*\s*\n", "", text)
    # Remove trailing fence
    text = re.sub(r"\n\s*```\s*$", "", text)
    # Remove any remaining standalone fences
    text = text.replace("```html", "").replace("```HTML", "").replace("```", "")
    return text.strip()


def looks_like_full_html_document(text: str) -> bool:
    """
    If the AI returns a complete HTML document (<!DOCTYPE html><html>...),
    we should not nest it inside another wrapper when trust_ai_html is enabled.
    """
    if not text:
        return False
    t = text.lstrip().lower()
    if "<html" in t and "</html>" in t:
        return True
    if t.startswith("<!doctype html"):
        return True
    return False


def wrap_ai_html(ai_html: str, trust_ai_html: bool) -> str:
    """
    Keeps your original safety model:
    - By default: escape AI output and show as <pre>
    - With --trust-ai-html: render raw HTML
    Additionally:
    - Strip Markdown fences
    - If trusted and AI output is full HTML doc, return it as-is.
    """
    ai_html = strip_markdown_fences(ai_html)

    if trust_ai_html and looks_like_full_html_document(ai_html):
        # Write full document as-is (no wrapper)
        return ai_html

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
    return tpl.render(body=body)

# ============================================================
# AI PROVIDERS
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


def ask_gemini(prompt: str, timeout: int = 60) -> str:
    if not GEMINI_API_KEY:
        return "<b>Gemini API key not configured.</b>"

    # Gemini Generative Language API (v1beta)
    # Endpoint format:
    # https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key=API_KEY
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    params = {"key": GEMINI_API_KEY}
    headers = {"Content-Type": "application/json"}

    payload = {
        "contents": [
            {"role": "user", "parts": [{"text": prompt}]}
        ],
        "generationConfig": {
            "temperature": TEMPERATURE,
            "maxOutputTokens": TOKEN_LIMIT,
        },
    }

    try:
        r = HTTP_SESSION.post(url, params=params, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        # Typical response: candidates[0].content.parts[0].text
        candidates = data.get("candidates") or []
        if not candidates:
            return "<b>Gemini returned no candidates.</b>"
        content = candidates[0].get("content") or {}
        parts = content.get("parts") or []
        if not parts:
            return "<b>Gemini returned empty content.</b>"
        return parts[0].get("text", "")
    except Exception as e:
        logging.error("Gemini API error: %s", e)
        return "<b>Gemini API error.</b>"


def ask_anthropic(prompt: str, timeout: int = 60) -> str:
    if not ANTHROPIC_API_KEY:
        return "<b>Anthropic API key not configured.</b>"

    # Anthropic Messages API
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": TOKEN_LIMIT,
        "temperature": TEMPERATURE,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        # content is a list of blocks; typically first is {type:"text", text:"..."}
        blocks = data.get("content") or []
        texts = []
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "text" and "text" in b:
                texts.append(b["text"])
        return "\n".join(texts).strip() if texts else "<b>Anthropic returned empty content.</b>"
    except Exception as e:
        logging.error("Anthropic API error: %s", e)
        return "<b>Anthropic API error.</b>"


def ask_replit(prompt: str, timeout: int = 60) -> str:
    if not REPLIT_API_KEY:
        return "<b>Replit API key not configured.</b>"

    # OpenAI-compatible endpoint (per your config)
    url = REPLIT_API_URL
    headers = {
        "Authorization": f"Bearer {REPLIT_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": REPLIT_MODEL,
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
        data = r.json()
        # OpenAI-like: choices[0].message.content
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error("Replit API error: %s", e)
        return "<b>Replit API error.</b>"


def ask_anythingllm(prompt: str, timeout: int = 60) -> str:
    if not (ANYTHINGLLM_API_KEY and ANYTHINGLLM_API_URL):
        return "<b>AnythingLLM API key/URL not configured.</b>"

    # AnythingLLM: chat endpoint varies by deployment. Common pattern:
    # POST {API_URL}/api/v1/workspace/{workspace}/chat
    base = ANYTHINGLLM_API_URL.rstrip("/")
    url = f"{base}/api/v1/workspace/{ANYTHINGLLM_WORKSPACE}/chat"
    headers = {
        "Authorization": f"Bearer {ANYTHINGLLM_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "message": prompt,
    }
    if ANYTHINGLLM_MODEL:
        payload["model"] = ANYTHINGLLM_MODEL

    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        # Response commonly: {"text":"..."} or {"response":"..."} depending on version.
        for k in ("text", "response", "message", "answer"):
            if k in data and isinstance(data[k], str):
                return data[k]
        # Some versions: {"data":{"text":"..."}}
        if isinstance(data.get("data"), dict):
            for k in ("text", "response", "message", "answer"):
                v = data["data"].get(k)
                if isinstance(v, str):
                    return v
        return "<b>AnythingLLM returned an unrecognized response shape.</b>"
    except Exception as e:
        logging.error("AnythingLLM API error: %s", e)
        return "<b>AnythingLLM API error.</b>"


def ask_provider(provider: str, prompt: str, timeout: int = 60) -> str:
    p = (provider or "openai").strip().lower()
    if p == "openai":
        return ask_openai(prompt, timeout=timeout)
    if p == "gemini":
        return ask_gemini(prompt, timeout=timeout)
    if p in ("anthropic", "claude"):
        return ask_anthropic(prompt, timeout=timeout)
    if p == "replit":
        return ask_replit(prompt, timeout=timeout)
    if p in ("anythingllm", "anything"):
        return ask_anythingllm(prompt, timeout=timeout)
    return f"<b>Unknown provider: {escape(provider)}</b>"

# ============================================================
# EXPORTERS
# ============================================================
def export_report_html(ai_html: str, filename: str, trust_ai_html: bool):
    html = wrap_ai_html(ai_html, trust_ai_html)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


def export_report_txt(ai_text: str, filename: str):
    ai_text = strip_markdown_fences(ai_text)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(ai_text)


def export_report_json(scan: Dict[str, Any], ai_output: str, filename: str, meta: Dict[str, Any]):
    ai_output = strip_markdown_fences(ai_output)
    payload = {
        "meta": meta,
        "scan": scan,
        "ai_output": ai_output,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def export_report_csv(scan: Dict[str, Any], ai_output: str, filename: str, meta: Dict[str, Any]):
    """
    Best-effort CSV: exports open ports and service info from parsed Nmap data.
    AI output is not converted into structured findings (that would require a schema).
    """
    import csv

    rows = []
    for host in scan.get("hosts", []):
        addr = host.get("address") or ""
        hn = (host.get("hostnames") or [""])[0]
        for p in host.get("ports", []):
            rows.append({
                "target": meta.get("target", ""),
                "host_address": addr,
                "hostname": hn,
                "protocol": p.get("protocol"),
                "port": p.get("portid"),
                "state": p.get("state"),
                "service_name": (p.get("service") or {}).get("name", ""),
                "service_product": (p.get("service") or {}).get("product", ""),
                "service_version": (p.get("service") or {}).get("version", ""),
                "service_extrainfo": (p.get("service") or {}).get("extrainfo", ""),
            })

    fieldnames = [
        "target", "host_address", "hostname",
        "protocol", "port", "state",
        "service_name", "service_product", "service_version", "service_extrainfo"
    ]

    with open(filename, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def export_report_xml(scan: Dict[str, Any], ai_output: str, filename: str, meta: Dict[str, Any]):
    """
    Best-effort XML: wraps scan JSON + AI output into a simple XML container.
    Not a replacement for native Nmap XML. This is 'report XML'.
    """
    ai_output = strip_markdown_fences(ai_output)

    root = ET.Element("ai_vulnerability_report")
    meta_el = ET.SubElement(root, "meta")
    for k, v in meta.items():
        child = ET.SubElement(meta_el, k)
        child.text = str(v)

    scan_el = ET.SubElement(root, "scan_json")
    scan_el.text = json.dumps(scan, ensure_ascii=False)

    ai_el = ET.SubElement(root, "ai_output")
    ai_el.text = ai_output

    tree = ET.ElementTree(root)
    tree.write(filename, encoding="utf-8", xml_declaration=True)

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


def resolve_nmap_args(args: argparse.Namespace) -> Tuple[str, int, bool]:
    """
    Returns (nmap_args, profile_number, used_profile)

    Important: This preserves previous behavior:
    - If user passes --nmap-args, we use it (profile ignored)
    - If user does NOT pass --nmap-args:
        - If profile is set, use profile args
        - Else fall back to legacy default args
    """
    # argparse.SUPPRESS means attribute won't exist if not provided.
    user_provided_nmap_args = hasattr(args, "nmap_args")

    profile = getattr(args, "profile", 1)
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Invalid profile {profile}. Available: {sorted(SCAN_PROFILES.keys())}")

    if user_provided_nmap_args:
        return args.nmap_args, profile, False

    # Not provided explicitly -> use profile args (default profile=1 == legacy args)
    return SCAN_PROFILES[profile], profile, True


def build_output_filename(target: str, output_format: str) -> str:
    ts = int(time.time())
    safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "_", target)
    ext = output_format.lower().strip()
    return f"{safe_target}-{ts}.{ext}"


def main():
    print_ethical_warning()
    validate_api_keys()

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--nmap-path", default=None)

    # Preserve previous default behavior, but allow detecting if user provided it:
    # - If user doesn't provide --nmap-args, we may apply -p profiles.
    # - Profile 1 is the legacy default args.
    parser.add_argument("--nmap-args", default=argparse.SUPPRESS)

    parser.add_argument("--provider", default="openai")
    parser.add_argument("--trust-ai-html", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-dl", "--debug-log", nargs="?", const="vulnscanner-debug.log")

    # NEW: Output format and scan profile (without removing any existing args)
    parser.add_argument(
        "-o", "--output",
        choices=["html", "csv", "xml", "txt", "json"],
        default="html",
        help="Output format: html, csv, xml, txt, or json (default: html)"
    )
    parser.add_argument(
        "-p", "--profile",
        type=int,
        default=1,
        help=f"Scan profile number (available: {sorted(SCAN_PROFILES.keys())}). "
             f"Used only if --nmap-args is not provided. Profile 1 matches legacy default."
    )

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

    try:
        nmap_args, profile_used, used_profile_flag = resolve_nmap_args(args)
        if used_profile_flag:
            logging.info("Using scan profile %s: %s", profile_used, nmap_args)
        else:
            logging.info("Using custom --nmap-args: %s", nmap_args)
    except Exception as e:
        logging.error("%s", e)
        sys.exit(1)

    scan = run_nmap_scan(nmap_bin, target, nmap_args)
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

    provider = args.provider
    ai_output = ask_provider(provider, prompt)
    if not ai_output:
        logging.error("AI returned empty output.")
        sys.exit(3)

    outfile = build_output_filename(target, args.output)

    meta = {
        "target": target,
        "provider": provider,
        "output_format": args.output,
        "profile": args.profile,
        "nmap_args": nmap_args,
        "trust_ai_html": bool(args.trust_ai_html),
        "timestamp": int(time.time()),
    }

    # Export based on -o / --output
    fmt = args.output.lower()
    if fmt == "html":
        export_report_html(ai_output, outfile, args.trust_ai_html)
    elif fmt == "txt":
        export_report_txt(ai_output, outfile)
    elif fmt == "json":
        export_report_json(scan, ai_output, outfile, meta)
    elif fmt == "csv":
        export_report_csv(scan, ai_output, outfile, meta)
    elif fmt == "xml":
        export_report_xml(scan, ai_output, outfile, meta)
    else:
        # argparse choices prevent this, but keep a safe fallback
        logging.error("Unsupported output format: %s", fmt)
        sys.exit(4)

    print(f"Scan complete. Output written to {outfile}")


if __name__ == "__main__":
    main()
