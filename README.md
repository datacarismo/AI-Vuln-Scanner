# AI-Vuln-Scanner

**AI-Vuln-Scanner** is a Python-based, AI-integrated vulnerability scanner that combines the power of Nmap (via `python3-nmap`), multiple leading AI models (OpenAI, Anthropic Claude, Replit AI, and AnythingLLM), and modern reporting. It performs advanced network scans, then uses AI to analyze results, prioritize risks, and suggest remediations with references to security standards (OWASP ASVS, WSTG, CAPEC, CWE).

---

## Key Features

- **Multiple AI Providers:** Supports OpenAI (GPT-4o), Gemini, Anthropic Claude, Replit AI, and AnythingLLM. User can select provider and model at runtime.
- **Scan Profiles:** Built-in scan profiles selectable via `-p`. Profile **1** matches the legacy default scan behavior. Profiles are only applied if `--nmap-args` is not provided.
- **Rich Output:** Exports to HTML, CSV, XML, TXT, or JSON (`-o`).
- **Safe-by-default HTML:** AI HTML is escaped by default. Use `--trust-ai-html` to render raw AI HTML.
- **HTML Formatting Fix:** Automatically strips Markdown code fences (``` / ```html) from AI output to avoid broken rendering in browsers. If the AI returns a full HTML document and `--trust-ai-html` is enabled, it is written directly (not nested).
- **Risk Prioritization & Remediation:** AI provides severity, rationale, and actionable remediation for each finding.
- **Debug Mode:** Use `-d` to see detailed debug logs and scan commands; use `-dl` to write debug logs to a file.
- **Interactive & Scriptable:** All options can be provided via command line.

---

## Installation

1. **Install Python 3.x**  
   [Download Python](https://www.python.org/downloads/)

2. **Clone this repository:**
    ```
    git clone https://github.com/davidfortytwo/AI-Vuln-Scanner.git
    cd AI-Vuln-Scanner
    ```

3. **Install dependencies:**
    ```
    pip install -r requirements.txt
    ```

4. **Configure your `.env` file:**  
   Copy `.env-example` to `.env` and fill in your API keys as needed:

    ```
    cp .env-example .env
    # Edit .env with your keys and endpoints
    ```

---

## Configuration

**.env-example:**
  ```
  OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  
  GEMINI_API_KEY=your_gemini_api_key
  
  ANYTHINGLLM_API_KEY=your_anythingllm_api_key
  
  ANYTHINGLLM_API_URL=http://localhost:3001
  
  ANTHROPIC_API_KEY=your_anthropic_api_key
  
  REPLIT_API_KEY=your_replit_api_key
  
  REPLIT_API_URL=https://chat.replit.com/v1/chat/completions
  ```

- Set only the providers you want to use.  
- If multiple are set, you can select the provider via `--provider`.

---

## Usage

### Basic Example

  python vulnscanner.py -t target_ip_or_hostname -o output_format


- `-t` Target IP or hostname (required)
- `-o` Output format: html, csv, xml, txt, or json (default: html)
- `-p` Scan profile number (see below)
- `--provider` AI provider: openai, gemini, anthropic, replit, anythingllm
- `--trust-ai-html` Render AI output as raw HTML (otherwise escaped)
- `-d` Enable debug mode (verbose output)
- `-dl` Enable debug log file output

### Example: Fast Scan with OpenAI
  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 1
  ```

### Example: Debug Mode
  ```
  python vulnscanner.py -t 192.168.1.1 -o json -p 2 -d -dl
  ```

### Example: Using Anthropic Claude

Set your `ANTHROPIC_API_KEY` in `.env` and run:

  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 2 --provider anthropic
  ```

### Example: Using Gemini

Set your `GEMINI_API_KEY` in `.env` and run:

  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 2 --provider gemini
  ```

### Example: Using AnythingLLM

Set `ANYTHINGLLM_API_KEY` and `ANYTHINGLLM_API_URL` in `.env` and run:

  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 2 --provider anythingllm
  ```

### Example: Trusted AI HTML Rendering

  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 1 --trust-ai-html
  ```

---

## Scan Profiles

You can select from the following scan profiles (shown in help and at runtime):

1. Legacy fast scan (matches previous default `--nmap-args`)
2. Full TCP scan with default scripts and version detection
3. TCP + UDP top ports (balanced)
4. Very fast scan (aggressive timing)

> Note: Profiles are only used if you do **not** provide `--nmap-args`. If `--nmap-args` is specified, it overrides profiles.

---

## Output

- Results are displayed in the terminal and saved to a timestamped file in your chosen format.
- Each finding includes (AI-dependent):  
  - Vulnerability description  
  - Affected endpoint  
  - Evidence  
  - Severity rating and rationale  
  - Remediation steps  
  - References to common security standards (OWASP/CWE/CAPEC)

---

## Debug Mode

Add `-d` to any command to enable debug output.  
Add `-dl` to also write to a log file.

This will show:
- The actual nmap command being run
- All intermediate data (scan results, AI prompts, etc.)
- API provider/model selection and responses

---

## Multi-AI Support

The scanner supports:
- **OpenAI (GPT-4o and compatible)**
- **Gemini**
- **AnythingLLM** (self-hosted, supports many models)
- **Anthropic Claude**
- **Replit AI**

You can set up one or more providers in your `.env` file and select at runtime via `--provider`.

---

## Disclaimer of Liability

The AI-Integrated Vulnerability Scanner is provided as-is, without any guarantees or warranties, either express or implied. By using this tool, you acknowledge that you are solely responsible for any consequences that may arise from its usage.

The tool is intended for educational purposes, ethical security assessments, and to help you identify potential vulnerabilities in your network or systems. It is strictly prohibited to use the AI-Integrated Vulnerability Scanner for malicious activities, unauthorized access, or any other illegal activities.

By using the AI-Integrated Vulnerability Scanner, you agree to assume full responsibility for your actions and the results generated by the tool. The developers and contributors of this project shall not be held liable for any damages or losses, whether direct, indirect, incidental, or consequential, arising from the use or misuse of this tool.

It is your responsibility to ensure that you have the proper authorization and consent before scanning any network or system. You must also comply with all applicable laws, regulations, and ethical guidelines related to network scanning and vulnerability assessment.

By using the AI-Integrated Vulnerability Scanner, you acknowledge and accept the terms stated in this Disclaimer of Liability. If you do not agree with these terms, you must not use this tool.

---

**Enjoy advanced, AI-powered vulnerability scanning!**  
For questions, feature requests, or contributions, please open an issue or PR.

