"""
AI Cybersecurity Copilot - Advanced FastAPI Backend

Features
--------
1. /health health check for the Streamlit frontend.
2. /analyze accepts a log file and performs advanced rule-based detection.
3. Optional Hugging Face Inference Providers LLM analysis for explanation/correlation.
4. No Hugging Face dependency.
5. LLM is an explanation/correlation layer; deterministic detections remain
   the source of security findings.

Environment variables
---------------------
HF_TOKEN        Optional. If missing, the backend still works with rules.
HF_MODEL        Optional. Default: meta-llama/Llama-3.1-8B-Instruct
MAX_LOG_LINES    Optional. Default: 20000
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

try:
    from huggingface_hub import InferenceClient
except ImportError:
    InferenceClient = None


app = FastAPI(
    title="AI Cybersecurity Copilot Backend",
    version="2.0.0",
    description="Advanced log detection with optional LLM-assisted analysis.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HF_TOKEN = os.getenv("HF_TOKEN", "").strip()
HF_MODEL = os.getenv(
    "HF_MODEL",
    "meta-llama/Llama-3.1-8B-Instruct"
).strip()
MAX_LOG_LINES = int(os.getenv("MAX_LOG_LINES", "20000"))

llm_client = None
if HF_TOKEN:
    try:
        from huggingface_hub import InferenceClient
        llm_client = InferenceClient(
            api_key=HF_TOKEN,
            provider="auto",
        )
    except Exception:
        llm_client = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "AI Cybersecurity Copilot Backend",
        "version": "2.0.0",
        "llm_enabled": llm_client is not None,
        "llm_provider": "Hugging Face Inference Providers" if llm_client is not None else None,
        "llm_model": HF_MODEL if llm_client is not None else None,
    }


@app.get("/")
def root():
    return {
        "message": "AI Cybersecurity Copilot Backend is running",
        "version": "2.0.0",
        "health": "/health",
        "analyze": "POST /analyze",
        "llm_enabled": llm_client is not None,
        "llm_provider": "Hugging Face Inference Providers" if llm_client is not None else None,
        "llm_model": HF_MODEL if llm_client is not None else None,
    }


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Common/combined log style:
# 1.2.3.4 - - [date] "GET /path HTTP/1.1" 404 123
HTTP_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[0-9.]+)?"\s+'
    r'(?P<status>\d{3})',
    re.IGNORECASE,
)

# Timestamp formats commonly found in logs.
TIMESTAMP_PATTERNS = [
    re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:[^\]]+)\]"),
    re.compile(r"\[(\d{4}-\d{2}-\d{2}[^\]]+)\]"),
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+)"),
]

SQLI_RE = re.compile(
    r"(?:union\s+(?:all\s+)?select|"
    r"or\s+1\s*=\s*1|"
    r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1|"
    r"sleep\s*\(|benchmark\s*\(|"
    r"information_schema|"
    r"xp_cmdshell|"
    r"load_file\s*\(|"
    r"waitfor\s+delay)",
    re.IGNORECASE,
)

XSS_RE = re.compile(
    r"(?:<script\b|javascript\s*:|onerror\s*=|onload\s*=|"
    r"<iframe\b|document\.cookie|alert\s*\()",
    re.IGNORECASE,
)

TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e)",
    re.IGNORECASE,
)

COMMAND_RE = re.compile(
    r"(?:;\s*(?:cat|id|whoami|uname|wget|curl|bash|sh)\b|"
    r"\|\s*(?:bash|sh|nc|netcat)\b|"
    r"\b(?:cmd\.exe|powershell(?:\.exe)?)\b|"
    r"\$\((?:id|whoami|uname|curl|wget)\b)",
    re.IGNORECASE,
)

SENSITIVE_PATH_RE = re.compile(
    r"(?:/\.env(?:\b|/)|"
    r"/\.git(?:\b|/)|"
    r"/etc/passwd\b|"
    r"/etc/shadow\b|"
    r"/wp-config\.php\b|"
    r"/config(?:\.php)?\b|"
    r"/phpmyadmin\b|"
    r"/server-status\b|"
    r"/actuator/(?:env|heapdump|mappings)\b)",
    re.IGNORECASE,
)

SCANNER_AGENT_RE = re.compile(
    r"(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|"
    r"ffuf|wpscan|acunetix|nessus|openvas|burp|zap)",
    re.IGNORECASE,
)

AUTOMATION_AGENT_RE = re.compile(
    r"(?:python-requests|python-urllib|scrapy|go-http-client|"
    r"libwww-perl|curl/|wget/)",
    re.IGNORECASE,
)

AUTH_FAILURE_RE = re.compile(
    r"(?:401|403|invalid\s+(?:user|username|password|credential)|"
    r"authentication\s+failed|login\s+failed|failed\s+login|"
    r"access\s+denied)",
    re.IGNORECASE,
)

ERROR_RE = re.compile(
    r"(?:\b500\b|\b502\b|\b503\b|internal\s+server\s+error|"
    r"exception|traceback|stack\s+trace)",
    re.IGNORECASE,
)


def extract_timestamp(line: str) -> str | None:
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


def extract_http(line: str) -> dict[str, Any] | None:
    match = HTTP_RE.search(line)
    if not match:
        return None

    return {
        "ip": match.group("ip"),
        "method": match.group("method").upper(),
        "path": match.group("path"),
        "status": int(match.group("status")),
    }


def safe_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(x) <= 255 for x in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Advanced deterministic detection
# ---------------------------------------------------------------------------

def analyze_logs(text: str) -> dict[str, Any]:
    raw_lines = [line.strip() for line in text.splitlines() if line.strip()]
    truncated = len(raw_lines) > MAX_LOG_LINES
    lines = raw_lines[:MAX_LOG_LINES]

    requests_count = 0
    status_counts = Counter()
    method_counts = Counter()
    ip_counts = Counter()
    ip_failed = Counter()
    ip_paths = defaultdict(set)
    ip_statuses = defaultdict(Counter)

    findings: list[dict[str, Any]] = []
    seen_finding_keys: set[str] = set()

    detection_counts = Counter()
    suspicious_ips: set[str] = set()
    suspicious_paths: set[str] = set()

    failed_login_count = 0
    sql_injection_count = 0
    xss_count = 0
    traversal_count = 0
    command_injection_count = 0
    sensitive_path_count = 0
    scanner_agent_count = 0
    server_error_count = 0

    def add_finding(
        severity: str,
        title: str,
        detail: str,
        evidence: list[str] | None = None,
        ip: str | None = None,
    ):
        key = f"{severity}|{title}|{ip or ''}|{detail}"
        if key in seen_finding_keys:
            return

        seen_finding_keys.add(key)
        findings.append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": (evidence or [])[:5],
            "source": "rule-engine",
        })

    evidence_by_detection: dict[str, list[str]] = defaultdict(list)

    for line in lines:
        parsed = extract_http(line)

        ips = [ip for ip in IP_RE.findall(line) if safe_ip(ip)]
        for ip in ips:
            ip_counts[ip] += 1

        lower = line.lower()

        if parsed:
            requests_count += 1
            ip = parsed["ip"]
            path = parsed["path"]
            status = parsed["status"]
            method = parsed["method"]

            status_counts[status] += 1
            method_counts[method] += 1
            ip_paths[ip].add(path)
            ip_statuses[ip][status] += 1

            if status in (401, 403):
                failed_login_count += 1
                ip_failed[ip] += 1

        # Authentication failures even when the line is not standard HTTP.
        if AUTH_FAILURE_RE.search(line) and not parsed:
            failed_login_count += 1
            for ip in ips:
                ip_failed[ip] += 1

        if SQLI_RE.search(line):
            sql_injection_count += 1
            detection_counts["sql_injection"] += 1
            evidence_by_detection["sql_injection"].append(line)
            suspicious_ips.update(ips)

        if XSS_RE.search(line):
            xss_count += 1
            detection_counts["xss"] += 1
            evidence_by_detection["xss"].append(line)
            suspicious_ips.update(ips)

        if TRAVERSAL_RE.search(line):
            traversal_count += 1
            detection_counts["path_traversal"] += 1
            evidence_by_detection["path_traversal"].append(line)
            suspicious_ips.update(ips)

        if COMMAND_RE.search(line):
            command_injection_count += 1
            detection_counts["command_injection"] += 1
            evidence_by_detection["command_injection"].append(line)
            suspicious_ips.update(ips)

        if SENSITIVE_PATH_RE.search(line):
            sensitive_path_count += 1
            detection_counts["sensitive_path"] += 1
            evidence_by_detection["sensitive_path"].append(line)
            suspicious_ips.update(ips)

            if parsed:
                suspicious_paths.add(parsed["path"])

        if SCANNER_AGENT_RE.search(line):
            scanner_agent_count += 1
            detection_counts["scanner_agent"] += 1
            evidence_by_detection["scanner_agent"].append(line)
            suspicious_ips.update(ips)

        if ERROR_RE.search(line):
            server_error_count += 1

        if AUTOMATION_AGENT_RE.search(line):
            detection_counts["automation_agent"] += 1
            evidence_by_detection["automation_agent"].append(line)

    # Per-IP behavioral findings.
    high_volume = sorted(
        [(ip, count) for ip, count in ip_counts.items() if count >= 100],
        key=lambda x: x[1],
        reverse=True,
    )

    for ip, count in high_volume[:5]:
        suspicious_ips.add(ip)
        add_finding(
            "medium",
            "High request volume",
            f"{ip} generated {count} requests in the supplied log window.",
            ip=ip,
        )

    for ip, count in ip_failed.most_common(10):
        if count >= 5:
            suspicious_ips.add(ip)
            severity = "high" if count >= 20 else "medium"
            add_finding(
                severity,
                "Repeated authentication failures",
                f"{ip} generated {count} authentication failure(s).",
                ip=ip,
            )

    for ip, paths in sorted(
        ip_paths.items(), key=lambda x: len(x[1]), reverse=True
    )[:10]:
        if len(paths) >= 20:
            suspicious_ips.add(ip)
            add_finding(
                "medium",
                "Possible directory/path enumeration",
                f"{ip} requested {len(paths)} unique paths.",
                ip=ip,
            )

    # Specific attack findings.
    if sql_injection_count:
        add_finding(
            "high",
            "Possible SQL injection",
            f"{sql_injection_count} request(s) matched SQL injection indicators.",
            evidence_by_detection["sql_injection"],
        )

    if xss_count:
        add_finding(
            "high",
            "Possible cross-site scripting (XSS)",
            f"{xss_count} request(s) matched common XSS payload indicators.",
            evidence_by_detection["xss"],
        )

    if traversal_count:
        add_finding(
            "high",
            "Possible path traversal",
            f"{traversal_count} request(s) contained path traversal indicators.",
            evidence_by_detection["path_traversal"],
        )

    if command_injection_count:
        add_finding(
            "critical",
            "Possible command injection",
            f"{command_injection_count} request(s) matched command-injection indicators.",
            evidence_by_detection["command_injection"],
        )

    if sensitive_path_count:
        add_finding(
            "high",
            "Sensitive file or administrative endpoint probing",
            f"{sensitive_path_count} request(s) targeted sensitive paths or administrative endpoints.",
            evidence_by_detection["sensitive_path"],
        )

    if scanner_agent_count:
        add_finding(
            "medium",
            "Security scanner or automated reconnaissance",
            f"{scanner_agent_count} request(s) used a known scanning/security-tool user agent.",
            evidence_by_detection["scanner_agent"],
        )

    if server_error_count >= 10:
        add_finding(
            "medium",
            "Elevated server errors",
            f"{server_error_count} line(s) matched server-error indicators.",
        )

    # If many 404s exist, this can indicate enumeration.
    not_found_count = status_counts.get(404, 0)
    if not_found_count >= 20:
        add_finding(
            "medium",
            "High number of HTTP 404 responses",
            f"{not_found_count} HTTP 404 responses were detected; this may indicate path enumeration or broken clients.",
        )

    # Failed-login aggregate.
    if failed_login_count >= 20:
        add_finding(
            "high",
            "Possible brute-force activity",
            f"{failed_login_count} authentication failure(s) were detected.",
        )
    elif failed_login_count >= 5:
        add_finding(
            "medium",
            "Repeated authentication failures",
            f"{failed_login_count} authentication failure(s) were detected.",
        )

    if not findings:
        add_finding(
            "low",
            "No major suspicious pattern detected",
            "The supplied logs did not match the current high-confidence detection rules.",
        )

    # Risk calculation.
    severity_weight = {
        "low": 1,
        "medium": 3,
        "high": 6,
        "critical": 10,
    }

    score = sum(
        severity_weight.get(f["severity"], 0)
        for f in findings
    )

    if score >= 10 or any(f["severity"] == "critical" for f in findings):
        risk_level = "critical"
    elif score >= 6:
        risk_level = "high"
    elif score >= 3:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Recommendations based on actual findings.
    recommendations = []

    if failed_login_count:
        recommendations.append(
            "Rate-limit authentication endpoints and consider account lockout or CAPTCHA after repeated failures."
        )
        recommendations.append(
            "Enable multi-factor authentication for administrator and sensitive accounts."
        )

    if sql_injection_count:
        recommendations.append(
            "Use parameterized queries/prepared statements and validate server-side input."
        )

    if xss_count:
        recommendations.append(
            "Apply context-aware output encoding, input validation, and an appropriate Content Security Policy."
        )

    if traversal_count or sensitive_path_count:
        recommendations.append(
            "Block direct access to sensitive files and normalize/validate paths before file operations."
        )

    if command_injection_count:
        recommendations.append(
            "Avoid shell execution with user-controlled input and use strict allowlists for command parameters."
        )

    if scanner_agent_count or not_found_count >= 20:
        recommendations.append(
            "Review reconnaissance traffic and apply rate limiting, WAF rules, or network controls where appropriate."
        )

    if not recommendations:
        recommendations.append(
            "Continue monitoring logs and keep authentication, application, and server components patched."
        )

    # Human-readable summary before LLM enhancement.
    summary = build_rule_summary(
        risk_level=risk_level,
        requests_count=requests_count,
        failed_logins=failed_login_count,
        suspicious_ip_count=len(suspicious_ips),
        sql_injection_count=sql_injection_count,
        xss_count=xss_count,
        traversal_count=traversal_count,
        command_injection_count=command_injection_count,
        sensitive_path_count=sensitive_path_count,
    )

    result = {
        "risk_level": risk_level,
        "summary": summary,
        "stats": {
            "requests": requests_count,
            "failed_logins": failed_login_count,
            "suspicious_ips": len(suspicious_ips),
            "sql_injection_attempts": sql_injection_count,
            "xss_attempts": xss_count,
            "path_traversal_attempts": traversal_count,
            "command_injection_attempts": command_injection_count,
            "sensitive_path_attempts": sensitive_path_count,
            "scanner_requests": scanner_agent_count,
            "server_errors": server_error_count,
        },
        "findings": findings,
        "recommendations": recommendations,
        "metadata": {
            "lines_analyzed": len(lines),
            "lines_received": len(raw_lines),
            "truncated": truncated,
            "methods": dict(method_counts),
            "status_codes": {
                str(k): v for k, v in status_counts.items()
            },
            "llm_enabled": llm_client is not None,
            "llm_model": HF_MODEL if llm_client is not None else None,
            "llm_provider": "Hugging Face Inference Providers",
        },
    }

    # LLM provides explanation/correlation, not the raw security detection.
    if llm_client is not None:
        llm = generate_llm_analysis(result, lines)

        if llm:
            if llm.get("summary"):
                result["summary"] = llm["summary"]

            if isinstance(llm.get("recommendations"), list):
                result["recommendations"] = unique_strings(
                    result["recommendations"] + llm["recommendations"]
                )[:8]

            if isinstance(llm.get("additional_insights"), list):
                result["ai_insights"] = [
                    str(x) for x in llm["additional_insights"][:8]
                ]

            result["metadata"]["llm_used"] = True
        else:
            result["metadata"]["llm_used"] = False
    else:
        result["metadata"]["llm_used"] = False

    return result


def build_rule_summary(
    risk_level: str,
    requests_count: int,
    failed_logins: int,
    suspicious_ip_count: int,
    sql_injection_count: int,
    xss_count: int,
    traversal_count: int,
    command_injection_count: int,
    sensitive_path_count: int,
) -> str:
    attacks = []

    if sql_injection_count:
        attacks.append(f"{sql_injection_count} possible SQL injection")
    if xss_count:
        attacks.append(f"{xss_count} possible XSS")
    if traversal_count:
        attacks.append(f"{traversal_count} possible path traversal")
    if command_injection_count:
        attacks.append(f"{command_injection_count} possible command injection")
    if sensitive_path_count:
        attacks.append(f"{sensitive_path_count} sensitive-path probe")

    attack_text = ""
    if attacks:
        attack_text = " Detected indicators include " + ", ".join(attacks) + "."

    return (
        f"{risk_level.upper()} risk was assessed from {requests_count} request(s). "
        f"{failed_logins} authentication failure(s) and "
        f"{suspicious_ip_count} suspicious IP(s) were identified."
        + attack_text
    )


def unique_strings(values: list[str]) -> list[str]:
    result = []
    seen = set()

    for value in values:
        value = str(value).strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


# ---------------------------------------------------------------------------
# LLM layer
# ---------------------------------------------------------------------------

def generate_llm_analysis(
    result: dict[str, Any],
    lines: list[str],
) -> dict[str, Any] | None:
    """
    Ask the LLM to explain and correlate already-detected evidence.

    The model is explicitly instructed not to invent incidents or override
    deterministic findings.
    """
    if llm_client is None:
        return None

    # Keep prompts reasonably small.
    evidence_lines = lines[:250]

    payload = {
        "risk_level": result["risk_level"],
        "stats": result["stats"],
        "findings": result["findings"],
        "recommendations": result["recommendations"],
        "log_samples": evidence_lines,
    }

    system_prompt = """
You are a cybersecurity SOC analyst assisting a log-analysis application.

Your job is to explain and correlate evidence already detected by a deterministic
security engine. Do not invent IP addresses, attacks, timestamps, credentials,
or events. Do not claim certainty when the evidence only indicates a possibility.

Return ONLY valid JSON with this schema:
{
  "summary": "short plain-English summary",
  "recommendations": ["action 1", "action 2"],
  "additional_insights": ["insight 1", "insight 2"]
}

Rules:
- Preserve the severity/risk assessment from the rule engine.
- Do not remove or downgrade deterministic findings.
- Clearly use words such as "possible", "indicates", or "may" when appropriate.
- Focus on attack patterns, correlations, affected endpoints, and defensive actions.
- Never output secrets, API keys, passwords, or authentication tokens found in logs.
"""

    try:
        response = llm_client.chat.completions.create(
            model=HF_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(payload, ensure_ascii=False),
                },
            ],
            temperature=0.1,
            max_tokens=800,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        if not content:
            return None

        # Some providers/models may wrap JSON in markdown fences.
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content)

        parsed = json.loads(content)

        if not isinstance(parsed, dict):
            return None

        return parsed

    except Exception:
        # Security analysis should continue even if the optional LLM fails.
        return None


# ---------------------------------------------------------------------------
# Analyze endpoint
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    data = await file.read()

    text = data.decode("utf-8", errors="replace")

    result = analyze_logs(text)

    result["metadata"]["filename"] = file.filename
    result["metadata"]["content_type"] = file.content_type

    return result
