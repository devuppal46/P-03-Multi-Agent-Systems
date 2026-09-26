"""
rca_agent.py — LLM-Powered Root Cause Analysis Synthesizer

Final step in the audit pipeline.  Takes the complete blackboard snapshot,
trace events and critic verdict, then asks Gemini to synthesize a
human-readable incident report formatted as a Slack Block Kit payload.

Environment variable
────────────────────
    GEMINI_API_KEY  — your Google AI Studio / Gemini API key.
    If not set, synthesize() returns a graceful fallback so the pipeline
    is never blocked.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

from google import genai
from google.genai import types as genai_types

GEMINI_MODEL = "gemini-1.5-flash"
_MAX_RETRIES = 2

_SYSTEM_PROMPT = """You are a senior Site Reliability Engineer (SRE) writing an automated incident report.
You will receive JSON data from a domain health audit that ran four independent checks:
  • DNS      — did the domain resolve? Which resolver was used?
  • Uptime   — is the site reachable over HTTPS/HTTP? What HTTP status?
  • TLS Cert — is the certificate valid? How many days until expiry?
  • RDAP     — is domain registration active? How many days until expiry?

Your task: synthesize this raw audit data into a crisp, actionable incident report.

RESPOND WITH ONLY A VALID JSON OBJECT. No markdown, no code fences, no extra text.
Use this exact schema:
{
  "summary": "Alert title in 12 words or fewer. Like a PagerDuty subject line.",
  "narrative": "2-4 sentences. Cite specific values (HTTP codes, days, IPs, resolver names). Explain what is failing or healthy and why. Write for an on-call engineer with 30 seconds to read.",
  "root_cause": "One sentence starting with 'Root cause is likely...' or 'No issues detected.' if all healthy.",
  "confidence": "high | medium | low",
  "recommended_actions": [
    "3-4 concrete, specific steps. NOT generic. Use exact values from the data."
  ],
  "severity": "P1 | P2 | P3 | P4",
  "severity_reason": "One sentence explaining the severity rating."
}

Severity guide:
  P1 — service is down or TLS cert has expired  (immediate response needed)
  P2 — degraded or expiring soon (<30 days)     (respond within the hour)
  P3 — minor degradation or warning             (respond next business day)
  P4 — all checks passed, domain is healthy     (no action needed)

Rules:
  • Be specific: use exact numbers from the data (e.g. "cert expires in 8 days", "HTTP 403")
  • If multiple checks failed, prioritise the highest-impact one as root cause
  • If DNS fell back to a secondary resolver, mention it — it signals fragility
  • If P4 (all healthy), write a positive confirmation, not an incident report
"""

def synthesize(
    domain: str,
    blackboard: dict,
    trace_events: list,
    verdict: dict,
    elapsed_s: float,
    api_key: str | None = None,
) -> dict:
    """
    Call Gemini to generate a structured RCA from audit data.

    Always returns a dict with keys:
        summary, narrative, root_cause, confidence,
        recommended_actions, severity, severity_reason,
        model, latency_ms, slack_payload

    On any failure returns a graceful fallback — the pipeline is never blocked.
    """
    key = api_key or os.environ.get("GEMINI_API_KEY", "")
    if not key:
        return _fallback(domain, verdict, elapsed_s,
                         reason="GEMINI_API_KEY not set — add it in the sidebar or set the env var")

    client = genai.Client(api_key=key)

    audit_summary = _build_audit_summary(domain, blackboard, trace_events, verdict, elapsed_s)
    user_message  = (
        f"Domain audited: {domain}\n\n"
        f"Audit data:\n{json.dumps(audit_summary, indent=2, default=str)}"
    )

    last_error = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            t0 = time.time()
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=[_SYSTEM_PROMPT, user_message],
                config=genai_types.GenerateContentConfig(
                    temperature=0.15,
                    max_output_tokens=1024,
                ),
            )
            latency_ms = round((time.time() - t0) * 1000)
            raw = response.text.strip()

            if raw.startswith("```"):
                lines = raw.split("\n")
                raw = "\n".join(
                    lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
                )

            parsed               = json.loads(raw)
            parsed["model"]      = GEMINI_MODEL
            parsed["latency_ms"] = latency_ms
            parsed["slack_payload"] = _build_slack_payload(domain, parsed, verdict, elapsed_s)
            return parsed

        except json.JSONDecodeError as exc:
            last_error = f"LLM returned non-JSON response: {exc}"
        except Exception as exc:
            last_error = f"Gemini API error: {exc}"
            if attempt < _MAX_RETRIES:
                time.sleep(1.5 * (attempt + 1))

    return _fallback(domain, verdict, elapsed_s, reason=last_error or "exhausted retries")

def _build_audit_summary(domain, blackboard, trace_events, verdict, elapsed_s):
    dns    = blackboard.get("dns", {}) or {}
    uptime = blackboard.get("uptime", {}) or {}
    cert   = blackboard.get("cert", {}) or {}
    rdap   = blackboard.get("rdap", {}) or {}

    total_retries   = sum(e.get("retries", 0) for e in trace_events)
    degraded_agents = [
        e.get("agent", "?") for e in trace_events
        if e.get("status") in ("failed", "retry", "degraded", "retrying")
    ]

    return {
        "domain":              domain,
        "audit_timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "elapsed_seconds":     elapsed_s,
        "overall_verdict":     verdict,
        "checks": {
            "dns": {
                "resolved":        dns.get("resolved"),
                "ip_addresses":    dns.get("addresses", []),
                "resolver_used":   dns.get("resolver", "cloudflare"),
                "dns_status_code": dns.get("status_code"),
            },
            "uptime": {
                "reachable":        uptime.get("reachable"),
                "http_status_code": uptime.get("status_code"),
                "scheme_used":      uptime.get("scheme"),
                "final_url":        uptime.get("final_url"),
            },
            "tls_certificate": {
                "check_attempted":     cert.get("checked"),
                "days_until_expiry":   cert.get("days_left"),
                "expiry_date":         cert.get("expires"),
                "certificate_expired": (
                    cert.get("days_left", 1) < 0
                    if cert.get("days_left") is not None else None
                ),
            },
            "domain_registration_rdap": {
                "record_found":      rdap.get("found"),
                "days_until_expiry": rdap.get("days_left"),
                "queried_apex":      rdap.get("queried_apex", domain),
                "error":             rdap.get("error"),
            },
        },
        "agent_reliability": {
            "total_retries":                  total_retries,
            "agents_that_retried_or_failed":  list(set(degraded_agents)),
        },
    }


def _build_slack_payload(domain, rca, verdict, elapsed_s):
    """
    Assemble a Slack Block Kit payload. LLM provides content;
    Python assembles the schema so it is always syntactically valid.
    """
    severity  = rca.get("severity", "P3")
    risk      = verdict.get("risk", "unknown").upper()
    emoji_map = {"P1": "🔴", "P2": "🟡", "P3": "🔵", "P4": "🟢"}
    sev_color = {"P1": "#FF4136", "P2": "#FFDC00", "P3": "#0074D9", "P4": "#2ECC40"}
    emoji     = emoji_map.get(severity, "⚪")

    actions_mrkdwn  = "\n".join(f"• {a}" for a in rca.get("recommended_actions", []))
    findings_mrkdwn = "\n".join(
        f"• {f}" for f in verdict.get("findings", ["No findings recorded."])
    )

    return {
        "attachments": [
            {
                "color": sev_color.get(severity, "#AAAAAA"),
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} [{severity}] {rca.get('summary', 'Domain Audit Alert')}",
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Domain*\n`{domain}`"},
                            {"type": "mrkdwn", "text": f"*Overall Risk*\n`{risk}`"},
                            {"type": "mrkdwn", "text": f"*Severity*\n`{severity}`"},
                            {"type": "mrkdwn", "text": f"*Elapsed*\n{elapsed_s}s"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*📋 Narrative*\n"
                                f"{rca.get('narrative', '_No narrative generated._')}"
                            ),
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*🔍 Root Cause*\n{rca.get('root_cause', '_Unknown_')}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*🤖 Critic Findings*\n{findings_mrkdwn}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*✅ Recommended Actions*\n{actions_mrkdwn}",
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"Confidence: *{rca.get('confidence', '?')}* | "
                                    f"Model: `{rca.get('model', 'gemini')}` | "
                                    f"RCA latency: {rca.get('latency_ms', '?')}ms | "
                                    f"Generated: {datetime.now(timezone.utc).strftime('%H:%M UTC')}"
                                ),
                            }
                        ],
                    },
                ],
            }
        ]
    }


def _fallback(domain, verdict, elapsed_s, reason):
    """Minimal RCA returned when Gemini is unavailable."""
    risk     = verdict.get("risk", "unknown")
    findings = verdict.get("findings", [])
    sev_map  = {"high": "P1", "medium": "P2", "low": "P4", "unknown": "P3"}
    severity = sev_map.get(risk, "P3")

    rca = {
        "summary":      f"Domain audit complete — {domain} risk={risk.upper()}",
        "narrative":    "Automated RCA synthesis unavailable. Critic findings: " + "; ".join(findings) + ".",
        "root_cause":   "Root cause: see critic findings above.",
        "confidence":   "low",
        "recommended_actions": [
            "Review the critic findings in the trace above.",
            "Re-run the audit to ensure full coverage.",
            "Set GEMINI_API_KEY to enable LLM synthesis.",
        ],
        "severity":        severity,
        "severity_reason": f"Fallback severity based on critic risk={risk}. ({reason})",
        "model":           "fallback",
        "latency_ms":      0,
        "error":           reason,
    }
    rca["slack_payload"] = _build_slack_payload(domain, rca, verdict, elapsed_s)
    return rca
