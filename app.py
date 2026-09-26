"""
app.py — Domain Guardian Web UI Backend

FastAPI server that:
  • Serves index.html at the root
  • Streams audit trace events via SSE  (GET /audit/{run_id}/stream)
  • Accepts human approval/deny         (POST /audit/{run_id}/approve)
  • Runs a batch harness                (POST /batch)

To swap the mock generator for the real one:
  1. Import your generator:
       from domain_guardian.orchestrator import run_domain_audit
  2. Replace `_mock_audit_generator(run_id)` calls in `_sse_wrapper` with
       run_domain_audit(state["domain"], chaos=state["chaos"])
  3. Yield events in the same dict shape this mock uses.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
import uuid
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="Domain Guardian UI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="."), name="static")


@app.get("/")
async def serve_index():
    return FileResponse("index.html")


# ── In-memory run state ───────────────────────────────────────────────────────

runs: dict[str, dict] = {}
# Shape of each run:
# {
#   "domain":          str,
#   "chaos":           str,          # "none" | "dns_timeout" | "cert_expired"
#   "start_ts":        float,
#   "steps":           int,
#   "approval_event":  asyncio.Event,
#   "approval_action": str | None,   # "approve" | "deny"
#   "blackboard":      dict,
# }


# ── Request / Response models ─────────────────────────────────────────────────

class AuditRequest(BaseModel):
    domain: str
    chaos: str = "none"


class ApproveRequest(BaseModel):
    action: str  # "approve" | "deny"


class BatchRequest(BaseModel):
    domains: list[str]
    repeats: int = 3


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/audit")
async def start_audit(req: AuditRequest):
    run_id = str(uuid.uuid4())[:8]
    runs[run_id] = {
        "domain":          req.domain,
        "chaos":           req.chaos,
        "start_ts":        time.time(),
        "steps":           0,
        "approval_event":  asyncio.Event(),
        "approval_action": None,
        "blackboard":      {},
    }
    return {"run_id": run_id}


@app.get("/audit/{run_id}/stream")
async def stream_audit(run_id: str):
    if run_id not in runs:
        raise HTTPException(status_code=404, detail="run not found")
    return StreamingResponse(
        _sse_wrapper(run_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/audit/{run_id}/approve")
async def approve_audit(run_id: str, req: ApproveRequest):
    if run_id not in runs:
        raise HTTPException(status_code=404, detail="run not found")
    if req.action not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="action must be approve or deny")
    state = runs[run_id]
    state["approval_action"] = req.action
    state["approval_event"].set()
    return {"status": "ok"}


@app.post("/batch")
async def run_batch(req: BatchRequest):
    """Dummy batch harness — replace body with real batch logic."""
    await asyncio.sleep(0.3)
    results = []
    for domain in req.domains:
        for r in range(req.repeats):
            results.append({
                "domain":      domain,
                "repeat":      r + 1,
                "verdict":     random.choice(["healthy", "degraded", "at_risk"]),
                "steps":       random.randint(4, 12),
                "latency_ms":  random.randint(800, 4000),
                "completed":   random.random() > 0.1,
            })

    completed   = sum(1 for r in results if r["completed"])
    total       = len(results)
    avg_latency = sum(r["latency_ms"] for r in results) / total if total else 0

    return {
        "total_runs":      total,
        "completed":       completed,
        "completion_rate": round(completed / total, 3) if total else 0,
        "avg_latency_ms":  round(avg_latency, 1),
        "verdicts":        results,
    }


# ── SSE helpers ───────────────────────────────────────────────────────────────

def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


async def _sse_wrapper(run_id: str) -> AsyncGenerator[str, None]:
    """
    Thin wrapper: drives the mock generator and serialises every event to SSE.
    SWAP POINT — replace `_mock_audit_generator` with `run_domain_audit`.
    """
    async for event in _mock_audit_generator(run_id):
        yield _sse_event(event)


# ── Mock audit generator ──────────────────────────────────────────────────────
# Each yielded dict shape:
# {
#   "type":       "trace" | "blackboard_update" | "requires_approval"
#                 | "approved" | "denied" | "verdict",
#   "agent":      str,
#   "tool":       str,
#   "status":     "ok" | "degraded" | "failed" | "retrying",
#   "rationale":  str,
#   "latency_ms": int,
#   "retries":    int,
#   "step":       int,
#   "elapsed_s":  float,
#   "blackboard": dict,   # on blackboard_update events
#   "risk":       str,    # on requires_approval / verdict events
#   "verdict":    str,    # on verdict events
# }

async def _mock_audit_generator(run_id: str) -> AsyncGenerator[dict, None]:
    state  = runs[run_id]
    domain = state["domain"]
    chaos  = state["chaos"]

    def step_event(agent, tool, status, rationale, latency, retries=0):
        state["steps"] += 1
        return {
            "type":       "trace",
            "agent":      agent,
            "tool":       tool,
            "status":     status,
            "rationale":  rationale,
            "latency_ms": latency,
            "retries":    retries,
            "step":       state["steps"],
            "elapsed_s":  round(time.time() - state["start_ts"], 2),
        }

    def bb_update(patch: dict, note: str):
        state["blackboard"].update(patch)
        return {
            "type":       "blackboard_update",
            "note":       note,
            "blackboard": dict(state["blackboard"]),
            "step":       state["steps"],
            "elapsed_s":  round(time.time() - state["start_ts"], 2),
        }

    # Step 1: Planner
    await asyncio.sleep(0.8)
    yield step_event(
        "planner", "dispatch", "ok",
        f"Dispatching dns_agent + rdap_agent for '{domain}'",
        42,
    )

    # Step 2: DNS agent
    if chaos == "dns_timeout":
        await asyncio.sleep(1.5)
        yield step_event(
            "dns_agent", "cloudflare_doh", "retrying",
            "Primary DoH timed out — retrying with Google DoH fallback",
            3200, retries=1,
        )
        await asyncio.sleep(1.0)
        yield step_event(
            "dns_agent", "google_doh", "degraded",
            "Resolved via fallback Google DoH; Cloudflare primary unreachable",
            1840, retries=1,
        )
        dns_ip = "93.184.216.34"
        dns_status = "degraded"
        dns_resolver = "google"
    else:
        await asyncio.sleep(1.2)
        dns_ip = "93.184.216.34"
        dns_status = "ok"
        dns_resolver = "cloudflare"
        yield step_event(
            "dns_agent", "cloudflare_doh", "ok",
            f"Resolved {domain} → {dns_ip} via Cloudflare DoH",
            310,
        )

    yield bb_update(
        {"dns": {"status": dns_status, "ip": dns_ip, "resolver": dns_resolver}},
        "dns_agent wrote DNS result to blackboard",
    )

    # Step 3: RDAP agent
    await asyncio.sleep(1.3)
    rdap_expiry = "2031-08-13"
    yield step_event(
        "rdap_agent", "rdap_lookup", "ok",
        f"Registration expiry: {rdap_expiry} (1782 days remaining, low risk)",
        620,
    )
    yield bb_update(
        {"rdap": {"status": "ok", "expiry": rdap_expiry, "days_remaining": 1782}},
        "rdap_agent wrote registration data",
    )

    # Step 4: Uptime agent
    await asyncio.sleep(1.4)
    yield step_event(
        "uptime_agent", "https_get", "ok",
        f"HTTPS GET {domain} → 200 OK in 487 ms",
        487,
    )
    yield bb_update(
        {"uptime": {"status": "ok", "http_code": 200, "latency_ms": 487, "protocol": "https"}},
        "uptime_agent confirmed site is reachable",
    )

    # Step 5: Cert agent
    await asyncio.sleep(1.5)
    if chaos == "cert_expired":
        cert_status   = "failed"
        cert_expiry   = "2024-01-15"
        cert_days     = -254
        cert_rationale = f"TLS certificate EXPIRED on {cert_expiry} ({abs(cert_days)} days ago)"
    else:
        cert_status   = "ok"
        cert_expiry   = "2026-11-20"
        cert_days     = 55
        cert_rationale = f"TLS cert valid until {cert_expiry} ({cert_days} days remaining)"

    yield step_event("cert_agent", "tls_handshake", cert_status, cert_rationale, 210)
    yield bb_update(
        {"cert": {"status": cert_status, "expiry": cert_expiry, "days_remaining": cert_days}},
        "cert_agent wrote certificate data",
    )

    # Step 6: Critic
    await asyncio.sleep(1.2)
    if chaos == "cert_expired":
        risk             = "high"
        critic_status    = "failed"
        critic_rationale = "CERT EXPIRED — site reachable but TLS is broken; risk=HIGH"
    elif chaos == "dns_timeout":
        risk             = "medium"
        critic_status    = "degraded"
        critic_rationale = "DNS fell back to secondary resolver; single-point fragility; risk=MEDIUM"
    else:
        risk             = "low"
        critic_status    = "ok"
        critic_rationale = "No contradictions found across all 4 checks. risk=LOW"

    yield step_event("critic", "cross_check", critic_status, critic_rationale, 95)

    # Approval gate
    yield {
        "type":      "requires_approval",
        "risk":      risk,
        "finding":   critic_rationale,
        "step":      state["steps"],
        "elapsed_s": round(time.time() - state["start_ts"], 2),
    }

    # Block until UI posts to /approve
    await state["approval_event"].wait()
    action = state["approval_action"]

    yield {
        "type":      "approved" if action == "approve" else "denied",
        "action":    action,
        "step":      state["steps"],
        "elapsed_s": round(time.time() - state["start_ts"], 2),
    }

    # Final verdict
    await asyncio.sleep(0.5)
    verdict = "at_risk" if chaos == "cert_expired" else ("degraded" if chaos == "dns_timeout" else "healthy")

    state["steps"] += 1
    yield {
        "type":        "verdict",
        "verdict":     verdict,
        "risk":        risk,
        "summary":     critic_rationale,
        "blackboard":  dict(state["blackboard"]),
        "step":        state["steps"],
        "elapsed_s":   round(time.time() - state["start_ts"], 2),
        "total_steps": state["steps"],
    }


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
