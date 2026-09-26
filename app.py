"""
app.py — Domain Guardian Web UI Backend

FastAPI server that:
  • Serves index.html at the root
  • Streams audit trace events via SSE  (GET /audit/{run_id}/stream)
  • Accepts human approval/deny         (POST /audit/{run_id}/approve)
  • Runs a batch harness                (POST /batch)

HOW THE REAL AUDIT IS WIRED IN
─────────────────────────────────────────────────────────────────────────────
The real `run_domain_audit()` in orchestrator.py is fully synchronous (it
does real blocking network calls + time.sleep back-offs).  Streaming its
events live to a browser requires three small bridges:

1. StreamingTraceLogger  — subclass of TraceLogger that, on every .log()
   call, immediately puts the event on a thread-safe queue.Queue so the
   async SSE generator can read it without any extra polling.

2. _web_approval_request — monkey-patched replacement for
   approval.request_approval().  Instead of calling input(), it:
     a) puts a "requires_approval" sentinel on the queue, and
     b) blocks the audit thread on a threading.Event until the browser
        POSTs to /audit/{run_id}/approve.

3. _real_audit_worker    — runs in a ThreadPoolExecutor so the blocking
   audit thread never stalls the async event loop.  It writes a final
   "verdict" sentinel to the queue when it finishes (or raises).

Nothing inside domain_guardian/ is modified.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

# Load .env before anything else so GEMINI_API_KEY is available to rca_agent
from dotenv import load_dotenv
load_dotenv()  # reads .env from the current working directory

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Real domain_guardian imports
from domain_guardian import approval as approval_mod
from domain_guardian.blackboard import Blackboard
from domain_guardian.budget import Budget
from domain_guardian import critic as critic_mod
from domain_guardian import planner as planner_mod
from domain_guardian.agents import CertAgent, DNSAgent, RDAPAgent, UptimeAgent
from domain_guardian.trace import TraceLogger
from domain_guardian import rca_agent

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(title="Domain Guardian UI", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="."), name="static")

_executor = ThreadPoolExecutor(max_workers=8)

# ── In-memory run state ───────────────────────────────────────────────────────

runs: dict[str, dict] = {}
# Shape:
# {
#   "domain":           str,
#   "chaos":            str,
#   "start_ts":         float,
#   "event_queue":      queue.Queue,   # bridge between audit thread → SSE stream
#   "approval_event":   threading.Event,
#   "approval_action":  bool | None,   # True=approve, False=deny
# }

# ── Request / Response models ─────────────────────────────────────────────────

class AuditRequest(BaseModel):
    domain: str
    chaos: str = "none"


class ApproveRequest(BaseModel):
    action: str   # "approve" | "deny"


class BatchRequest(BaseModel):
    domains: list[str]
    repeats: int = 3


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
async def serve_index():
    return FileResponse("index.html")


def _idna_encode(domain: str) -> str:
    """Encode an internationalized domain name to ASCII-compatible encoding.
    Converts e.g. münchen.de → xn--mnchen-3ya.de so DNS/TLS tools never
    receive raw Unicode. Falls back to the original string on encoding errors.
    """
    try:
        return domain.strip().encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain.strip()


@app.post("/audit")
async def start_audit(req: AuditRequest):
    # FIX 3: Sanitize IDN domains at the API boundary before any agent sees them.
    domain = _idna_encode(req.domain)
    run_id = str(uuid.uuid4())[:8]
    runs[run_id] = {
        "domain":          domain,
        "chaos":           req.chaos,
        "start_ts":        time.time(),
        "event_queue":     queue.Queue(),
        "approval_event":  threading.Event(),
        "approval_action": None,
    }
    return {"run_id": run_id}


@app.get("/audit/{run_id}/stream")
async def stream_audit(run_id: str):
    if run_id not in runs:
        raise HTTPException(status_code=404, detail="run not found")
    return StreamingResponse(
        _sse_wrapper(run_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/audit/{run_id}/approve")
async def approve_audit(run_id: str, req: ApproveRequest):
    if run_id not in runs:
        raise HTTPException(status_code=404, detail="run not found")
    if req.action not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="action must be approve or deny")
    state = runs[run_id]
    state["approval_action"] = (req.action == "approve")
    state["approval_event"].set()       # unblocks the audit thread
    return {"status": "ok"}


@app.post("/batch")
async def run_batch_endpoint(req: BatchRequest):
    """
    Runs the real run_batch() in a thread so the event loop isn't blocked.
    """
    loop = asyncio.get_event_loop()
    from domain_guardian.orchestrator import run_batch as _run_batch
    rows = await loop.run_in_executor(
        _executor,
        lambda: _run_batch(req.domains, repeats=req.repeats,
                           auto_decision=False, max_steps=12, max_seconds=25.0),
    )
    total       = len(rows)
    completed_n = sum(1 for r in rows if r["completed"])
    times       = [r["elapsed_s"] for r in rows]
    return {
        "total_runs":      total,
        "completed":       completed_n,
        "completion_rate": round(completed_n / total, 3) if total else 0,
        "avg_latency_s":   round(sum(times) / total, 2) if total else 0,
        "rows":            rows,
    }


# ── Bridge 1: Streaming TraceLogger ──────────────────────────────────────────

class StreamingTraceLogger(TraceLogger):
    """
    Drops every logged event onto a queue.Queue immediately so the SSE
    generator can stream it to the browser without waiting for the full audit
    to finish.  Also pushes a matching blackboard snapshot alongside it.
    """

    def __init__(self, event_queue: queue.Queue, blackboard: Blackboard, start_ts: float):
        super().__init__()
        self._q  = event_queue
        self._bb = blackboard
        self._start_ts = start_ts

    def log(self, *, agent, action, tool=None, inputs=None, output=None,
            rationale="", latency_ms=None, retries=0, confidence=None, status="ok"):
        event = super().log(
            agent=agent, action=action, tool=tool, inputs=inputs, output=output,
            rationale=rationale, latency_ms=latency_ms, retries=retries,
            confidence=confidence, status=status,
        )
        # Map the agent's internal status names to the UI's expected names
        ui_status = {
            "ok":       "ok",
            "degraded": "degraded",
            "failed":   "failed",
            "retry":    "retrying",
            "retrying": "retrying",
            "rejected": "degraded",
            "stopped":  "degraded",
            "pending":  "ok",
            "denied":   "failed",
        }.get(status, status)

        self._q.put({
            "type":       "trace",
            "agent":      agent,
            "tool":       tool or action,
            "status":     ui_status,
            "rationale":  rationale,
            "latency_ms": round(latency_ms) if latency_ms is not None else None,
            "retries":    retries,
            "step":       event["step"],
            "elapsed_s":  round(time.time() - self._start_ts, 2),
        })
        # Push blackboard snapshot after every write so the UI panel updates
        bb_snap = {k: v for k, v in self._bb.snapshot().items()
                   if not k.startswith("_")}  # hide internal flags
        if bb_snap:
            self._q.put({
                "type":       "blackboard_update",
                "note":       f"{agent} → wrote to blackboard",
                "blackboard": bb_snap,
                "step":       event["step"],
                "elapsed_s":  round(time.time() - self._start_ts, 2),
            })
        return event


# ── Bridge 2: Web approval gate ───────────────────────────────────────────────

def _make_web_approval_fn(run_id: str):
    """
    Returns a drop-in replacement for approval.request_approval().
    Puts a REQUIRES_APPROVAL sentinel on the queue, then blocks the audit
    thread until the browser POSTs to /audit/{run_id}/approve.
    """
    def _web_approval(action, risk, trace, auto_decision=None):
        state = runs[run_id]

        # Log the pending event exactly as the real function would
        trace.log(
            agent="approval_gate", action="requested",
            inputs={"action": action, "risk": risk},
            rationale="this action requires explicit human sign-off before executing",
            status="pending",
        )

        # Tell the UI to show the modal
        state["event_queue"].put({
            "type":      "requires_approval",
            "risk":      risk,
            "finding":   action,
            "step":      len(trace.events),
            "elapsed_s": round(time.time() - state["start_ts"], 2),
        })

        # Block the audit thread until the browser responds
        state["approval_event"].wait(timeout=300)   # 5-min safety timeout
        decision = bool(state["approval_action"])

        source = "human (web UI)"
        trace.log(
            agent="approval_gate", action="decided",
            output={"approved": decision, "decided_by": source},
            rationale=f"decision made by {source}",
            status="ok" if decision else "denied",
        )
        return decision

    return _web_approval


# ── Bridge 3: Real audit worker (runs in thread) ──────────────────────────────

AGENTS = {
    "dns_agent":    DNSAgent(),
    "uptime_agent": UptimeAgent(),
    "cert_agent":   CertAgent(),
    "rdap_agent":   RDAPAgent(),
}


def _real_audit_worker(run_id: str):
    """
    Runs the full real audit pipeline in a background thread.
    Communicates with the SSE stream exclusively through state["event_queue"].
    Signals completion by putting a "verdict" or "error" sentinel on the queue.
    """
    state   = runs[run_id]
    domain  = state["domain"]
    q       = state["event_queue"]
    start   = state["start_ts"]

    blackboard = Blackboard()
    trace      = StreamingTraceLogger(q, blackboard, start)
    budget     = Budget(max_steps=12, max_seconds=25.0)
    done       = []

    # Monkey-patch approval for this run only (thread-local via closure)
    original_fn = approval_mod.request_approval
    approval_mod.request_approval = _make_web_approval_fn(run_id)

    try:
        queue_ = list(planner_mod.build_plan(domain, blackboard, trace))
        stopped_early = False

        while queue_:
            if budget.exceeded():
                trace.log(
                    agent="orchestrator", action="stop",
                    rationale=f"budget exceeded ({budget.summary()}); ending run early",
                    status="stopped",
                )
                stopped_early = True
                break
            agent_name = queue_.pop(0)
            AGENTS[agent_name].run(domain, blackboard, budget, trace)
            done.append(agent_name)
            nxt = planner_mod.next_step(domain, blackboard, trace, done)
            if nxt and nxt not in done and nxt not in queue_:
                queue_.append(nxt)

        def rerun_agent(name):
            AGENTS[name].run(domain, blackboard, budget, trace)
            key_map = {
                "dns_agent": "dns", "uptime_agent": "uptime",
                "cert_agent": "cert", "rdap_agent": "rdap",
            }
            return blackboard.read(key_map[name])

        if not stopped_early:
            verdict = critic_mod.review(domain, blackboard, budget, trace, rerun_agent)
        else:
            verdict = {
                "risk": "unknown",
                "findings": ["run stopped before a full audit completed"],
            }

        # ── Verdict event ─────────────────────────────────────────────────
        clean_bb = {k: v for k, v in blackboard.snapshot().items()
                    if not k.startswith("_")}
        q.put({
            "type":        "verdict",
            "verdict":     _risk_to_verdict(verdict["risk"]),
            "risk":        verdict["risk"],
            "summary":     "; ".join(verdict["findings"]),
            "blackboard":  clean_bb,
            "step":        budget.steps_used,
            "elapsed_s":   round(time.time() - start, 2),
            "total_steps": budget.steps_used,
        })

        # ── LLM RCA synthesis (runs after verdict; ~1-2 s Gemini latency) ──
        # Reads GEMINI_API_KEY from environment; gracefully degrades if absent.
        try:
            rca_result = rca_agent.synthesize(
                domain=domain,
                blackboard=clean_bb,
                trace_events=trace.events,
                verdict=verdict,
                elapsed_s=round(time.time() - start, 2),
            )
            q.put({
                "type":      "rca",
                "rca":       rca_result,
                "step":      budget.steps_used + 1,
                "elapsed_s": round(time.time() - start, 2),
            })
        except Exception as rca_exc:
            # Never let RCA failure block the stream close
            q.put({
                "type":    "rca",
                "rca":     {
                    "summary":  "RCA synthesis failed",
                    "narrative": str(rca_exc),
                    "root_cause": "Unknown — see error.",
                    "recommended_actions": ["Check GEMINI_API_KEY", "Retry audit"],
                    "severity": "P3",
                    "confidence": "low",
                    "error": str(rca_exc),
                    "model": "error",
                    "latency_ms": 0,
                },
                "step":      budget.steps_used + 1,
                "elapsed_s": round(time.time() - start, 2),
            })

    except Exception as exc:
        q.put({
            "type":    "error",
            "message": str(exc),
        })
    finally:
        # Always restore original approval function
        approval_mod.request_approval = original_fn
        # None sentinel tells the SSE wrapper to close the stream
        q.put(None)


def _risk_to_verdict(risk: str) -> str:
    return {"low": "healthy", "medium": "degraded", "high": "at_risk"}.get(risk, "unknown")


# ── SSE helpers ───────────────────────────────────────────────────────────────

def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


async def _sse_wrapper(run_id: str):
    """
    Async generator that:
      1. Kicks the real audit into a thread.
      2. Drains events from the queue asynchronously (non-blocking poll with
         a tiny sleep so the event loop stays responsive).
      3. Closes when it sees the None sentinel (put after the rca event).

    Event sequence on the queue:
        trace / blackboard_update / requires_approval / approved|denied
        → verdict
        → rca          (Gemini synthesis, ~1-2 s after verdict)
        → None         (terminal sentinel)
    """
    loop = asyncio.get_event_loop()

    # Start the real audit in a thread
    loop.run_in_executor(_executor, _real_audit_worker, run_id)

    state = runs[run_id]
    q     = state["event_queue"]

    while True:
        # Non-blocking drain — yield control back to the event loop between checks
        try:
            event = q.get_nowait()
        except queue.Empty:
            await asyncio.sleep(0.05)
            continue

        if event is None:
            # Terminal sentinel — audit thread has finished (after rca event)
            break

        yield _sse_event(event)
        # No early break on 'verdict' — keep draining until None so the
        # rca event also reaches the browser.
