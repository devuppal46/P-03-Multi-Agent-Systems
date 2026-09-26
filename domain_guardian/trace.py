"""Structured, human-auditable trace of every action taken during a run.
This is the artifact a human reviews afterwards to answer: which agent did
what, with which inputs, and why did it make that choice.
"""
import json
import time


class TraceLogger:
    def __init__(self):
        self.events = []

    def log(self, *, agent, action, tool=None, inputs=None, output=None,
            rationale="", latency_ms=None, retries=0, confidence=None, status="ok"):
        event = {
            "step": len(self.events) + 1,
            "ts": round(time.time(), 3),
            "agent": agent,
            "action": action,
            "tool": tool,
            "inputs": inputs,
            "output": output,
            "rationale": rationale,
            "latency_ms": latency_ms,
            "retries": retries,
            "confidence": confidence,
            "status": status,
        }
        self.events.append(event)
        return event

    def print_table(self):
        print(f"{'#':<3} {'agent':<16} {'action':<12} {'status':<10} {'lat(ms)':<9} {'retries':<8} rationale")
        print("-" * 110)
        for e in self.events:
            lat = f"{e['latency_ms']:.0f}" if e["latency_ms"] is not None else "-"
            print(f"{e['step']:<3} {e['agent']:<16} {e['action']:<12} {e['status']:<10} "
                  f"{lat:<9} {e['retries']:<8} {e['rationale'][:56]}")

    def to_json(self):
        return json.dumps(self.events, indent=2, default=str)

    def total_retries(self):
        return sum(e["retries"] for e in self.events)
