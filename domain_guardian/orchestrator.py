"""Ties planner, agents, blackboard, critic and the approval gate together.
This is the only component allowed to decide when a run ends -- see budget.py.
"""
import statistics
import time

from .agents import CertAgent, DNSAgent, RDAPAgent, UptimeAgent
from . import approval as approval_mod
from .blackboard import Blackboard
from .budget import Budget
from . import critic as critic_mod
from . import planner as planner_mod
from .trace import TraceLogger

AGENTS = {
    "dns_agent": DNSAgent(),
    "uptime_agent": UptimeAgent(),
    "cert_agent": CertAgent(),
    "rdap_agent": RDAPAgent(),
}

_KEY_FOR_AGENT = {
    "dns_agent": "dns",
    "uptime_agent": "uptime",
    "cert_agent": "cert",
    "rdap_agent": "rdap",
}


def run_domain_audit(domain, auto_decision=None, max_steps=12, max_seconds=25.0, verbose=True):
    blackboard = Blackboard()
    trace = TraceLogger()
    budget = Budget(max_steps=max_steps, max_seconds=max_seconds)
    done = []

    queue = list(planner_mod.build_plan(domain, blackboard, trace))
    stopped_early = False

    while queue:
        if budget.exceeded():
            trace.log(agent="orchestrator", action="stop",
                       rationale=f"budget exceeded ({budget.summary()}); ending run early",
                       status="stopped")
            stopped_early = True
            break
        agent_name = queue.pop(0)
        AGENTS[agent_name].run(domain, blackboard, budget, trace)
        done.append(agent_name)
        nxt = planner_mod.next_step(domain, blackboard, trace, done)
        if nxt and nxt not in done and nxt not in queue:
            queue.append(nxt)

    def rerun_agent(name):
        AGENTS[name].run(domain, blackboard, budget, trace)
        return blackboard.read(_KEY_FOR_AGENT[name])

    if not stopped_early:
        verdict = critic_mod.review(domain, blackboard, budget, trace, rerun_agent)
    else:
        verdict = {"risk": "unknown", "findings": ["run stopped before a full audit completed"]}
        trace.log(agent="critic", action="skipped",
                   rationale="budget was already exhausted; producing a partial verdict instead",
                   status="degraded")

    approved = None
    if verdict["risk"] in ("high", "medium"):
        action = f"send an alert about {domain} to its registrant/on-call contact"
        approved = approval_mod.request_approval(action, verdict["risk"], trace, auto_decision)

    result = {
        "domain": domain,
        "verdict": verdict,
        "approved_action": approved,
        "budget": budget.summary(),
        "blackboard": blackboard.snapshot(),
        "trace": trace.events,
        "stopped_early": stopped_early,
    }

    if verbose:
        print(f"\n=== Domain Guardian audit: {domain} ===\n")
        trace.print_table()
        print(f"\nVerdict: {verdict['risk'].upper()}")
        for f in verdict["findings"]:
            print(f" - {f}")
        print(f"\nBudget used: {budget.summary()}")
        if approved is not None:
            print(f"Approved: {approved} -- {'action executed' if approved else 'action NOT executed'}")

    return result


def run_batch(domains, repeats=1, auto_decision=False, max_steps=12, max_seconds=25.0):
    rows = []
    for domain in domains:
        for i in range(repeats):
            start = time.time()
            try:
                res = run_domain_audit(domain, auto_decision=auto_decision, max_steps=max_steps,
                                        max_seconds=max_seconds, verbose=False)
                completed = not res["stopped_early"]
                risk = res["verdict"]["risk"]
                retries = sum(e["retries"] for e in res["trace"])
                failed_steps = sum(1 for e in res["trace"] if e["status"] == "failed")
            except Exception:
                completed, risk, retries, failed_steps = False, "error", 0, 0
            elapsed = time.time() - start
            rows.append({"domain": domain, "run": i + 1, "completed": completed, "risk": risk,
                         "retries": retries, "failed_steps": failed_steps, "elapsed_s": round(elapsed, 2)})

    total = len(rows)
    completed_n = sum(1 for r in rows if r["completed"])
    print(f"\n=== Completion-rate harness: {total} runs across {len(domains)} domain(s) ===\n")
    print(f"{'domain':<26}{'run':<5}{'completed':<11}{'risk':<9}{'retries':<9}{'failed':<8}time(s)")
    for r in rows:
        print(f"{r['domain']:<26}{r['run']:<5}{str(r['completed']):<11}{r['risk']:<9}"
              f"{r['retries']:<9}{r['failed_steps']:<8}{r['elapsed_s']}")
    print(f"\nCompletion rate: {completed_n}/{total} ({100 * completed_n / total:.0f}%)")
    times = [r["elapsed_s"] for r in rows]
    print(f"Latency: avg={statistics.mean(times):.2f}s  min={min(times):.2f}s  max={max(times):.2f}s")
    return rows
