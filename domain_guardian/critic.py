"""Reviews the blackboard for contradictions and produces the overall
verdict. Can reject an agent's result and force exactly one confirmation
re-run -- bounded, via the `_uptime_rechecked` flag, so a disagreement can
never turn into an infinite loop.

Tune these two constants to force a medium/high verdict on a healthy domain
during a live demo of the approval gate.
"""

CERT_WARNING_DAYS = 14
RDAP_WARNING_DAYS = 30

_SEVERITY = {"low": 0, "medium": 1, "high": 2}


def _bump(current, candidate):
    return candidate if _SEVERITY[candidate] > _SEVERITY[current] else current


def review(domain, blackboard, budget, trace, rerun_agent_fn):
    findings = []
    risk = "low"

    dns = blackboard.read("dns")
    uptime = blackboard.read("uptime")
    cert = blackboard.read("cert")
    rdap = blackboard.read("rdap")

    # Contradiction check: DNS says the name doesn't resolve, but the HTTP
    # agent still got a live response back. That's internally inconsistent
    # (stale resolver cache, wildcard DNS) -- reject and force one
    # confirmation re-run rather than silently trusting either result.
    if (dns and not dns.get("resolved") and uptime and uptime.get("reachable")
            and not blackboard.read("_uptime_rechecked")):
        trace.log(agent="critic", action="reject", inputs={"dns": dns, "uptime": uptime},
                   rationale="DNS says this domain doesn't resolve, but uptime_agent got a "
                              "live HTTP response -- that's inconsistent. Rejecting the "
                              "uptime result and forcing one confirmation re-run.",
                   status="rejected")
        blackboard.write("_uptime_rechecked", True, agent="critic")
        if not budget.exceeded():
            uptime = rerun_agent_fn("uptime_agent")
        else:
            trace.log(agent="critic", action="reject_abandoned",
                       rationale="wanted a confirmation re-run but the budget was already "
                                  "exhausted; proceeding with the unconfirmed result",
                       status="degraded")

    if dns is None:
        findings.append("DNS check could not be completed (all sources failed)")
        risk = _bump(risk, "medium")
    elif not dns.get("resolved"):
        findings.append("domain does not currently resolve")
        risk = _bump(risk, "high")

    if uptime is None:
        findings.append("uptime check could not be completed (all sources failed)")
        risk = _bump(risk, "medium")
    elif uptime.get("reachable") is False and dns and dns.get("resolved"):
        findings.append("DNS resolves but the site did not respond over HTTP or HTTPS")
        risk = _bump(risk, "high")

    if cert is None:
        findings.append("certificate check could not be completed")
        risk = _bump(risk, "medium")
    elif cert.get("checked") and cert.get("days_left") is not None:
        if cert["days_left"] < 0:
            findings.append("TLS certificate has already expired")
            risk = _bump(risk, "high")
        elif cert["days_left"] < CERT_WARNING_DAYS:
            findings.append(f"TLS certificate expires in {cert['days_left']} day(s)")
            risk = _bump(risk, "medium")

    if rdap is None:
        findings.append("domain registration check could not be completed")
        risk = _bump(risk, "medium")
    elif rdap.get("found") and rdap.get("days_left") is not None:
        if rdap["days_left"] < 0:
            findings.append("domain registration has already expired")
            risk = _bump(risk, "high")
        elif rdap["days_left"] < RDAP_WARNING_DAYS:
            findings.append(f"domain registration expires in {rdap['days_left']} day(s)")
            risk = _bump(risk, "medium")

    if not findings:
        findings.append("no issues found across DNS, uptime, certificate, or registration checks")

    verdict = {"risk": risk, "findings": findings}
    trace.log(agent="critic", action="verdict", output=verdict,
               rationale="combined all agent results into a single risk verdict",
               status="ok")
    return verdict
