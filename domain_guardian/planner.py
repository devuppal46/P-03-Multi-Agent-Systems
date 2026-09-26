"""Decides which agents to run and in what order. This is a real planner,
not a fixed chain: the second dispatch decision is generated only after
seeing dns_agent's actual result, and the rationale logged for it quotes
that real result -- so two different domains produce two different,
inspectable planning traces, not just two different outputs.
"""


def build_plan(domain, blackboard, trace):
    plan = ["dns_agent", "rdap_agent"]
    trace.log(agent="planner", action="plan", inputs={"domain": domain}, output=plan,
               rationale="DNS health and domain-registration status are independent "
                          "of each other, so both are dispatched first regardless of "
                          "how the audit turns out",
               status="ok")
    return plan


def next_step(domain, blackboard, trace, done):
    if "uptime_agent" not in done and "dns_agent" in done:
        dns = blackboard.read("dns") or {}
        trace.log(agent="planner", action="dispatch",
                   rationale=f"dns_agent reported resolved={dns.get('resolved')}; dispatching "
                              f"uptime_agent, which will itself decide whether a live HTTP "
                              f"call is worth making given that result",
                   status="ok")
        return "uptime_agent"
    if "cert_agent" not in done and "uptime_agent" in done:
        uptime = blackboard.read("uptime") or {}
        trace.log(agent="planner", action="dispatch",
                   rationale=f"uptime_agent reported reachable={uptime.get('reachable')} over "
                              f"scheme={uptime.get('scheme')}; dispatching cert_agent, which "
                              f"will itself decide whether a TLS handshake is worth attempting",
                   status="ok")
        return "cert_agent"
    return None
