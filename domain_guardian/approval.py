"""Human approval gate. Any action tagged as sensitive/irreversible pauses
the run here -- the orchestrator will not proceed on that action without an
explicit decision, whether that comes from a human at a prompt or a
pre-supplied decision for batch/testing runs.
"""


def request_approval(action, risk, trace, auto_decision=None):
    trace.log(agent="approval_gate", action="requested", inputs={"action": action, "risk": risk},
               rationale="this action is externally visible or irreversible, so it requires "
                          "an explicit human sign-off before executing",
               status="pending")
    if auto_decision is not None:
        decision = auto_decision
        source = "auto (non-interactive run)"
    else:
        raw = input(f"\n[APPROVAL REQUIRED] risk={risk}\nProposed action: {action}\nApprove? (y/n): ")
        decision = raw.strip().lower().startswith("y")
        source = "human"
    trace.log(agent="approval_gate", action="decided", output={"approved": decision, "decided_by": source},
               rationale=f"decision made by {source}", status="ok" if decision else "denied")
    return decision
