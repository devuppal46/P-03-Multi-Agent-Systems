# Domain & Website Guardian

A multi-agent system that audits a domain the way an SRE would: is it
resolving, is the site up, is the TLS cert about to expire, is the
registration about to lapse -- and it does this by planning, delegating to
specialist agents, calling real external services, and recovering when one
of them fails, rather than a single prompt guessing at the answer.

## Architecture

```
Orchestrator (owns the stopping condition: steps + wall clock)
  -> Planner            decides which agents run next, based on real results
  -> Blackboard          shared state every agent reads/writes, versioned
  -> dns_agent           Cloudflare DoH, falls back to Google DoH
  -> rdap_agent          RDAP (rdap.org) for registration expiry
  -> uptime_agent        real HTTPS GET, falls back to HTTP
  -> cert_agent          real TLS handshake, reads certificate expiry
  -> Critic              finds contradictions, can reject + force a re-run
  -> Approval gate       human sign-off required before any risky action
```

Each agent wraps exactly one real tool call with retry + backoff + (where
one exists) a fallback source. Two agents also decide *not* to call their
tool at all when the blackboard already shows the precondition can't be met
(no HTTPS response -> don't bother with a TLS handshake) -- that's
deliberate tool-selection-under-uncertainty, not a shortcut.

## Why this needs more than one agent

Parsing a DNS-over-HTTPS response, doing a TLS handshake and reading a
certificate, and reconciling four independent (and sometimes contradictory)
data sources into one risk verdict are three different kinds of work. A
single prompt would either hallucinate the numeric details or silently drop
the cross-checking the critic does.

## Mapping to the challenge requirements

| Requirement | Where |
|---|---|
| Needs >1 agent, justified | 4 specialist agents + critic, see above |
| Real planning/delegation | `planner.py` -- dispatch decisions quote the actual prior result |
| Real external tool + malformed responses | `agents.py` -- DoH, RDAP, live HTTP, live TLS; malformed JSON/missing fields raise `RecoverableError` and get retried |
| Survives a failed/slow/malformed step | retry+backoff -> fallback source -> graceful "failed"/"degraded" status, never a crash |
| Readable trace | `trace.py` -- every action logged with agent, tool, inputs, output, one-line rationale, latency, retries |
| Stopping condition | `budget.py` -- step count AND wall-clock timeout, owned by the orchestrator, not the agents |
| Human approval for risky action | `approval.py` -- gates any medium/high-risk finding before "sending an alert" |

Advanced directions covered: critic that can actually reject and force a
bounded re-run (`critic.py`); shared blackboard; tool selection under
uncertainty (agents self-skip); cost/latency measured per run, not
estimated (every event has a real `latency_ms`); completion rate across
repeated runs (`run_batch`).

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# single domain, interactive approval prompt if risk is medium/high
python main.py example.com

# force an early stop to see the budget/stopping-condition in action
python main.py example.com --max-steps 3

# non-interactive (for demos/CI) -- auto-deny or auto-approve the gate
python main.py example.com --auto-deny

# completion-rate + cost/latency harness across repeated runs
python main.py --batch domains.txt --repeats 5 --auto-deny
```

`domains.txt` is just one domain per line.

## Proving the recovery logic (no network needed)

```bash
python -m unittest discover -s tests -v
```

These tests mock the network and assert, deterministically: the DNS agent
actually falls back to a secondary resolver after the primary times out;
the critic actually rejects a contradictory result and forces exactly one
re-run; the orchestrator actually halts when the step budget runs out; and
the whole pipeline survives every single tool failing at once without
crashing, producing an honest "couldn't verify" verdict instead of a false
all-clear.

## Live demo tips

- **A real, controllable TLS failure**: point `cert_agent` at
  `expired.badssl.com` or `self-signed.badssl.com` -- these are public test
  domains that exist specifically to have broken certificates. This
  triggers the real retry -> graceful-degrade path, no mocking required.
- **A real DNS failure**: any domain that doesn't exist, e.g.
  `this-domain-should-not-exist-12345.com`.
- **Force the approval gate on a healthy domain**: temporarily raise
  `CERT_WARNING_DAYS` / `RDAP_WARNING_DAYS` in `critic.py` -- e.g. set
  `RDAP_WARNING_DAYS = 9000` so almost any domain trips a "medium" finding.
- **Force the stopping condition**: `--max-steps 3` on any domain.
- **Force total-failure degradation live**: disconnect your network
  mid-run and watch it still finish with a verdict instead of crashing
  (this is exactly what the sandboxed test run below demonstrated for real).

## Known limitations / next steps with more time

- DNS and RDAP are dispatched sequentially; they're independent and could
  run concurrently.
- The trace is in-memory only; a real deployment would persist it (SQLite/
  JSON file per run) for later audit.
- No real notification is sent on approval -- `approved_action` is a stub
  you'd wire to an actual email/Slack call.
- A small web dashboard over the JSON trace would make the blackboard's
  evolution and the critic's rejection visible in real time instead of a
  printed table.
