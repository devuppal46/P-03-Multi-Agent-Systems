"""Specialist agents. Each one wraps exactly one real external tool call
with retry + backoff + an optional fallback source, and reports a
structured result through the TraceLogger. No agent decides when the whole
run stops -- that is the orchestrator's job (see budget.py). Some agents
also decide NOT to call their tool at all when the blackboard already shows
the precondition can't be met -- that's deliberate tool-selection-under-
uncertainty, not a bug.
"""
import socket
import ssl
import time
from datetime import datetime, timezone

import requests


class RecoverableError(Exception):
    """Raised for transient failures worth retrying: timeouts, 5xx, connection resets."""


class ToolAgent:
    name = "base_agent"
    tool_name = "none"
    max_retries = 2
    backoff_base = 0.4

    def call_tool(self, domain, blackboard):
        raise NotImplementedError

    def fallback(self, domain, blackboard):
        """Override to provide a secondary source. Return None if there isn't one."""
        return None

    def rationale(self, result):
        return "tool call succeeded"

    def run(self, domain, blackboard, budget, trace):
        attempt = 0
        last_err = None
        while attempt <= self.max_retries:
            if budget.exceeded():
                trace.log(agent=self.name, action="skipped", tool=self.tool_name,
                           rationale="orchestrator budget exhausted before this step could run",
                           status="stopped")
                return None
            start = time.time()
            try:
                result = self.call_tool(domain, blackboard)
                latency = (time.time() - start) * 1000
                trace.log(agent=self.name, action="tool_call", tool=self.tool_name,
                           inputs={"domain": domain}, output=result,
                           latency_ms=round(latency, 1), retries=attempt,
                           rationale=self.rationale(result), status="ok")
                budget.charge_step()
                return result
            except RecoverableError as e:
                last_err = e
                attempt += 1
                budget.charge_step()
                trace.log(agent=self.name, action="retry", tool=self.tool_name,
                           inputs={"domain": domain},
                           rationale=f"{e} -- retrying ({attempt}/{self.max_retries})",
                           retries=attempt, status="retry")
                if attempt <= self.max_retries:
                    time.sleep(self.backoff_base * (2 ** (attempt - 1)))

        try:
            fb = self.fallback(domain, blackboard)
        except RecoverableError as e:
            fb = None
            last_err = e
        if fb is not None:
            trace.log(agent=self.name, action="fallback", tool=f"{self.tool_name}_fallback",
                       inputs={"domain": domain}, output=fb,
                       rationale="primary source failed after retries; used fallback source",
                       retries=attempt, status="degraded")
            budget.charge_step()
            return fb

        trace.log(agent=self.name, action="failed", tool=self.tool_name,
                   inputs={"domain": domain},
                   rationale=f"exhausted retries and no fallback available: {last_err}",
                   retries=attempt, status="failed")
        budget.charge_step()
        return None


class DNSAgent(ToolAgent):
    name = "dns_agent"
    tool_name = "cloudflare_doh"

    def _query(self, url, domain):
        try:
            r = requests.get(url, params={"name": domain, "type": "A"},
                              headers={"accept": "application/dns-json"}, timeout=4)
        except (requests.Timeout, requests.ConnectionError) as e:
            raise RecoverableError(f"network error contacting DoH resolver: {e}")
        if r.status_code >= 500:
            raise RecoverableError(f"DoH resolver returned {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            raise RecoverableError("DoH resolver returned malformed JSON")
        status = data.get("Status")
        if status is None:
            raise RecoverableError("DoH response missing Status field")
        answers = data.get("Answer", [])
        return {
            "resolved": status == 0 and len(answers) > 0,
            "status_code": status,
            "addresses": [a.get("data") for a in answers if a.get("type") == 1],
        }

    def call_tool(self, domain, blackboard):
        result = self._query("https://cloudflare-dns.com/dns-query", domain)
        blackboard.write("dns", result, agent=self.name)
        return result

    def fallback(self, domain, blackboard):
        result = self._query("https://dns.google/resolve", domain)
        blackboard.write("dns", result, agent=self.name)
        return result

    def rationale(self, result):
        if result["resolved"]:
            return f"domain resolves to {len(result['addresses'])} address(es)"
        return "domain does not resolve (NXDOMAIN or no A record)"


class UptimeAgent(ToolAgent):
    name = "uptime_agent"
    tool_name = "http_get"

    def _get(self, scheme, domain):
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=5, allow_redirects=True)
        except requests.Timeout:
            raise RecoverableError(f"{scheme} request timed out")
        except requests.ConnectionError as e:
            raise RecoverableError(f"{scheme} connection failed: {e}")
        return {"scheme": scheme, "status_code": r.status_code, "final_url": r.url, "reachable": True}

    def call_tool(self, domain, blackboard):
        dns = blackboard.read("dns")
        if dns is not None and not dns.get("resolved", True):
            # Tool-selection under uncertainty: DNS already showed this name
            # doesn't resolve, so an HTTP call would just waste a step.
            result = {"scheme": None, "status_code": None, "final_url": None, "reachable": False}
            blackboard.write("uptime", result, agent=self.name)
            return result
        result = self._get("https", domain)
        blackboard.write("uptime", result, agent=self.name)
        return result

    def fallback(self, domain, blackboard):
        result = self._get("http", domain)
        blackboard.write("uptime", result, agent=self.name)
        return result

    def rationale(self, result):
        if not result["reachable"]:
            return "skipped the live HTTP call: DNS already showed this name doesn't resolve"
        return f"reachable over {result['scheme']}, HTTP {result['status_code']}"


class CertAgent(ToolAgent):
    name = "cert_agent"
    tool_name = "tls_handshake"
    max_retries = 1  # a hung TLS handshake is expensive to retry repeatedly

    def call_tool(self, domain, blackboard):
        uptime = blackboard.read("uptime")
        if uptime is None or uptime.get("scheme") != "https":
            # Another self-skip: no point attempting a TLS handshake against
            # a host we already know isn't answering over HTTPS.
            result = {"checked": False, "days_left": None}
            blackboard.write("cert", result, agent=self.name)
            return result
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            raise RecoverableError(f"TLS handshake failed: {e}")
        not_after = cert.get("notAfter")
        if not not_after:
            raise RecoverableError("certificate missing notAfter field")
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        result = {"checked": True, "days_left": days_left, "expires": not_after}
        blackboard.write("cert", result, agent=self.name)
        return result

    def rationale(self, result):
        if not result["checked"]:
            return "skipped: site isn't reachable over HTTPS"
        return f"certificate valid for {result['days_left']} more day(s)"


class RDAPAgent(ToolAgent):
    name = "rdap_agent"
    tool_name = "rdap_lookup"

    def call_tool(self, domain, blackboard):
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        except (requests.Timeout, requests.ConnectionError) as e:
            raise RecoverableError(f"RDAP lookup failed: {e}")
        if r.status_code == 404:
            result = {"found": False, "days_left": None}
            blackboard.write("rdap", result, agent=self.name)
            return result
        if r.status_code >= 500:
            raise RecoverableError(f"RDAP server returned {r.status_code}")
        if r.status_code >= 400:
            result = {"found": False, "days_left": None}
            blackboard.write("rdap", result, agent=self.name)
            return result
        try:
            data = r.json()
        except ValueError:
            raise RecoverableError("RDAP response was not valid JSON")
        events = data.get("events", [])
        expiry_event = next((e for e in events if e.get("eventAction") == "expiration"), None)
        if not expiry_event:
            result = {"found": True, "days_left": None}
        else:
            expiry = datetime.fromisoformat(expiry_event["eventDate"].replace("Z", "+00:00"))
            days_left = (expiry - datetime.now(timezone.utc)).days
            result = {"found": True, "days_left": days_left}
        blackboard.write("rdap", result, agent=self.name)
        return result

    def rationale(self, result):
        if not result["found"]:
            return "no RDAP record found (unsupported TLD or unregistered)"
        if result["days_left"] is None:
            return "registered, but no expiration date published"
        return f"registration expires in {result['days_left']} day(s)"
