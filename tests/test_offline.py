"""These tests prove the recovery logic actually works, without touching a
real network -- they mock requests.get so the suite is deterministic and
runs anywhere. Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests

from domain_guardian import run_domain_audit
from domain_guardian.agents import DNSAgent
from domain_guardian.blackboard import Blackboard
from domain_guardian.budget import Budget
from domain_guardian.trace import TraceLogger
from domain_guardian import critic as critic_mod


class FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data
        self.url = "https://example.com/"

    def json(self):
        return self._json_data


class TestDNSFallback(unittest.TestCase):
    def test_falls_back_to_secondary_resolver_after_primary_times_out(self):
        good = FakeResponse(json_data={"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
        with patch("domain_guardian.agents.requests.get") as mock_get:
            mock_get.side_effect = [requests.Timeout(), requests.Timeout(), requests.Timeout(), good]
            trace = TraceLogger()
            bb = Blackboard()
            budget = Budget(max_steps=20, max_seconds=10)
            result = DNSAgent().run("example.com", bb, budget, trace)

        self.assertIsNotNone(result)
        self.assertTrue(result["resolved"])
        statuses = [e["status"] for e in trace.events]
        self.assertIn("degraded", statuses)
        self.assertEqual(mock_get.call_count, 4)


class TestCriticRejection(unittest.TestCase):
    def test_critic_rejects_contradictory_result_and_forces_one_rerun(self):
        bb = Blackboard()
        bb.write("dns", {"resolved": False, "status_code": 3, "addresses": []})
        bb.write("uptime", {"scheme": "https", "status_code": 200, "reachable": True})
        trace = TraceLogger()
        budget = Budget(max_steps=20, max_seconds=10)
        rerun_calls = []

        def fake_rerun(name):
            rerun_calls.append(name)
            bb.write("uptime", {"scheme": None, "status_code": None, "reachable": False})
            return bb.read("uptime")

        verdict = critic_mod.review("example.com", bb, budget, trace, fake_rerun)

        self.assertEqual(rerun_calls, ["uptime_agent"])
        self.assertTrue(any(e["status"] == "rejected" for e in trace.events))
        self.assertEqual(verdict["risk"], "high")


class TestBudgetStopsEarly(unittest.TestCase):
    def test_orchestrator_halts_when_step_budget_is_exhausted(self):
        ok_dns = FakeResponse(json_data={"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
        with patch("domain_guardian.agents.requests.get", return_value=ok_dns):
            result = run_domain_audit("example.com", auto_decision=False, max_steps=1,
                                       max_seconds=10, verbose=False)

        self.assertTrue(result["stopped_early"])
        self.assertTrue(any(e["agent"] == "orchestrator" and e["status"] == "stopped"
                             for e in result["trace"]))


class TestTotalNetworkFailureDegradesGracefully(unittest.TestCase):
    def test_full_pipeline_survives_every_tool_failing(self):
        with patch("domain_guardian.agents.requests.get", side_effect=requests.ConnectionError("down")):
            result = run_domain_audit("broken-example.test", auto_decision=False,
                                       max_steps=30, max_seconds=20, verbose=False)

        self.assertIn(result["verdict"]["risk"], ("medium", "high"))
        self.assertFalse(result["stopped_early"])
        self.assertFalse(result["approved_action"])
        self.assertTrue(any(e["agent"] == "approval_gate" and e["action"] == "requested"
                             for e in result["trace"]))
        self.assertTrue(any(e["status"] == "failed" for e in result["trace"]))


if __name__ == "__main__":
    unittest.main()
