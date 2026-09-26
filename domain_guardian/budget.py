"""The orchestrator-owned stopping condition: a step count AND a wall-clock
timeout. No agent decides for itself when to stop -- only this object does,
so a single misbehaving agent can never turn into an infinite loop or blow
the run's cost budget on its own.
"""
import time


class Budget:
    def __init__(self, max_steps=12, max_seconds=25.0):
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self._start = time.time()
        self.steps_used = 0

    def charge_step(self, n=1):
        self.steps_used += n

    def elapsed(self):
        return time.time() - self._start

    def exceeded(self):
        return self.steps_used >= self.max_steps or self.elapsed() >= self.max_seconds

    def summary(self):
        return {
            "steps_used": self.steps_used,
            "max_steps": self.max_steps,
            "elapsed_s": round(self.elapsed(), 2),
            "max_seconds": self.max_seconds,
        }
