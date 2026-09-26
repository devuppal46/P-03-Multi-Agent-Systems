"""Shared state every agent reads from and writes to, with a versioned
history so a human can later ask "what did we know at step 4 vs step 7?"
"""
import time


class Blackboard:
    def __init__(self):
        self._state = {}
        self._history = []

    def write(self, key, value, agent="unknown"):
        self._state[key] = value
        self._history.append({"ts": time.time(), "agent": agent, "key": key, "value": value})

    def read(self, key, default=None):
        return self._state.get(key, default)

    def snapshot(self):
        return dict(self._state)

    def history(self):
        return list(self._history)
