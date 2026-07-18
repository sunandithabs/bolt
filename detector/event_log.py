import time
from dataclasses import dataclass


@dataclass
class Event:
    timestamp: float
    attack_name: str
    version: int
    result: str
    detail: str = ""


class EventLog:
    def __init__(self):
        self.events: list[Event] = []

    def record(self, attack_name: str, version: int, blocked: bool, detail: str = ""):
        result = "BLOCKED" if blocked else "SUCCEEDED"
        self.events.append(Event(time.time(), attack_name, version, result, detail))

    def summary(self):
        total = len(self.events)
        blocked = sum(1 for e in self.events if e.result == "BLOCKED")
        return {"total": total, "blocked": blocked, "succeeded": total - blocked}
