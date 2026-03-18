# IDS v2 – Correlation Engine
# Detects attack chains instead of single events

from collections import defaultdict
import time

class IDSCorrelationEngine:
    def __init__(self):
        self.ip_history = defaultdict(list)
        self.window = 300  # 5 minutes

    def correlate(self, ip: str, alert: dict) -> dict:
        now = time.time()

        # store alert
        self.ip_history[ip].append({
            "time": now,
            "severity": alert["severity"],
            "attack_types": alert.get("attack_types", [])
        })

        # remove old events
        self.ip_history[ip] = [
            a for a in self.ip_history[ip]
            if now - a["time"] <= self.window
        ]

        # correlation logic
        stages = set()
        for a in self.ip_history[ip]:
            for t in a["attack_types"]:
                stages.add(t)

        escalated = False
        if len(stages) >= 2:
            escalated = True

        return {
            "correlated": escalated,
            "attack_chain": list(stages),
            "events_in_window": len(self.ip_history[ip])
        }
