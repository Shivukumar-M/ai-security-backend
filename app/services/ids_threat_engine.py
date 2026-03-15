# backend/app/services/ids_threat_engine.py

class IDSThreatEngine:
    """
    Calculates threat score, severity, confidence,
    and enriches attacks with MITRE ATT&CK mapping.
    """

    # -------------------------------------------------
    # MITRE ATT&CK MAPPING (Lightweight & Academic-safe)
    # -------------------------------------------------
    MITRE_MAP = {
        "SQL Injection": {
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application",
        },
        "Brute Force / DoS": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique": "Brute Force",
        },
        "Cross-Site Scripting": {
            "tactic": "Initial Access",
            "technique_id": "T1059",
            "technique": "Command and Scripting Interpreter",
        },
    }

    def calculate(self, signals: dict) -> dict:
        score = 0
        attack_types = []

        # -------------------------
        # Rate-based detection
        # -------------------------
        request_rate = signals.get("request_rate", 0)
        if request_rate > 50:
            score += 30
            attack_types.append("Brute Force / DoS")

        # -------------------------
        # Payload-based detection
        # -------------------------
        if signals.get("sql_injection"):
            score += 40
            attack_types.append("SQL Injection")

        if signals.get("xss"):
            score += 30
            attack_types.append("Cross-Site Scripting")

        # -------------------------
        # Repeated behavior
        # -------------------------
        if signals.get("repeat_offender"):
            score += 20

        # -------------------------
        # Score normalization
        # -------------------------
        score = min(score, 100)

        # -------------------------
        # Severity mapping
        # -------------------------
        if score >= 80:
            severity = "Critical"
        elif score >= 60:
            severity = "High"
        elif score >= 30:
            severity = "Medium"
        else:
            severity = "Low"

        # -------------------------
        # Confidence (simple model)
        # -------------------------
        confidence = round(score / 100, 2)

        # -------------------------
        # Recommended action
        # -------------------------
        if severity in ["High", "Critical"]:
            action = "Temporarily block IP"
        else:
            action = "Monitor"

        # -------------------------
        # 🔥 MITRE ATT&CK ENRICHMENT
        # -------------------------
        mitre_techniques = []
        for atk in set(attack_types):
            if atk in self.MITRE_MAP:
                mitre_techniques.append(self.MITRE_MAP[atk])

        return {
            "threat_score": score,
            "severity": severity,
            "confidence": confidence,
            "attack_types": list(set(attack_types)),
            "mitre_techniques": mitre_techniques,
            "recommended_action": action,
        }
