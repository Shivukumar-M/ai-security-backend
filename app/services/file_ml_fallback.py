# backend/app/file_ml_fallback.py
import hashlib
from collections import Counter
import math

def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for c in counts.values():
        p = c / len(data)
        entropy -= p * math.log2(p)
    return entropy

class FileMLFallback:
    """
    Simple deterministic fallback analyzer:
    - Uses entropy and basic keyword heuristics
    - Returns a structured analysis similar to a real ML engine
    """

    SUSPICIOUS_INDICATORS = [
        b"getasynckeystate", b"setwindowshookex", b"createremotethread",
        b"sendinput", b"keylogger", b"keystroke", b"registerhotkey",
        b"openprocess", b"writeprocessmemory", b"virtualallocex",
    ]

    def analyze_file(self, content: bytes):
        entropy = shannon_entropy_bytes(content)
        lower = content.lower()

        hits = []
        for i in self.SUSPICIOUS_INDICATORS:
            try:
                if i in lower:
                    hits.append(i.decode(errors="ignore"))
            except Exception:
                continue

        suspicious = len(hits) > 0 or entropy >= 7.5

        # Build engine-like result
        return {
            "malicious_count": 1 if suspicious else 0,
            "total_engines": 1,
            "type_description": "HeuristicResult",
            "engine_results": {
                "FileMLFallback": {
                    "category": "malicious" if suspicious else "harmless",
                    "result": "malicious" if suspicious else "clean",
                    "details": {
                        "entropy": round(entropy, 3),
                        "indicators": hits
                    }
                }
            },
            "file_properties": {"size_bytes": len(content)}
        }
