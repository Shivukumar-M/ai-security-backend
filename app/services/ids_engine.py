import pandas as pd
import io
import os
import numpy as np
import logging
from datetime import datetime
from fastapi import UploadFile
from typing import Dict, Any

from app.utils.helper import load_ml_model
from app.services.log_simulator import LogSimulatorService
from app.services.ids_threat_engine import IDSThreatEngine
from app.services.ids_correlation_engine import IDSCorrelationEngine

logger = logging.getLogger(__name__)


class IDSEngineService:
    def __init__(self):
        """
        IDS Engine:
        - ML (best-effort, optional)
        - Signature rules
        - Heuristic rules
        - Threat scoring
        - Correlation
        """
        self.ml_model = load_ml_model("ids_model.pkl")
        self.log_simulator = LogSimulatorService()

        self.threat_engine = IDSThreatEngine()
        self.correlation_engine = IDSCorrelationEngine()

    # -----------------------------------------------------------
    # 1. Preprocessing (ML-safe)
    # -----------------------------------------------------------
    def _preprocess_log_data(self, df: pd.DataFrame) -> pd.DataFrame:
        numeric_df = df.select_dtypes(include=np.number)

        if numeric_df.empty:
            return pd.DataFrame(np.zeros((len(df), 1)), columns=["dummy"])

        return numeric_df

    # -----------------------------------------------------------
    # 2. Core IDS Logic
    # -----------------------------------------------------------
    async def _run_analysis(
        self,
        df: pd.DataFrame,
        file_name: str,
        source_type: str
    ) -> Dict[str, Any]:

        total_packets = len(df)
        if total_packets == 0:
            return {
                "source_type": source_type,
                "file_name": file_name,
                "total_packets": 0,
                "malicious_packets": 0,
                "normal_packets": 0,
                "overall_severity": "Low",
                "attack_breakdown": [],
                "engine_results": [],
                "mitre_techniques": [],
                "file_path": None,
            }

        # -------------------------------------------------------
        # ML PREDICTION (SAFE)
        # -------------------------------------------------------
        df["prediction"] = 0

        if source_type == "GENERATED" and "label" in df.columns:
            # 🔥 SAFE label mapping
            df["prediction"] = df["label"].apply(
                lambda x: 0 if str(x).lower() in ["normal", "benign", "0"] else 1
            )

        else:
            try:
                features_df = self._preprocess_log_data(df)
                expected = getattr(self.ml_model, "feature_names_in_", None)

                if expected is not None:
                    features_df = features_df.reindex(
                        columns=expected,
                        fill_value=0
                    )

                df["prediction"] = self.ml_model.predict(features_df).astype(int)

            except Exception as e:
                logger.error("ML skipped: %s", e)
                df["prediction"] = 0

        # -------------------------------------------------------
        # Ensure required fields
        # -------------------------------------------------------
        df["packet_len"] = df.get("packet_len", 500)
        df["flow_duration"] = df.get("flow_duration", 20000)
        df["dst_port"] = df.get("dst_port", 443)
        df["protocol"] = df.get("protocol", "TCP")

        # -------------------------------------------------------
        # Signature Engine
        # -------------------------------------------------------
        df["sig_flag"] = (
            (df["packet_len"] > 1500) |
            (df["flow_duration"] > 100000)
        ).astype(int)

        # -------------------------------------------------------
        # Heuristic Engine
        # -------------------------------------------------------
        df["heur_flag"] = (
            ((df["dst_port"] < 50) & (df["packet_len"] > 900)) |
            (df["protocol"].isin(["ICMP"]))
        ).astype(int)

        # -------------------------------------------------------
        # Final Alert (ROW-LEVEL, SAFE)
        # -------------------------------------------------------
        df["final_alert"] = (
            (df["prediction"] == 1) |
            (df["sig_flag"] == 1) |
            (df["heur_flag"] == 1)
        ).astype(int)

        malicious_packets = int(df["final_alert"].sum())
        malicious_packets = min(malicious_packets, total_packets)
        normal_packets = max(total_packets - malicious_packets, 0)

        # -------------------------------------------------------
        # Attack Classification (FOR BAR CHART)
        # -------------------------------------------------------
        def classify_attack(row):
            if row["sig_flag"] == 1:
                return "DoS"
            if row["heur_flag"] == 1:
                return "Brute Force"
            if row["prediction"] == 1:
                return "ML Anomaly"
            return "Normal"

        df["attack_type"] = df.apply(classify_attack, axis=1)

        breakdown = []
        for atk, cnt in (
            df[df["final_alert"] == 1]["attack_type"]
            .value_counts()
            .items()
        ):
            severity = "High" if cnt > 50 else "Medium" if cnt > 5 else "Low"
            breakdown.append({
                "attack_type": atk,
                "count": int(cnt),
                "severity": severity,
            })

        # -------------------------------------------------------
        # Overall Severity
        # -------------------------------------------------------
        ratio = malicious_packets / total_packets
        if ratio >= 0.30:
            overall_severity = "High"
        elif ratio >= 0.05:
            overall_severity = "Medium"
        else:
            overall_severity = "Low"

        # -------------------------------------------------------
        # Engine Explainability Panel
        # -------------------------------------------------------
        engine_results = [
            {
                "engine": "ML Behavior Engine",
                "verdict": "Malicious" if df["prediction"].sum() else "Clean",
                "score": float(df["prediction"].mean()),
            },
            {
                "engine": "Signature Engine",
                "verdict": "Detected" if df["sig_flag"].sum() else "No Match",
                "score": float(df["sig_flag"].mean()),
            },
            {
                "engine": "Heuristic Engine",
                "verdict": "Suspicious" if df["heur_flag"].sum() else "Normal",
                "score": float(df["heur_flag"].mean()),
            },
        ]

        return {
            "source_type": source_type,
            "file_name": file_name,
            "total_packets": total_packets,
            "malicious_packets": malicious_packets,
            "normal_packets": normal_packets,
            "overall_severity": overall_severity,
            "attack_breakdown": breakdown,
            "engine_results": engine_results,
            "mitre_techniques": [],
        }

    # -----------------------------------------------------------
    # 3. Real-time / Streaming IDS
    # -----------------------------------------------------------
    def analyze_single_event(self, event: dict) -> Dict[str, Any]:
        ip = event.get("ip", "unknown")

        signals = {
            "request_rate": event.get("request_rate", 0),
            "sql_injection": event.get("sql_injection", False),
            "xss": event.get("xss", False),
            "repeat_offender": event.get("repeat_offender", False),
        }

        threat = self.threat_engine.calculate(signals)
        correlation = self.correlation_engine.correlate(ip, threat)

        if correlation["correlated"] and threat["severity"] != "Critical":
            threat["severity"] = "Critical"
            threat["threat_score"] = min(threat["threat_score"] + 20, 100)
            threat["correlated_attack"] = True
        else:
            threat["correlated_attack"] = False

        return {
            "ip": ip,
            "threat": threat,
            "correlation": correlation,
        }

    # -----------------------------------------------------------
    # 4. Auto-generation
    # -----------------------------------------------------------
    async def generate_and_analyze(self, log_type: str, count: int) -> Dict[str, Any]:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"sim_{log_type}_{timestamp}.csv"

        df = self.log_simulator._generate_log_dataframe(log_type, count)
        log_path = self.log_simulator._save_log_dataframe(df, file_name)

        summary = await self._run_analysis(df, file_name, "GENERATED")
        summary["file_path"] = log_path
        return summary

    # -----------------------------------------------------------
    # 5. Uploaded CSV Analysis
    # -----------------------------------------------------------
    async def analyze_uploaded_file(self, file: UploadFile) -> Dict[str, Any]:
        contents = await file.read()
        file_name = file.filename

        if not file_name.lower().endswith(".csv"):
            raise ValueError("Please upload a CSV file.")

        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))

        save_dir = os.path.join(os.getcwd(), "backend", "app", "media", "uploads")
        os.makedirs(save_dir, exist_ok=True)

        file_path = os.path.join(save_dir, file_name)
        with open(file_path, "wb") as f:
            f.write(contents)

        summary = await self._run_analysis(df, file_name, "UPLOADED")
        summary["file_path"] = file_path
        return summary
