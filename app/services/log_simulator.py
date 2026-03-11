# backend/app/services/log_simulator.py

import pandas as pd
import numpy as np
import os
import random

class LogSimulatorService:
    def __init__(self):
        # Random seed disabled for full randomness every time
        pass

    # ---------------------------
    # Utility: Add natural noise
    # ---------------------------
    def _add_noise(self, arr, noise_level=0.15):
        noise = np.random.normal(0, noise_level, len(arr))
        return (arr * (1 + noise)).astype(int)

    # ---------------------------
    # Normal Traffic Generator
    # ---------------------------
    def _generate_normal_flow(self, count):
        packet_len = np.random.randint(200, 900, count)
        flow_duration = np.random.randint(3000, 70000, count)

        return pd.DataFrame({
            "packet_len": self._add_noise(packet_len),
            "flow_duration": self._add_noise(flow_duration),
            "dst_port": np.random.choice([80, 443, 53, 8080, 3306], count),
            "protocol": np.random.choice(["TCP", "UDP", "ICMP"], count),
            "attack_type": ["Normal"] * count,
            "label": [0] * count,
        })

    # ---------------------------
    # DoS High Traffic
    # ---------------------------
    def _generate_dos_flow(self, count):
        packet_len = np.random.randint(1400, 3500, count)
        flow_duration = np.random.randint(90000, 200000, count)

        return pd.DataFrame({
            "packet_len": self._add_noise(packet_len, 0.25),
            "flow_duration": self._add_noise(flow_duration, 0.25),
            "dst_port": np.random.choice([80, 443], count),
            "protocol": np.random.choice(["TCP", "UDP"], count),
            "attack_type": ["DoS"] * count,
            "label": [1] * count,
        })

    # ---------------------------
    # Port Scan (random ports)
    # ---------------------------
    def _generate_portscan_flow(self, count):
        ports = np.random.randint(1, 65535, count)

        return pd.DataFrame({
            "packet_len": np.random.randint(50, 400, count),
            "flow_duration": np.random.randint(500, 5000, count),
            "dst_port": ports,
            "protocol": np.random.choice(["TCP", "UDP"], count),
            "attack_type": ["PortScan"] * count,
            "label": [1] * count,
        })

    # ---------------------------
    # Mixed Traffic (Randomized)
    # ---------------------------
    def _generate_log_dataframe(self, log_type, count):

        if log_type == "Normal":
            return self._generate_normal_flow(count)

        elif log_type == "DoS":
            return self._generate_dos_flow(count)

        elif log_type == "PortScan":
            return self._generate_portscan_flow(count)

        elif log_type == "Mixed":
            # Randomized distribution every time
            c_normal = random.randint(int(count * 0.3), int(count * 0.6))
            c_dos = random.randint(int(count * 0.1), int(count * 0.4))
            c_scan = count - c_normal - c_dos

            df = pd.concat([
                self._generate_normal_flow(c_normal),
                self._generate_dos_flow(c_dos),
                self._generate_portscan_flow(c_scan)
            ], ignore_index=True)

            # Random shuffle for realism
            df = df.sample(frac=1).reset_index(drop=True)
            return df

        else:
            raise ValueError("Unknown log_type")

    # ---------------------------
    # Save simulated logs
    # ---------------------------
    def _save_log_dataframe(self, df, file_name):
        save_dir = os.path.join(os.getcwd(), "backend", "app", "media", "generated_logs")
        os.makedirs(save_dir, exist_ok=True)

        file_path = os.path.join(save_dir, file_name)
        df.to_csv(file_path, index=False)
        return file_path
