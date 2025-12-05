# Filename: orchestrator.py
# Location: src/network_security_suite/
# PURPOSE: Central intelligent orchestrator for C2C, DDoS, MITM attack detection

import os
import sys
from typing import Dict, Any


class Orchestrator:
    """
    Unified orchestrator for C2C, DDoS, MITM detection.
    Only MITM logic is modified — others remain untouched.
    """

    def __init__(self, model_base_path: str):
        self.model_base_path = model_base_path
        self.models = {}
        print("[*] Orchestrator initialized (data-type-aware sequential detection)")

    # ============================================================
    # 1. DATA TYPE IDENTIFICATION
    # ============================================================
    def _identify_data_type(self, flow_data: Dict[str, Any]) -> str:

        if flow_data.get("feature_type") == "mitm":
            return "mitm"

        if "features" in flow_data and isinstance(flow_data["features"], list):
            if len(flow_data["features"]) == 8 and "ip_address" in flow_data:
                return "mitm"

        if all(key in flow_data for key in ['proto', 'service', 'duration', 'orig_bytes', 'resp_bytes']):
            return "c2c"

        if "features" in flow_data and isinstance(flow_data["features"], dict):
            ddos_keys = ["Packets_Per_Sec", "Bytes_Per_Sec", "Unique_IPs"]
            if all(k in flow_data["features"] for k in ddos_keys):
                return "ddos"

        return "unknown"

    # ============================================================
    # MODEL LOADING (unchanged)
    # ============================================================
    def _load_c2c_model(self):
        if "c2c" not in self.models:
            try:
                from .models.c2c import C2CModel
                self.models["c2c"] = C2CModel(model_path=os.path.join(self.model_base_path, "c2c"))
                print("✓ C2C model loaded")
            except Exception as e:
                print(f"⚠ Failed to load C2C model: {e}")
                return None
        return self.models["c2c"]

    def _load_ddos_model(self):
        if "ddos" not in self.models:
            try:
                from .models.ddos import DDoSModel
                self.models["ddos"] = DDoSModel(model_path=os.path.join(self.model_base_path, "ddos"))
                print("✓ DDoS model loaded")
            except Exception as e:
                print(f"⚠ Failed to load DDoS model: {e}")
                return None
        return self.models["ddos"]

    def _load_mitm_model(self):
        if "mitm" not in self.models:
            try:
                from .models.mitm import MITMModel
                self.models["mitm"] = MITMModel(model_path=os.path.join(self.model_base_path, "mitm"))
                print("✓ MITM model loaded")
            except Exception as e:
                print(f"⚠ Failed to load MITM model: {e}")
                return None
        return self.models["mitm"]

    # ============================================================
    # MAIN ENTRY
    # ============================================================
    def process_flow(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:

        data_type = self._identify_data_type(flow_data)
        print(f"[*] Identified data type: {data_type}")

        if data_type == "c2c":
            return self._process_c2c_data(flow_data)

        if data_type == "ddos":
            return self._process_ddos_data(flow_data)

        if data_type == "mitm":
            return self._process_mitm_data(flow_data)

        return {
            "verdict": "UNKNOWN",
            "attack_type": "None",
            "confidence": "LOW",
            "reason": "Unknown data structure",
            "detection_path": "unknown_data_type"
        }

    # ============================================================
    # C2C / DDoS (unchanged)
    # ============================================================
    def _process_c2c_data(self, flow_data):
        if self._resembles_c2c_attack(flow_data):
            c2c_model = self._load_c2c_model()
            if c2c_model:
                result = c2c_model.predict(self._extract_c2c_features(flow_data))
                result["detection_path"] = "c2c_conditions_met"
                return result
            return self._c2c_rule_based_fallback(flow_data)

        return {"verdict": "BENIGN", "attack_type": "None", "confidence": "HIGH",
                "reason": "No C2C attack patterns detected",
                "detection_path": "c2c_conditions_not_met"}

    def _process_ddos_data(self, flow_data):
        if self._resembles_ddos_attack(flow_data):
            ddos_model = self._load_ddos_model()
            if ddos_model:
                result = ddos_model.predict(self._extract_ddos_features(flow_data))
                result["detection_path"] = "ddos_conditions_met"
                return result
            return self._ddos_rule_based_fallback(flow_data)

        return {"verdict": "BENIGN", "attack_type": "None", "confidence": "HIGH",
                "reason": "No DDoS attack patterns detected",
                "detection_path": "ddos_conditions_not_met"}

    # ============================================================
    # 🔥 MITM PROCESSING (UPDATED)
    # ============================================================
    def _process_mitm_data(self, flow_data):
        if self._resembles_mitm_attack(flow_data):
            print("[MITM] MITM-like behavior detected. Loading model...")
            mitm_model = self._load_mitm_model()

            if mitm_model:
                result = mitm_model.predict(self._extract_mitm_features(flow_data))
                result["detection_path"] = "mitm_conditions_met"
                return result

            return self._mitm_rule_based_fallback(flow_data)

        return {
            "verdict": "BENIGN",
            "attack_type": "None",
            "confidence": "HIGH",
            "reason": "MITM patterns not detected",
            "detection_path": "mitm_conditions_not_met"
        }

    # ============================================================
    # ✔✔✔ MITM RULE ENGINE (FULLY CORRECTED)
    # ============================================================
    def _resembles_mitm_attack(self, flow_data: Dict[str, Any]) -> bool:
        """
        Deterministic rules matching dataset + real ARP behavior.
        Corrected to avoid false positives and align with ML model.
        """

        try:
            f = flow_data.get("features", [])
            if len(f) != 8:
                return False

            mac_mismatch = int(f[0])
            packet_count = int(f[1])
            packet_rate = float(f[2])
            rtt_avg = float(f[3])
            is_broadcast = int(f[4])
            arp_request = int(f[5])
            arp_reply = int(f[6])
            opcode = int(f[7])

            # RULE A: MAC mismatch + some traffic
            if mac_mismatch == 1 and packet_count >= 2:
                return True

            # RULE B: High packet rate
            if packet_rate > 0.06:
                return True

            # RULE C: Reply + non-trivial rate
            if arp_reply == 1 and packet_rate > 0.08:
                return True

            # RULE D: Broadcast + request + moderate rate
            if is_broadcast == 1 and arp_request == 1 and packet_rate > 0.05:
                return True

            # RULE E: opcode reply anomaly
            if opcode == 2 and (mac_mismatch == 1 or packet_rate > 0.05):
                return True

            return False

        except Exception as e:
            print("[MITM-RULE-ERROR]", e)
            return False

    # ============================================================
    # FEATURE EXTRACTION (unchanged)
    # ============================================================
    def _extract_c2c_features(self, flow):
        keys = ["proto", "service", "duration", "orig_bytes",
                "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts"]
        return {k: flow.get(k, 0) for k in keys}

    def _extract_ddos_features(self, flow):
        return flow.get("features", {})

    def _extract_mitm_features(self, flow):
        return {
            "ip_address": flow.get("ip_address", "unknown"),
            "features": flow.get("features", [])
        }

    # ============================================================
    # FALLBACKS (unchanged)
    # ============================================================
    def _c2c_rule_based_fallback(self, flow):
        return {"verdict": "SUSPICIOUS", "attack_type": "C2C", "confidence": "MEDIUM"}

    def _ddos_rule_based_fallback(self, flow):
        return {"verdict": "SUSPICIOUS", "attack_type": "DDoS", "confidence": "MEDIUM"}

    def _mitm_rule_based_fallback(self, flow):
        return {"verdict": "SUSPICIOUS", "attack_type": "MITM", "confidence": "MEDIUM"}

