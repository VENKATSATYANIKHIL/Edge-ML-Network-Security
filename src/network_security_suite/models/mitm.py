# Filename: mitm.py
# Location: src/network_security_suite/models/
# PURPOSE: MITM detection model for live inference (3-class model)

import numpy as np
import joblib
import json
import os
import pandas as pd
from .base_model import BaseModel

class MITMModel(BaseModel):

    def __init__(self, model_path: str = None):
        super().__init__(model_name="mitm", model_path=model_path)

        self.feature_type = "mitm"

        # EXACT order matching pi_mitm_dataset.csv and your C++ extractor
        self.raw_feature_names = [
            'mac_ip_inconsistency',
            'packet_in_count',
            'packet_rate',
            'rtt (avg)',
            'is_broadcast',
            'arp_request',
            'arp_reply',
            'op_code(arp)'
        ]

    # ---------------------------------------------------------------
    # Load model + scaler
    # ---------------------------------------------------------------
    def load(self):
        print(f"[*] Loading MITM model from {self.model_path}")

        try:
            # Your real filenames
            model_file = os.path.join(self.model_path, 'semi_balanced_rf.pkl')
            scaler_file = os.path.join(self.model_path, 'semi_balanced_scaler.pkl')

            if not os.path.exists(model_file):
                raise FileNotFoundError(f"Model file NOT FOUND: {model_file}")

            if not os.path.exists(scaler_file):
                raise FileNotFoundError(f"Scaler file NOT FOUND: {scaler_file}")

            self.model = joblib.load(model_file)
            self.scaler = joblib.load(scaler_file)

            self.metadata = {"description": "3-class MITM model"}

            print("✓ MITM model loaded successfully.")

        except Exception as e:
            print(f"❌ ERROR loading MITM model: {e}")
            raise

    # ---------------------------------------------------------------
    # Predict 3-class (Normal / Suspicious / Attack)
    # ---------------------------------------------------------------
    def predict(self, flow_data: dict) -> dict:

        try:
            features = flow_data.get("features", [])
            ip_addr = flow_data.get("ip_address", "unknown")

            if len(features) != 8:
                raise ValueError(f"Expected 8 MITM features, got {len(features)}")

            # Correct scaling: DataFrame with column names
            df = pd.DataFrame([features], columns=self.raw_feature_names)
            scaled = self.scaler.transform(df)

            pred_class = int(self.model.predict(scaled)[0])
            proba = self.model.predict_proba(scaled)[0]

            label_map = {0: "Normal", 1: "Suspicious", 2: "Attack"}
            predicted_label = label_map[pred_class]

            result = self.get_prediction_template()
            result.update({
                "verdict": predicted_label,
                "attack_type": "MITM" if predicted_label == "Attack" else "None",
                "confidence": float(max(proba)),
                "ip_address": ip_addr,
                "details": {
                    "raw_class": pred_class,
                    "class_probabilities": {
                        "Normal": float(proba[0]),
                        "Suspicious": float(proba[1]),
                        "Attack": float(proba[2])
                    }
                }
            })

            return result

        except Exception as e:
            result = self.get_prediction_template()
            result.update({
                "verdict": "ERROR",
                "reason": f"MITM prediction failed: {e}"
            })
            return result
