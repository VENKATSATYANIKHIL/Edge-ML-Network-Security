#!/usr/bin/env python3

# Filename: run_orchestrator.py
# Location: nss_project/

import os
import json
import sys

# Import orchestrator from the package
from src.network_security_suite.orchestrator import Orchestrator


def main():
    """
    Sequential attack detection: C2C → DDoS → MITM.
    ML models are lazily loaded only when rules identify matching patterns.
    """
    print("[+] Initializing Network Security Suite (Sequential Detection)...")

    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        model_base_path = os.path.join(project_root, 'src', 'trained_models')

        orchestrator = Orchestrator(model_base_path=model_base_path)

    except Exception as e:
        print(f"[FATAL] Could not initialize Orchestrator: {e}", file=sys.stderr)
        sys.exit(1)

    print("[*] Detection Engine Active.")
    print("[*] Pipeline: C2C → DDoS → MITM (Rules → ML → Verdict)\n")
    print("[*] Ready to process live JSON data...\n")

    # Read JSON lines from STDIN (streaming)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            flow_data = json.loads(line)

        except json.JSONDecodeError:
            print(f"[Warning] Invalid JSON: {line}", file=sys.stderr)
            continue

        try:
            result = orchestrator.process_flow(flow_data)
            print(json.dumps(result, ensure_ascii=False))
            sys.stdout.flush()

        except Exception as e:
            print(f"[Error] Processing failed: {e}", file=sys.stderr)
            continue


if __name__ == "__main__":
    main()
