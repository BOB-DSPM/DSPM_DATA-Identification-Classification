# scripts/call_collect.py
import os
import json
from aegis_client import trigger_collect

SAGE_HOST = os.getenv("SAGE_HOST", "43.202.228.52")

AEGIS_BASE = f"http://{SAGE_HOST}:9000"

if __name__ == "__main__":
    data = trigger_collect(
        server_host=f"{AEGIS_BASE}/aegis",
        collector_api=f"{AEGIS_BASE}/collector",
        only_detected=True,
    )
    print(json.dumps(data, ensure_ascii=False, indent=2))
