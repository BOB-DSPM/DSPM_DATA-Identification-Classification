# scripts/call_collect.py
import json
from aegis_client import trigger_collect  

if __name__ == "__main__":
    data = trigger_collect(
        server_host="http://43.202.228.52:9000/aegis",
        collector_api="http://43.202.228.52:9000/collector",
        only_detected=True,
    )
    print(json.dumps(data, ensure_ascii=False, indent=2))