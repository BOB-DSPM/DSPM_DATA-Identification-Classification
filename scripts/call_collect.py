# scripts/call_collect.py
import json
from aegis_client import trigger_collect  

if __name__ == "__main__":
    data = trigger_collect(
        server_host="http://211.44.183.248:9000/aegis",
        collector_api="http://211.44.183.248:9000/collector",
        only_detected=True,
    )
    print(json.dumps(data, ensure_ascii=False, indent=2))
