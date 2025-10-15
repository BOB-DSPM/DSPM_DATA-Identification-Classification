# scripts/call_collect.py
import json
from aegis_client import trigger_collect  

if __name__ == "__main__":
    data = trigger_collect(
        # AEGIS 서버는 게이트웨이의 /aegis 밑으로 노출
        server_host="http://<gateway-host>:9000/aegis",
        # Collector는 /collector 밑으로 노출
        collector_api="http://<gateway-host>:9000/collector",
        only_detected=True,
    )
    print(json.dumps(data, ensure_ascii=False, indent=2))
