import json
from typing import Dict, Any

def parse(line: str) -> Dict[str, Any]:
    try:
        obj = json.loads(line)
    except Exception:
        return {"event": {"module": "json", "action": "PARSE_ERROR"}}
    # Very naive CloudTrail-ish mapping
    module = obj.get("eventSource", "json")
    action = obj.get("eventName", "EVENT")
    user = obj.get("userIdentity", {}).get("userName")
    src_ip = obj.get("sourceIPAddress")
    return {
        "event": {"module": module, "action": action},
        "source": {"ip": src_ip, "port": None},
        "user": {"name": user},
    }
