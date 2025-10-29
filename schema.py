from datetime import datetime
from typing import Any, Dict, Optional

def base_event(raw: str) -> Dict[str, Any]:
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "event": {"module": None, "action": None},
        "source": {"ip": None, "port": None},
        "destination": {"ip": None, "port": None},
        "user": {"name": None},
        "http": {"method": None, "status_code": None, "path": None},
        "log": {"original": raw},
        "tags": [],
    }
