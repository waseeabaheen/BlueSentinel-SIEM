import regex as re
from typing import Dict, Any

# Common Log Format: 127.0.0.1 - frank [10/Oct/2025:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326

CLF = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) \S+'
)

def parse(line: str) -> Dict[str, Any]:
    m = CLF.match(line)
    if not m:
        return {"event": {"module": "apache", "action": "LOG"}}
    d: Dict[str, Any] = {
        "event": {"module": "apache", "action": "HTTP_ACCESS"},
        "source": {"ip": m.group("ip"), "port": None},
        "http": {"method": m.group("method"), "status_code": int(m.group("status")), "path": m.group("path")},
    }
    return d
