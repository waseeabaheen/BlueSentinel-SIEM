import regex as re
from typing import Dict, Any
from .utils import set_if

# Example line:
# Oct 12 22:14:15 host sshd[12345]: Failed password for root from 1.2.3.4 port 5555 ssh2

SSH_FAILED = re.compile(r".*sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)")
SSH_ACCEPT = re.compile(r".*sshd\[\d+\]: Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)")

def parse(line: str) -> Dict[str, Any]:
    ev = {
        "event": {"module": "auth", "action": None},
        "source": {"ip": None, "port": None},
        "user": {"name": None},
    }
    m = SSH_FAILED.match(line)
    if m:
        ev["event"]["action"] = "FAILED_PASSWORD"
        ev["user"]["name"] = m.group("user")
        ev["source"]["ip"] = m.group("ip")
        ev["source"]["port"] = int(m.group("port"))
        return ev
    m = SSH_ACCEPT.match(line)
    if m:
        ev["event"]["action"] = "ACCEPTED_LOGIN"
        ev["user"]["name"] = m.group("user")
        ev["source"]["ip"] = m.group("ip")
        ev["source"]["port"] = int(m.group("port"))
        return ev
    # Fallback generic
    return {"event": {"module": "syslog", "action": "MESSAGE"}}
