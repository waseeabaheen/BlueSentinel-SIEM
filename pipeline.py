from typing import Dict, Any, Optional
from . import storage, schema
from .rules_engine import RulesEngine
from .parsers import syslog as syslog_parser
from .parsers import apache as apache_parser
from .parsers import json_parser as json_parser

class Pipeline:
    def __init__(self, rules_dir: str = "rules"):
        storage.init_db()
        self.engine = RulesEngine.load_from_dir(rules_dir)

    def ingest_line(self, source_type: str, line: str) -> Dict[str, Any]:
        base = schema.base_event(line.rstrip("\n"))
        parsed: Dict[str, Any] = {}
        if source_type == "syslog":
            parsed = syslog_parser.parse(line)
        elif source_type == "apache":
            parsed = apache_parser.parse(line)
        elif source_type == "json":
            parsed = json_parser.parse(line)
        else:
            parsed = {"event": {"module": "unknown", "action": "LINE"}}

        # merge
        ev = {**base}
        for key, val in parsed.items():
            if isinstance(val, dict) and key in ev:
                ev[key].update(val)
            else:
                ev[key] = val

        # store
        storage.insert_event(ev)

        # detect
        alerts = self.engine.evaluate(ev)
        for a in alerts:
            storage.insert_alert(a)

        return ev
