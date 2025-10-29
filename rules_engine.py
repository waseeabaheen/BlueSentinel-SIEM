import yaml
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Deque, Tuple

class Rule:
    def __init__(self, raw: Dict[str, Any]):
        self.id = raw.get("id")
        self.title = raw.get("title")
        self.severity = raw.get("severity", "low")
        self.description = raw.get("description", "")
        self.tags = raw.get("tags", [])
        self.where = raw.get("where", {})  # {"all":[{"field":"event.module","equals":"auth"}, ...]} or {"any":[...]}
        self.aggregate = raw.get("aggregate")  # {"group_by":"source.ip","within":"5m","count":">=10"}

    def match_event(self, ev: Dict[str, Any]) -> bool:
        def get_field(d, dotted):
            x = d
            for p in dotted.split("."):
                if isinstance(x, dict):
                    x = x.get(p)
                else:
                    return None
            return x

        def check(cond):
            field = cond.get("field")
            op = next((k for k in ["equals", "contains", "in", "regex"] if k in cond), None)
            if not op:
                return False
            val = get_field(ev, field)
            target = cond.get(op)
            if op == "equals":
                return val == target
            if op == "contains":
                return (val is not None) and (str(target) in str(val))
            if op == "in":
                return val in target
            if op == "regex":
                import regex as re
                return (val is not None) and re.search(target, str(val)) is not None
            return False

        if "all" in self.where:
            return all(check(c) for c in self.where["all"])
        if "any" in self.where:
            return any(check(c) for c in self.where["any"])
        return True

def parse_duration(s: str) -> timedelta:
    # supports Ns, Nm, Nh
    num = int("".join(ch for ch in s if ch.isdigit()))
    if s.endswith("s"):
        return timedelta(seconds=num)
    if s.endswith("m"):
        return timedelta(minutes=num)
    if s.endswith("h"):
        return timedelta(hours=num)
    return timedelta(minutes=num)

class RulesEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules
        # state: rule_id -> key -> deque[timestamps]
        self.state: Dict[str, Dict[str, Deque[datetime]]] = defaultdict(lambda: defaultdict(deque))

    @classmethod
    def load_from_dir(cls, path: str) -> "RulesEngine":
        import os, glob
        rules = []
        for f in glob.glob(os.path.join(path, "*.y*ml")):
            with open(f, "r", encoding="utf-8") as fh:
                y = yaml.safe_load(fh)
                if isinstance(y, list):
                    for item in y:
                        rules.append(Rule(item))
                else:
                    rules.append(Rule(y))
        return cls(rules)

    def evaluate(self, ev: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        now = datetime.utcnow()
        for rule in self.rules:
            if not rule.match_event(ev):
                continue

            if rule.aggregate:
                group_by = rule.aggregate.get("group_by")
                within = parse_duration(rule.aggregate.get("within", "5m"))
                count_expr = rule.aggregate.get("count", ">=10")
                key = str(_get(ev, group_by)) if group_by else "_"
                dq = self.state[rule.id][key]
                dq.append(now)
                # trim old
                while dq and (now - dq[0]) > within:
                    dq.popleft()

                if _compare(len(dq), count_expr):
                    alerts.append(_mk_alert(rule, ev, now, {"group": key, "count": len(dq)}))
            else:
                alerts.append(_mk_alert(rule, ev, now, {}))
        return alerts

def _mk_alert(rule: Rule, ev: Dict[str, Any], ts: datetime, ctx: Dict[str, Any]) -> Dict[str, Any]:
    from json import dumps
    return {
        "ts": ts.isoformat() + "Z",
        "rule_id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "description": rule.description,
        "context": dumps({"event": ev, "ctx": ctx})[:4000],  # truncate for sqlite
    }

def _get(d, dotted):
    x = d
    for p in dotted.split("."):
        if isinstance(x, dict):
            x = x.get(p)
        else:
            return None
    return x

def _compare(n: int, expr: str) -> bool:
    # expr like ">=10", ">5", "==3"
    import operator
    ops = {">=": operator.ge, "<=": operator.le, "==": operator.eq, ">": operator.gt, "<": operator.lt}
    for sym, fn in ops.items():
        if expr.startswith(sym):
            try:
                return fn(n, int(expr[len(sym):]))
            except ValueError:
                return False
    return False
