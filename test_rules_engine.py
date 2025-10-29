from bluesentinel.rules_engine import RulesEngine, Rule
from datetime import datetime, timedelta

def test_compare_window_detection():
    rule = Rule({
        "id": "TEST",
        "title": "Test",
        "where": {"all": [{"field":"event.module","equals":"auth"},{"field":"event.action","equals":"FAILED_PASSWORD"}]},
        "aggregate": {"group_by":"source.ip","within":"1h","count":">=3"}
    })
    re = RulesEngine([rule])
    ev_base = {"event":{"module":"auth","action":"FAILED_PASSWORD"},"source":{"ip":"1.2.3.4"}}
    a1 = re.evaluate(ev_base)[0:]
    a2 = re.evaluate(ev_base)[0:]
    a3 = re.evaluate(ev_base)[0:]
    assert len(a3) >= 1  # at least one alert on third event
