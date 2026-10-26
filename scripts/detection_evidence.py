"""Offline assertions for normalized R2 evidence; not a live metrics collector.

Every query must succeed and be complete. A trusted R2 collector must retain raw
responses and explain normalization. A hand-authored JSON file is not runtime proof.
"""
import datetime
import re
import uuid

EXPECTED = {
    'ssh': ('/lab/logs/ssh/auth.log', 'crowdsecurity/ssh-bf', '203.0.113.50', 8),
    'web': ('/lab/logs/web/access.log', 'crowdsecurity/http-probing', '198.51.100.77', 12),
}
QUERIES = {'acquisition', 'parsers', 'scenarios', 'alerts', 'decisions', 'bouncers'}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    check(type(value) is int and value >= 0, 'Counters/IDs must be nonnegative integers')
    return value


def timestamp(value):
    check(isinstance(value, str) and value.endswith('Z'), 'Require explicit UTC timestamps')
    return datetime.datetime.fromisoformat(value[:-1] + '+00:00')


def verify_evidence(evidence):
    check(evidence.get('format_version') == 1, 'Unsupported detection evidence format')
    check(re.fullmatch(r'qa-[a-z0-9-]{1,28}', evidence.get('installation_id', '')), 'Evidence must use a separate qa- installation')
    uuid.UUID(evidence['run_id'])
    started, completed = timestamp(evidence['started_at']), timestamp(evidence['completed_at'])
    check(completed > started, 'Invalid detection interval')
    before, after = evidence['before'], evidence['after']
    check(bool(before['engine_id']) and before['engine_id'] == after['engine_id'] and
          bool(before['boot_id']) and before['boot_id'] == after['boot_id'], 'Engine/restart changed during detection')
    all_ids = []
    for snapshot in [before, after]:
        check(set(snapshot['queries']) == QUERIES, 'Missing query status')
        for query in snapshot['queries'].values():
            check(type(query.get('exit_code')) is int and query.get('exit_code') == 0 and query.get('complete') is True and query.get('error') is None,
                  'Failed/incomplete query cannot satisfy detection')
        check(isinstance(snapshot['alerts'], list) and isinstance(snapshot['decisions'], list) and
              snapshot['bouncers'] == [] and snapshot['enforcement_enabled'] is False, 'Detection-only boundary not established')
        check(isinstance(snapshot['loaded_scenarios'], list), 'Malformed scenario list')
        ids = [number(alert['id']) for alert in snapshot['alerts']]
        check(len(ids) == len(set(ids)), 'Duplicate alert IDs')
        all_ids.append(set(ids))
    baseline = all_ids[0]
    check(baseline <= all_ids[1], 'Incomplete alert history or database changed during test')
    verified = {}
    for name, (source, scenario, ip, submitted) in EXPECTED.items():
        check(scenario in before['loaded_scenarios'] and scenario in after['loaded_scenarios'], 'Expected scenario not loaded')
        check(evidence['submitted'][name] == submitted, 'Unexpected synthetic burst count')
        for counter in ['read', 'parsed']:
            delta = number(after['sources'][source][counter]) - number(before['sources'][source][counter])
            check(delta >= submitted, 'No proven consumption/parsing for ' + source)
        check(number(after['sources'][source]['unparsed']) == number(before['sources'][source]['unparsed']), 'Unparsed synthetic events')
        for counter in ['poured', 'overflows']:
            check(number(after['scenario_activity'][scenario][counter]) > number(before['scenario_activity'][scenario][counter]),
                  'No fresh expected scenario activity: ' + scenario)
        fresh = []
        for alert in after['alerts']:
            if alert['id'] in baseline:
                continue
            if (alert.get('scenario') == scenario and alert.get('source') == {'scope': 'Ip', 'value': ip}
                    and started <= timestamp(alert['start_at']) <= timestamp(alert['stop_at']) <= completed):
                fresh.append(alert['id'])
        check(bool(fresh), 'No new exact-scenario/source alert within this run: ' + scenario)
        verified[name] = fresh
    return {'alerts': verified, 'decisions': len(after['decisions']), 'enforcement': 'not enabled'}
