"""Strict offline fixture policy. Checks format AND reviewed byte integrity."""
import datetime
import hashlib
import ipaddress
import json
import re
from pathlib import Path

MONTHS = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
NETS = [ipaddress.ip_network(x) for x in ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']]
FILES = {'ssh/auth.log': 10, 'web/access.log': 14}
SSH = re.compile(r'(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) labhost sshd\[\d+\]: (?P<result>Accepted|Failed) password for (?:invalid user )?[a-z][a-z0-9_]* from (?P<ip>[0-9.]+) port (?P<port>\d+) ssh2')
WEB = re.compile(r'(?P<ip>[0-9.]+) - - \[(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2}) \+0000\] "GET (?P<path>/[^\s"]*) HTTP/1\.1" (?P<status>200|404) \d+ "-" "lab-(?:benign|synthetic-probe)/1\.0"')


def valid_ip(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or not any(address in network for network in NETS):
        raise ValueError('Fixture IP must be a documentation-only IPv4 address: ' + value)


def validate_fixtures(root):
    root = Path(root)
    directory = root / 'fixtures/logs'
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Missing/unsafe fixture directory')
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    if actual != set(FILES) or any(p.is_symlink() for p in directory.rglob('*')):
        raise ValueError('Require exactly the two reviewed fixture files, with no symlinks')
    manifest = json.loads((root / 'fixtures/manifest.json').read_text(encoding='utf-8'))
    if manifest.get('format_version') != 1 or set(manifest.get('files', {})) != set(FILES):
        raise ValueError('Unsupported/incomplete fixture integrity manifest')
    counts = {}
    for name, expected_count in FILES.items():
        raw = (directory / name).read_bytes()
        if not raw or b'\r' in raw or raw.startswith(b'\xef\xbb\xbf') or not raw.endswith(b'\n'):
            raise ValueError('Fixture must be nonempty UTF-8 without BOM, LF-only, with final newline: ' + name)
        text = raw.decode('utf-8', errors='strict')
        matches = []
        for number, line in enumerate(text.splitlines(), 1):
            if number == 1 and line.startswith('# CrowdSec Guard synthetic '):
                continue
            match = (SSH if name.startswith('ssh/') else WEB).fullmatch(line)
            if not match:
                raise ValueError('Malformed fixture structure: %s:%d' % (name, number))
            event = match.groupdict()
            valid_ip(event['ip'])
            for ip in re.findall(r'(?<![\w.])(?:\d+\.){3}\d+(?![\w.])', line):
                valid_ip(ip)
            month = MONTHS.index(event['month']) + 1
            datetime.datetime.strptime('%s-%02d-%02d %s' % (event.get('year', '2026'), month, int(event['day']), event['time']), '%Y-%m-%d %H:%M:%S')
            if 'port' in event and not 1 <= int(event['port']) <= 65535:
                raise ValueError('Invalid SSH port')
            matches.append(event)
        if len(matches) != expected_count:
            raise ValueError('Truncated/unexpected fixture event count: ' + name)
        if name.startswith('ssh/'):
            if sum(e['result'] == 'Failed' and e['ip'] == '203.0.113.50' for e in matches) != 8:
                raise ValueError('Expected eight synthetic SSH failures')
        elif len({e['path'] for e in matches if e['status'] == '404' and e['ip'] == '198.51.100.77'}) != 12:
            raise ValueError('Expected twelve distinct synthetic HTTP probes')
        if hashlib.sha256(raw).hexdigest() != manifest['files'][name].get('sha256'):
            raise ValueError('Fixture checksum differs from reviewed content: ' + name)
        counts[name] = len(matches)
    return counts
