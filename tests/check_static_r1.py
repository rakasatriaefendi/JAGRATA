"""Real Compose rendering only. No daemon calls. Evidence writes only under QA."""
import ast
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import guard_lab as lab
from fixture_policy import validate_fixtures


def main():
    parent = Path(os.environ['CS00_R1_QA_DIR']).resolve()
    parent.relative_to((ROOT / 'runtime/qa-cs00-r1').resolve())
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError('Use a dedicated QA run directory')
    target = parent / ('static-' + uuid.uuid4().hex)
    target.mkdir(exist_ok=False)
    checks = []
    names = []
    for name, mode in [('qa-static-a', 'named'), ('qa-static-b', 'named'), ('qa-static-a', 'bind')]:
        data = {'installation_id': name, 'owner_token': '1' * 32, 'root_hash': lab.root_hash(ROOT),
                'persistence': mode, 'docker_context': 'default'}
        runtime = lab.Runtime(ROOT, data)
        result = runtime.configuration()
        (target / (name + '-' + mode + '.json')).write_text(json.dumps(result, indent=2), encoding='utf-8')
        if mode == 'named':
            names.append({result['services']['crowdsec']['container_name'], result['networks']['guardnet']['name']} |
                         {v['name'] for v in result['volumes'].values()})
        checks.append(name + '/' + mode + ': configuration controls PASS')
        if name == 'qa-static-a':
            diagnostic = json.loads(runtime.compose('-f', str(ROOT / 'deploy/docker/compose.host-lapi.yaml'), 'config', '--format', 'json'))
            ports = diagnostic['services']['crowdsec']['ports']
            assert len(ports) == 1 and ports[0]['host_ip'] == '127.0.0.1' and ports[0]['target'] == 8080
            (target / (mode + '-host-lapi.json')).write_text(json.dumps(diagnostic, indent=2), encoding='utf-8')
            checks.append(mode + '/host-lapi: loopback-only configuration PASS')
        # Prove the actual rendered-config checker rejects dangerous modifications.
        altered = json.loads(json.dumps(result))
        altered['services']['crowdsec']['ports'] = [{'target': 8080, 'published': '8080', 'host_ip': '0.0.0.0'}]
        runtime.compose = lambda *args, **kwargs: json.dumps(altered)
        try:
            runtime.configuration()
        except lab.GuardError:
            checks.append(name + '/' + mode + ': published-port tamper rejected PASS')
        else:
            raise AssertionError('Unsafe Compose configuration accepted')
    assert names[0].isdisjoint(names[1])
    checks.append('Distinct installation resource names: PASS')
    validate_fixtures(ROOT)
    checks.append('Fixture integrity: PASS')
    for file in list((ROOT / 'scripts').glob('*.py')) + list((ROOT / 'tests').glob('*.py')):
        text = file.read_text(encoding='utf-8')
        # Enforce Python 3.8 grammar without writing bytecode.
        ast.parse(text, filename=str(file), feature_version=(3, 8))
    checks.append('Python 3.8 grammar: PASS (interpreter runtime matrix pending)')
    bash = Path('C:/Program Files/Git/bin/bash.exe') if os.name == 'nt' else Path('/bin/bash')
    for relative in ['scripts/lab.sh', 'installer/linux/preflight.sh', 'installer/macos/preflight.sh']:
        result = subprocess.run([str(bash), '--noprofile', '--norc', '-n', str(ROOT / relative)], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        checks.append(relative + ': bash -n PASS')
    (target / 'results.txt').write_text('\n'.join(checks) + '\n', encoding='utf-8')
    print('\n'.join(checks))
    print('Evidence directory: ' + str(target))


if __name__ == '__main__':
    main()
