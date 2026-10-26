"""R1 adversarial tests. All filesystem writes are confined to a fresh QA child.

Run with CS00_R1_QA_DIR pointing at a NEW audit run under runtime/qa-cs00-r1.
Docker is always an in-memory double. No live resources are accessed.
"""
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
import uuid
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / 'scripts'))
import guard_lab as lab
from fixture_policy import validate_fixtures
from detection_evidence import verify_evidence, QUERIES, EXPECTED


class DockerDouble:
    def __init__(self, root, data):
        self.runtime = lab.Runtime(root, data)
        self.calls = []
        self.objects = {'container': {}, 'network': {}, 'volume': {}}
        self.fail = None
        self.cli = 'Docker version 28.5.1, build mocked'
        self.endpoint = 'unix:///qa-only/docker.sock'
        self.alerts = []

    def populate(self):
        project = self.runtime.project
        labels = dict(self.runtime.labels, **{'com.docker.compose.project': project})
        self.objects['container'][project + '-engine'] = {
            'Id': 'container-' + project, 'Name': '/' + project + '-engine',
            'Config': {'Labels': dict(labels)}, 'State': {'Running': True, 'Health': {'Status': 'healthy'}}}
        self.objects['network'][project + '-guardnet'] = {
            'Id': 'network-' + project, 'Name': project + '-guardnet', 'Labels': dict(labels), 'Containers': {}}
        if self.runtime.data['persistence'] == 'named':
            for suffix in ['data', 'config']:
                name = project + '-' + suffix
                self.objects['volume'][name] = {'Name': name, 'Labels': dict(labels)}

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        args = argv[3:]
        if self.fail and self.fail(args):
            raise lab.GuardError('injected native failure')
        if args == ['--version']:
            return self.cli
        if args[:2] == ['context', 'inspect']:
            return json.dumps([{'Endpoints': {'docker': {'Host': self.endpoint}}}])
        if args[:1] == ['info']:
            return json.dumps({'OSType': 'linux', 'ServerVersion': '28.5.1', 'Architecture': 'amd64'})
        if args[:3] == ['compose', 'version', '--short']:
            return '2.40.0'
        if args[:1] == ['compose']:
            if 'up' in args:
                self.populate()
                return ''
            raise AssertionError('Unexpected unmocked Compose operation: ' + str(args))
        if args[:1] == ['exec']:
            if args[3:] == ['lapi', 'status']:
                return 'LAPI reachable'
            if args[3:] == ['scenarios', 'list', '-o', 'json']:
                return json.dumps({'scenarios': [{'name': s, 'status': 'enabled'} for s in lab.EXPECTED_SCENARIOS]})
            if args[3:] == ['alerts', 'list', '-o', 'json']:
                return json.dumps(self.alerts)
            if args[3:] in [['decisions', 'list', '-o', 'json'], ['bouncers', 'list', '-o', 'json']]:
                return '[]'
        if args[0] in self.objects:
            kind, verb = args[:2]
            objects = self.objects[kind]
            if verb == 'ls':
                query = args[args.index('--filter') + 1]
                matches = []
                for name, obj in objects.items():
                    labels = obj.get('Config', {}).get('Labels', {}) if kind == 'container' else obj['Labels']
                    if query.startswith('label='):
                        key, value = query[6:].split('=', 1)
                        selected = labels.get(key) == value
                    else:
                        selected = query[5:] in name
                    if selected:
                        matches.append(obj.get('Id', name))
                return '\n'.join(matches)
            selected = [(name, obj) for name, obj in objects.items() if obj.get('Id', name) == args[2]]
            if verb == 'inspect':
                return json.dumps([obj for _, obj in selected])
            if verb == 'stop':
                for _, obj in selected:
                    obj['State']['Running'] = False
                return ''
            if verb == 'rm':
                for name, _ in selected:
                    del objects[name]
                return ''
        raise AssertionError('Unexpected Docker request: ' + str(args))


def evidence():
    snapshot = {'engine_id': 'qa-engine', 'boot_id': 'qa-boot',
                'queries': {q: {'exit_code': 0, 'complete': True, 'error': None} for q in QUERIES},
                'loaded_scenarios': list(lab.EXPECTED_SCENARIOS), 'alerts': [], 'decisions': [],
                'bouncers': [], 'enforcement_enabled': False, 'sources': {}, 'scenario_activity': {}}
    for _, (source, scenario, _, _) in EXPECTED.items():
        snapshot['sources'][source] = {'read': 0, 'parsed': 0, 'unparsed': 0}
        snapshot['scenario_activity'][scenario] = {'poured': 0, 'overflows': 0}
    result = {'format_version': 1, 'installation_id': 'qa-unit', 'run_id': str(uuid.uuid4()),
              'started_at': '2026-10-23T03:00:00Z', 'completed_at': '2026-10-23T03:03:00Z',
              'submitted': {'ssh': 8, 'web': 12}, 'before': copy.deepcopy(snapshot), 'after': copy.deepcopy(snapshot)}
    for index, (_, (source, scenario, ip, count)) in enumerate(EXPECTED.items(), 1):
        result['after']['sources'][source].update(read=count, parsed=count)
        result['after']['scenario_activity'][scenario].update(poured=count, overflows=1)
        result['after']['alerts'].append({'id': index, 'scenario': scenario, 'source': {'scope': 'Ip', 'value': ip},
                                         'start_at': '2026-10-23T03:01:00Z', 'stop_at': '2026-10-23T03:01:10Z'})
    return result


class R1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qa = Path(os.environ['CS00_R1_QA_DIR']).resolve()
        qa.relative_to((SOURCE / 'runtime/qa-cs00-r1').resolve())
        if not qa.is_dir() or qa.is_symlink():
            raise RuntimeError('Use an existing, dedicated QA run directory')
        cls.qa = qa / ('unit-' + uuid.uuid4().hex)
        cls.qa.mkdir(exist_ok=False)

    def setUp(self):
        self.root = self.qa / self._testMethodName
        self.root.mkdir(exist_ok=False)
        for rel in ['fixtures', 'config/acquis.d']:
            shutil.copytree(SOURCE / rel, self.root / rel)

    def init(self, mode='named', name='qa-unit'):
        return lab.new_installation(self.root, name, mode, 'qa-local')

    def invoke(self, args, docker):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return lab.main(args, root=self.root, runner=docker)

    def test_fixtures_valid(self):
        self.assertEqual(validate_fixtures(self.root), {'ssh/auth.log': 10, 'web/access.log': 14})

    def test_fixture_rejects_corruption_encoding_line_endings_and_truncation(self):
        file = self.root / 'fixtures/logs/ssh/auth.log'
        original = file.read_bytes()
        for change in [original.replace(b'password', b'passwod'), original + b'\xff', original.replace(b'\n', b'\r\n'),
                       original[:-1], original[:100], original.replace(b'203.0.113.50', b'203.0.113.999'),
                       original.replace(b'203.0.113.50', b'8.8.8.8'), original.replace(b'51000', b'51001')]:
            with self.subTest(change=change[:25]):
                file.write_bytes(change)
                with self.assertRaises(ValueError):
                    validate_fixtures(self.root)
        file.write_bytes(original)

    def test_fixture_missing_extra_and_empty(self):
        file = self.root / 'fixtures/logs/web/access.log'
        original = file.read_bytes()
        file.unlink()
        with self.assertRaises(ValueError):
            validate_fixtures(self.root)
        file.write_bytes(b'')
        with self.assertRaises(ValueError):
            validate_fixtures(self.root)
        file.write_bytes(original)
        (file.parent / 'extra.log').write_bytes(b'anything\n')
        with self.assertRaises(ValueError):
            validate_fixtures(self.root)

    def test_init_exclusive_stable_and_no_legacy_writes(self):
        legacy = self.root / 'runtime/logs/ssh/auth.log'
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(b'customer sentinel')
        data = self.init()
        self.assertEqual(lab.load_installation(self.root), data)
        with self.assertRaises(lab.GuardError):
            self.init()
        self.assertEqual(legacy.read_bytes(), b'customer sentinel')

    def test_invalid_and_legacy_identity(self):
        for value in ['lab', 'crowdsec-guard-lab', '../outside', 'UPPER', '-x', 'x-', 'x' * 33, 'a b', None]:
            with self.subTest(value=value), self.assertRaises(lab.GuardError):
                lab.identifier(value)

    def test_copied_registration_is_rejected(self):
        data = self.init()
        data['root_hash'] = '0' * 64
        (self.root / 'config/installation.json').write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(lab.GuardError):
            lab.load_installation(self.root)

    def test_distinct_checkouts_have_distinct_resource_names(self):
        first = lab.Runtime(self.root, self.init(name='qa-first'))
        other = self.root / 'second'
        other.mkdir()
        for rel in ['fixtures', 'config/acquis.d']:
            shutil.copytree(SOURCE / rel, other / rel)
        second = lab.Runtime(other, lab.new_installation(other, 'qa-second', 'named', 'qa-local'))
        self.assertNotEqual(first.project, second.project)
        self.assertNotEqual(first.labels['io.crowdsec-guard.owner'], second.labels['io.crowdsec-guard.owner'])

    def test_disabled_operations_do_not_open_archives_or_invoke_docker(self):
        def forbidden(*args, **kwargs):
            self.fail('Docker must not be reached')
        for action in ['backup', 'restore', 'update', 'reset']:
            self.assertEqual(self.invoke([action, '../../untrusted-archive'], forbidden), 1)
        for flags in [['--remove-image', '--keep-backups'], ['--keep-backups', '--remove-image'], ['--purge']]:
            self.assertEqual(self.invoke(['uninstall'] + flags, forbidden), 1)

    def test_unowned_named_resource_and_extra_project_container_rejected(self):
        data = self.init()
        docker = DockerDouble(self.root, data)
        docker.populate()
        volume = docker.objects['volume'][docker.runtime.project + '-data']
        volume['Labels'].pop('io.crowdsec-guard.owner')
        with self.assertRaises(lab.GuardError):
            lab.Runtime(self.root, data, docker).owned()
        self.assertFalse(any('stop' in c or 'rm' in c for c in docker.calls))
        docker.populate()
        extra = copy.deepcopy(next(iter(docker.objects['container'].values())))
        extra.update(Id='foreign-id', Name='/foreign-service')
        docker.objects['container']['foreign-service'] = extra
        with self.assertRaises(lab.GuardError):
            lab.Runtime(self.root, data, docker).owned()
        self.assertFalse(any('stop' in c or 'rm' in c for c in docker.calls))

    def test_foreign_network_attachment_rejected(self):
        data = self.init()
        docker = DockerDouble(self.root, data)
        docker.populate()
        next(iter(docker.objects['network'].values()))['Containers'] = {'other': {'Name': 'unrelated'}}
        with self.assertRaises(lab.GuardError):
            lab.Runtime(self.root, data, docker).owned()

    def test_native_nonzero_and_timeout_fail_closed(self):
        with mock.patch.object(lab.subprocess, 'run', return_value=subprocess.CompletedProcess(['docker'], 7, 'looks successful', '')):
            with self.assertRaises(lab.GuardError):
                lab.command(['docker', 'info'])
        with mock.patch.object(lab.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['docker'], 1)):
            with self.assertRaises(lab.GuardError):
                lab.command(['docker', 'info'])

    def test_cli_shim_remote_context_and_bad_json_rejected(self):
        data = self.init()
        docker = DockerDouble(self.root, data)
        docker.cli = 'The command docker could not be found; enable WSL integration'
        self.assertEqual(self.invoke(['preflight'], docker), 1)
        docker.cli = 'Docker version 28.5.1, build mocked'
        docker.endpoint = 'ssh://production.example.invalid'
        self.assertEqual(self.invoke(['preflight'], docker), 1)
        self.assertFalse(any('info' in c for c in docker.calls))
        with self.assertRaises(ValueError):
            lab.json_result('not-json', dict)

    def test_failed_start_does_not_overwrite_logs_or_claim_success(self):
        data = self.init()
        docker = DockerDouble(self.root, data)
        docker.fail = lambda args: args[0] == 'compose' and 'up' in args
        log = self.root / 'runtime/installations/qa-unit/logs/ssh/auth.log'
        log.write_bytes(b'existing runtime sentinel')
        with mock.patch.object(lab.Runtime, 'configuration', return_value={}):
            self.assertEqual(self.invoke(['up'], docker), 1)
        self.assertEqual(log.read_bytes(), b'existing runtime sentinel')
        self.assertFalse((log.parents[2] / '.operation.lock').exists())

    def test_down_stops_after_failure_and_preserves_all_data(self):
        data = self.init()
        docker = DockerDouble(self.root, data)
        docker.populate()
        docker.fail = lambda args: args[:2] == ['container', 'stop']
        backup = self.root / 'runtime/installations/qa-unit/backup-sentinel'
        backup.write_bytes(b'never delete')
        with mock.patch.object(lab.Runtime, 'configuration', return_value={}):
            self.assertEqual(self.invoke(['uninstall', '--keep-backups'], docker), 1)
        self.assertFalse(any('rm' in c for c in docker.calls))
        self.assertEqual(backup.read_bytes(), b'never delete')

    def test_down_only_removes_owned_ids_and_keeps_volumes(self):
        data = self.init()
        docker = DockerDouble(self.root, data)
        docker.populate()
        with mock.patch.object(lab.Runtime, 'configuration', return_value={}):
            self.assertEqual(self.invoke(['down'], docker), 0)
        self.assertFalse(docker.objects['container'])
        self.assertFalse(docker.objects['network'])
        self.assertEqual(len(docker.objects['volume']), 2)
        self.assertTrue((self.root / 'config/installation.json').exists())

    def test_status_json_records_not_lines_and_query_failure_is_error(self):
        data = self.init()
        docker = DockerDouble(self.root, data)
        docker.populate()
        docker.alerts = [{'id': 1}, {'id': 2}]
        stream = io.StringIO()
        with mock.patch.object(lab.Runtime, 'configuration', return_value={}), redirect_stdout(stream):
            self.assertEqual(lab.main(['status'], root=self.root, runner=docker), 0)
        self.assertIn('Alerts returned: 2;', stream.getvalue())
        docker.fail = lambda args: args[0] == 'exec' and 'alerts' in args
        with mock.patch.object(lab.Runtime, 'configuration', return_value={}):
            self.assertEqual(self.invoke(['status'], docker), 1)

    def test_bind_mode_has_no_named_volume_expectation(self):
        data = self.init(mode='bind')
        docker = DockerDouble(self.root, data)
        docker.populate()
        self.assertEqual(lab.Runtime(self.root, data, docker).owned()['volume'], [])
        self.assertTrue((self.root / 'runtime/installations/qa-unit/crowdsec/data').is_dir())

    def test_lock_refuses_existing_owner_without_deleting_lock(self):
        self.init()
        lock = self.root / 'runtime/installations/qa-unit/.operation.lock'
        lock.write_bytes(b'existing owner')
        with self.assertRaises(lab.GuardError):
            with lab.operation_lock(self.root, 'qa-unit'):
                self.fail('Must not acquire lock')
        self.assertEqual(lock.read_bytes(), b'existing owner')

    def test_evidence_positive(self):
        self.assertEqual(set(verify_evidence(evidence())['alerts']), {'ssh', 'web'})

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell launcher test')
    def test_powershell_forwards_flags_and_native_failure(self):
        shim = self.root / 'shim'
        shim.mkdir()
        capture = self.root / 'powershell-arguments.txt'
        (shim / 'python.cmd').write_bytes(
            b'@echo off\r\nif "%~2"=="-c" exit /b 0\r\necho %*>"%CS00_LAUNCHER_CAPTURE%"\r\nexit /b 37\r\n')
        env = dict(os.environ)
        env['PATH'] = str(shim) + os.pathsep + env.get('PATH', '')
        env['CS00_LAUNCHER_CAPTURE'] = str(capture)
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                 '-File', str(SOURCE / 'scripts/lab.ps1'), 'uninstall', '-RemoveImage', '-KeepBackups'],
                                env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        text = capture.read_text()
        self.assertIn('--remove-image', text)
        self.assertIn('--keep-backups', text)
        self.assertIn('uninstall', text)

    def test_bash_forwards_all_flags_and_native_failure(self):
        bash = Path('C:/Program Files/Git/bin/bash.exe') if os.name == 'nt' else shutil.which('bash')
        if not bash or not Path(bash).is_file():
            self.skipTest('Bash unavailable')
        shim = self.root / 'shim'
        shim.mkdir()
        fake = shim / 'python3'
        fake.write_bytes(b'#!/usr/bin/env bash\nif [ "$2" = "-c" ]; then exit 0; fi\nprintf "<%s>\\n" "$@" > "$CS00_LAUNCHER_CAPTURE"\nexit 37\n')
        fake.chmod(0o700)
        def shell_path(path):
            value = str(path).replace('\\', '/')
            return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value
        capture = self.root / 'bash-arguments.txt'
        env = dict(os.environ, CS00_LAUNCHER_CAPTURE=shell_path(capture))
        result = subprocess.run([str(bash), '--noprofile', '--norc', '-c',
                                 'PATH="$1:/usr/bin:/bin"; export PATH; exec bash "$2" "${@:3}"',
                                 'qa', shell_path(shim), shell_path(SOURCE / 'scripts/lab.sh'),
                                 'uninstall', '--remove-image', '--keep-backups'],
                                env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertIn('<--remove-image>', capture.read_text())
        self.assertIn('<--keep-backups>', capture.read_text())

    def test_evidence_rejects_stale_wrong_failed_missing_and_reset(self):
        cases = []
        e = evidence(); e['before']['alerts'] = copy.deepcopy(e['after']['alerts']); cases.append(e)
        e = evidence(); e['after']['alerts'][0]['scenario'] = 'crowdsecurity/other'; cases.append(e)
        e = evidence(); e['after']['alerts'][0]['source']['value'] = '203.0.113.51'; cases.append(e)
        e = evidence(); e['after']['alerts'][0]['start_at'] = '2020-01-01T00:00:00Z'; cases.append(e)
        e = evidence(); e['after']['queries']['alerts']['exit_code'] = 1; cases.append(e)
        e = evidence(); e['before']['queries']['alerts']['complete'] = False; cases.append(e)
        e = evidence(); e['after']['boot_id'] = 'restarted'; cases.append(e)
        e = evidence(); e['after']['loaded_scenarios'] = []; cases.append(e)
        e = evidence(); e['after']['sources']['/lab/logs/ssh/auth.log']['parsed'] = 0; cases.append(e)
        e = evidence(); e['after']['sources']['/lab/logs/ssh/auth.log']['read'] = 0; cases.append(e)
        e = evidence(); e['after']['scenario_activity']['crowdsecurity/ssh-bf']['overflows'] = 0; cases.append(e)
        e = evidence(); e['after']['bouncers'] = [{'name': 'unexpected'}]; cases.append(e)
        for index, e in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify_evidence(e)


if __name__ == '__main__':
    unittest.main(verbosity=2)
