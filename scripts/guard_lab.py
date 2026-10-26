#!/usr/bin/env python3
"""CS-00 lifecycle checks shared by Bash and PowerShell. Standard library only.

Recovery and data destruction are deliberately unavailable in R1. This module
never adopts the historical lab and never invokes a global cleanup command.
"""
import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path

from fixture_policy import validate_fixtures
from detection_evidence import verify_evidence

IMAGE = 'crowdsecurity/crowdsec:v1.8.1@sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a'
DISABLED = {'backup', 'restore', 'update', 'reset'}
EXPECTED_SCENARIOS = {'crowdsecurity/ssh-bf', 'crowdsecurity/http-probing'}


class GuardError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise GuardError(message)


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,30}[a-z0-9]|[a-z]', value),
            'Installation ID must be 1-32 lowercase letters/digits/hyphens, starting with a letter.')
    require(value not in {'lab', 'crowdsec-guard-lab'}, 'Legacy lab identities are reserved; automatic adoption is forbidden.')
    return value


def safe_path(root, relative):
    root = Path(root).resolve()
    relative = Path(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe project path.')
    path = root
    for part in relative.parts:
        path = path / part
        if path.exists() or path.is_symlink():
            attrs = path.lstat()
            require(not path.is_symlink() and not (getattr(attrs, 'st_file_attributes', 0) & 0x400),
                    'Symlink/reparse paths are not allowed: ' + str(path))
    require(os.path.commonpath([str(root), str(path.resolve())]) == str(root), 'Path escapes installation root.')
    return path


def root_hash(root):
    return hashlib.sha256(os.path.normcase(str(Path(root).resolve())).encode('utf-8')).hexdigest()


def write_new(path, content):
    # Exclusive creation: never overwrite a pre-existing registration or log.
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(content)


def new_installation(root, install_id, persistence, context):
    identifier(install_id)
    require(persistence in {'named', 'bind'}, 'Unknown persistence mode.')
    require(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', context or ''), 'Invalid explicit Docker context.')
    validate_fixtures(root)
    registration = safe_path(root, 'config/installation.json')
    require(not registration.exists(), 'Installation already registered; init never overwrites or migrates state.')
    config = safe_path(root, 'config/installations/' + install_id)
    runtime = safe_path(root, 'runtime/installations/' + install_id)
    require(not config.exists() and not runtime.exists(), 'Existing installation directories require manual review; no overwrite.')
    config.mkdir(parents=True, mode=0o700)
    runtime.mkdir(parents=True, mode=0o700)
    (config / 'acquis.d').mkdir(mode=0o700)
    for name, fixture in [('ssh', 'auth.log'), ('web', 'access.log')]:
        write_new(config / 'acquis.d' / (name + '.yaml'), safe_path(root, 'config/acquis.d/' + name + '.yaml').read_bytes())
        (runtime / 'logs' / name).mkdir(parents=True, mode=0o700)
        write_new(runtime / 'logs' / name / fixture, safe_path(root, 'fixtures/logs/' + name + '/' + fixture).read_bytes())
    if persistence == 'bind':
        for name in ['data', 'config']:
            (runtime / 'crowdsec' / name).mkdir(parents=True, mode=0o700)
    data = {'format_version': 1, 'installation_id': install_id, 'owner_token': uuid.uuid4().hex,
            'root_hash': root_hash(root), 'persistence': persistence, 'docker_context': context,
            'engine_image': IMAGE}
    # Registration is written last; partial initialization is never auto-adopted.
    write_new(registration, (json.dumps(data, indent=2) + '\n').encode('utf-8'))
    return data


def load_installation(root):
    path = safe_path(root, 'config/installation.json')
    require(path.is_file(), 'No R1 installation identity. Run init with a NEW identity; legacy resources remain untouched.')
    data = json.loads(path.read_text(encoding='utf-8'))
    require(data.get('format_version') == 1, 'Unsupported installation format.')
    identifier(data.get('installation_id'))
    require(re.fullmatch(r'[0-9a-f]{32}', data.get('owner_token', '')), 'Invalid ownership token.')
    require(data.get('root_hash') == root_hash(root), 'Installation moved/copied: explicit migration is required; resources will not be adopted.')
    require(data.get('persistence') in {'named', 'bind'}, 'Unsupported persistence mode.')
    require(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', data.get('docker_context', '')), 'Invalid Docker context.')
    require(data.get('engine_image') == IMAGE, 'Image changed; update is disabled pending recovery validation.')
    return data


def command(argv, env=None, cwd=None, timeout=30):
    try:
        result = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True,
                                encoding='utf-8', errors='strict', timeout=timeout, shell=False)
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise GuardError('Native command unavailable, timed out or returned invalid UTF-8: ' + argv[0]) from error
    require(result.returncode == 0, 'Native command failed (exit %s): %s' % (result.returncode, ' '.join(argv[:5])))
    return result.stdout


def json_result(text, kind):
    result = json.loads(text)
    require(isinstance(result, kind), 'Unexpected native JSON response type.')
    return result


def json_records(text):
    result = json_result(text, list)
    require(all(isinstance(item, dict) for item in result), 'Expected JSON record array.')
    return result


def enabled_scenarios(text):
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get('scenarios')
    require(isinstance(data, list), 'Unknown scenario JSON schema; readiness is NOT established.')
    require(all(isinstance(item, dict) for item in data), 'Malformed scenario records.')
    return {item['name'] for item in data if isinstance(item.get('name'), str) and item.get('status') == 'enabled'}


class Runtime:
    def __init__(self, root, installation, runner=command):
        self.root = Path(root).resolve()
        self.data = installation
        self.run = runner
        self.project = 'crowdsec-guard-' + identifier(installation['installation_id'])
        self.labels = {'io.crowdsec-guard.installation': installation['installation_id'],
                       'io.crowdsec-guard.owner': installation['owner_token'],
                       'io.crowdsec-guard.root': installation['root_hash'], 'io.crowdsec-guard.schema': '1'}
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('COMPOSE_', 'GUARD_', 'CROWDSEC_'))
                    and k not in {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'}}
        self.env.update(GUARD_ROOT=str(self.root).replace('\\', '/'),
                        GUARD_INSTALLATION_ID=installation['installation_id'],
                        GUARD_OWNER_TOKEN=installation['owner_token'], GUARD_ROOT_HASH=installation['root_hash'])

    def docker(self, *args, **kwargs):
        return self.run(['docker', '--context', self.data['docker_context']] + list(args),
                        env=self.env, cwd=str(self.root), **kwargs)

    def local_context(self):
        records = json_records(self.docker('context', 'inspect', self.data['docker_context']))
        require(len(records) == 1, 'Ambiguous Docker context.')
        endpoint = records[0].get('Endpoints', {}).get('docker', {}).get('Host', '')
        require(endpoint.startswith('unix:///') or endpoint.startswith('npipe:////./pipe/'),
                'Only local Unix sockets or Windows named pipes are allowed; remote Docker targets are rejected.')

    def preflight(self, expected_platform=None):
        host = platform.system()
        require(host in {'Windows', 'Linux', 'Darwin'} and (not expected_platform or expected_platform == host),
                'Wrong installer for this host platform.')
        require(platform.machine().lower() in {'amd64', 'x86_64', 'aarch64', 'arm64'}, 'Unsupported host architecture.')
        print('[CHECK] Host platform candidate: %s/%s; product runtime support remains unverified.' % (host, platform.machine()))
        cli = self.docker('--version').strip()
        require(re.match(r'^Docker version \d+\.\d+', cli), 'Docker CLI is a shim or returned an invalid version.')
        print('[PASS] Working Docker CLI')
        self.local_context()
        info = json_result(self.docker('info', '--format', '{{json .}}'), dict)
        require(info.get('OSType') == 'linux' and isinstance(info.get('ServerVersion'), str)
                and re.match(r'^\d+\.\d+', info['ServerVersion']), 'No reachable Linux Docker engine.')
        require(info.get('Architecture') in {'x86_64', 'amd64'}, 'R1 digest validated only on AMD64; ARM64 manifest validation is pending.')
        print('[PASS] Local Linux daemon reachable (AMD64)')
        version = self.docker('compose', 'version', '--short').strip()
        match = re.fullmatch(r'v?(\d+)\.(\d+)\.\d+(?:[-+][\w.-]+)?', version)
        require(match and tuple(map(int, match.groups())) >= (2, 20), 'Working Docker Compose >=2.20 required.')
        print('[PASS] Compose capability; no writability or end-to-end runtime claim')

    def compose(self, *args, **kwargs):
        argv = ['compose', '--project-name', self.project, '--project-directory', str(self.root),
                '--env-file', str(self.root / 'deploy/docker/.env.example'),
                '-f', str(self.root / 'deploy/docker/compose.yaml')]
        if self.data['persistence'] == 'bind':
            argv += ['-f', str(self.root / 'deploy/docker/compose.bind-paths.yaml')]
        return self.docker(*(argv + list(args)), **kwargs)

    def configuration(self):
        data = json_result(self.compose('config', '--format', 'json'), dict)
        require(set(data.get('services', {})) == {'crowdsec'}, 'Unexpected Compose services.')
        engine = data['services']['crowdsec']
        require(data.get('name') == self.project and engine.get('container_name') == self.project + '-engine', 'Compose identity mismatch.')
        require(engine.get('image') == IMAGE and not engine.get('ports') and not engine.get('privileged'), 'Unsafe engine configuration.')
        require(not engine.get('cap_add') and not engine.get('pid') and not engine.get('network_mode')
                and not engine.get('entrypoint') and not engine.get('command'), 'Unexpected engine privilege/command override.')
        require('no-new-privileges:true' in engine.get('security_opt', []), 'Privilege escalation protection missing.')
        require(engine.get('environment', {}).get('DISABLE_ONLINE_API') == 'true', 'CAPI must remain disabled.')
        require(engine.get('labels') == self.labels, 'Compose ownership labels mismatch.')
        mounts = {v['target']: v for v in engine.get('volumes', [])}
        require(len(mounts) == len(engine.get('volumes', [])), 'Duplicate mount destinations.')
        require(set(mounts) == {'/var/lib/crowdsec/data', '/etc/crowdsec', '/lab/logs',
                              '/etc/crowdsec/acquis.d/guard-ssh.yaml', '/etc/crowdsec/acquis.d/guard-web.yaml'}, 'Unexpected mount destinations.')
        install_id = self.data['installation_id']
        expected_binds = {
            '/lab/logs': 'runtime/installations/' + install_id + '/logs',
            '/etc/crowdsec/acquis.d/guard-ssh.yaml': 'config/installations/' + install_id + '/acquis.d/ssh.yaml',
            '/etc/crowdsec/acquis.d/guard-web.yaml': 'config/installations/' + install_id + '/acquis.d/web.yaml'}
        for target, suffix in [('/var/lib/crowdsec/data', 'data'), ('/etc/crowdsec', 'config')]:
            if self.data['persistence'] == 'bind':
                expected_binds[target] = 'runtime/installations/' + install_id + '/crowdsec/' + suffix
            else:
                mount = mounts[target]
                require(mount['type'] == 'volume' and mount['source'] == 'crowdsec-' + suffix, 'Persistence mode mismatch.')
                volume = data.get('volumes', {}).get('crowdsec-' + suffix, {})
                require(volume.get('name') == self.project + '-' + suffix and volume.get('labels') == self.labels
                        and not volume.get('external'), 'Volume ownership mismatch.')
        network = data.get('networks', {}).get('guardnet', {})
        require(set(engine.get('networks', {})) == {'guardnet'} and network.get('name') == self.project + '-guardnet'
                and network.get('labels') == self.labels and not network.get('external'), 'Network ownership mismatch.')
        for target, mount in mounts.items():
            if mount['type'] == 'bind':
                relative = Path(mount['source']).resolve().relative_to(self.root)
                safe_path(self.root, relative)
                require(target in expected_binds and relative == Path(expected_binds[target]), 'Unexpected bind source.')
                # Compose omits false booleans when serializing normalized JSON.
                require(mount.get('bind', {}).get('create_host_path', False) is False, 'Automatic bind-path creation is forbidden.')
            else:
                require(target not in expected_binds, 'Expected an installation-local bind mount.')
            if target.startswith('/lab/') or target.startswith('/etc/crowdsec/acquis.d/'):
                require(mount.get('read_only') is True, 'Logs/acquisition must be read-only.')
        return data

    def owned(self):
        """Check both exact names AND all resources claiming the Compose project."""
        expected = {'container': {self.project + '-engine'}, 'network': {self.project + '-guardnet'},
                    'volume': {self.project + '-data', self.project + '-config'} if self.data['persistence'] == 'named' else set()}
        found = {'container': [], 'network': [], 'volume': []}
        for kind, names in expected.items():
            listing = [kind, 'ls'] + (['--all'] if kind == 'container' else [])
            objects = set(self.docker(*(listing + ['--filter', 'label=com.docker.compose.project=' + self.project,
                                                  '--format', '{{.ID}}' if kind != 'volume' else '{{.Name}}'])).split())
            for name in names:
                # A plain name filter must include an exact collision on every
                # Docker resource type. Reject extra partial matches as ambiguous.
                objects.update(self.docker(*(listing + ['--filter', 'name=' + name,
                                                        '--format', '{{.ID}}' if kind != 'volume' else '{{.Name}}'])).split())
            for object_id in sorted(objects):
                records = json_records(self.docker(kind, 'inspect', object_id))
                require(len(records) == 1, 'Ambiguous Docker resource.')
                obj = records[0]
                name = obj.get('Name', '').lstrip('/')
                labels = obj.get('Config', {}).get('Labels', {}) if kind == 'container' else obj.get('Labels', {})
                require(name in names and isinstance(labels, dict) and
                        all(labels.get(k) == v for k, v in self.labels.items()) and
                        labels.get('com.docker.compose.project') == self.project,
                        'Unowned/mismatched resource: ' + name + '; no adoption or mutation allowed.')
                if kind == 'network':
                    require(all(v.get('Name') == self.project + '-engine' for v in obj.get('Containers', {}).values()),
                            'Network has unrelated attachments; refusing lifecycle operation.')
                found[kind].append(obj)
        return found

    def readiness(self, container):
        require(container.get('State', {}).get('Running') is True, 'Engine is not running.')
        require(container.get('State', {}).get('Health', {}).get('Status') == 'healthy', 'Engine/LAPI health not established.')
        cid = container['Id']
        self.docker('exec', cid, 'cscli', 'lapi', 'status')
        require(EXPECTED_SCENARIOS <= enabled_scenarios(self.docker('exec', cid, 'cscli', 'scenarios', 'list', '-o', 'json')),
                'Required scenarios are not enabled; readiness failed.')
        alerts = json_records(self.docker('exec', cid, 'cscli', 'alerts', 'list', '-o', 'json'))
        decisions = json_records(self.docker('exec', cid, 'cscli', 'decisions', 'list', '-o', 'json'))
        bouncers = json_records(self.docker('exec', cid, 'cscli', 'bouncers', 'list', '-o', 'json'))
        require(not bouncers, 'A bouncer is registered; detection-only boundary is not established.')
        print('[LAB] Alerts returned: %d; decisions returned: %d (query page, not lifetime totals); no registered bouncers.' % (len(alerts), len(decisions)))
        print('[LAB] LAPI/scenarios ready; successful ingestion/parsing/detection NOT established.')


@contextlib.contextmanager
def operation_lock(root, install_id):
    lock = safe_path(root, 'runtime/installations/' + install_id + '/.operation.lock')
    try:
        write_new(lock, ('pid=%d\n' % os.getpid()).encode('ascii'))
    except FileExistsError as error:
        raise GuardError('Installation operation already locked. Never auto-delete a stale lock.') from error
    try:
        yield
    finally:
        lock.unlink()


def options(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='validate', choices=['init', 'validate', 'preflight', 'up', 'down', 'status', 'detect', 'backup', 'restore', 'update', 'reset', 'uninstall'])
    parser.add_argument('legacy_value', nargs='?')
    for name in ['installation-id', 'docker-context', 'expected-platform', 'evidence', 'archive', 'tag']:
        parser.add_argument('--' + name)
    parser.add_argument('--persistence', choices=['named', 'bind'])
    for name in ['purge', 'keep-backups', 'remove-image']:
        parser.add_argument('--' + name, action='store_true')
    args = parser.parse_args(argv)
    require(not args.purge and not args.remove_image, 'Data purge and global image removal are disabled in R1; backups/state are preserved.')
    if args.action in DISABLED:
        raise GuardError(args.action + ' is UNSUPPORTED in R1. No archive is opened, state changed or Docker command executed. See docs/backup-format.md and the R2 plan.')
    allowed = {'installation_id': {'init'}, 'persistence': {'init'}, 'docker_context': {'init', 'preflight', 'validate'},
               'expected_platform': {'preflight'}, 'evidence': {'detect'}, 'keep_backups': {'uninstall'},
               'archive': set(), 'tag': set(), 'legacy_value': set()}
    for field, actions in allowed.items():
        require(not getattr(args, field) or args.action in actions, 'Option %s is invalid for %s.' % (field, args.action))
    return args


def main(argv=None, root=None, runner=command):
    root = Path(root or Path(__file__).resolve().parent.parent).resolve()
    try:
        args = options(argv)
        if args.action == 'init':
            data = new_installation(root, args.installation_id or ('guard-' + uuid.uuid4().hex[:12]),
                                    args.persistence or 'named', args.docker_context or 'default')
            print('[LAB] Initialized NEW identity ' + data['installation_id'] + '; no Docker resources accessed.')
            return 0
        if args.action == 'detect':
            require(args.evidence, 'Live detect is disabled in R1. Supply --evidence for OFFLINE assertion checks only; R2 must validate the collector.')
            verify_evidence(json.loads(Path(args.evidence).read_text(encoding='utf-8')))
            print('[LAB] OFFLINE evidence assertions PASS. No live detection was run; collection provenance is not certified.')
            return 0
        if args.action in {'validate', 'preflight'}:
            data = load_installation(root) if safe_path(root, 'config/installation.json').exists() else {
                'installation_id': 'validation-only', 'owner_token': '0' * 32, 'root_hash': root_hash(root),
                'persistence': 'named', 'docker_context': args.docker_context or 'default'}
            if args.docker_context:
                data = dict(data, docker_context=args.docker_context)
            runtime = Runtime(root, data, runner)
            if args.action == 'preflight':
                runtime.preflight(args.expected_platform)
            else:
                validate_fixtures(root)
                runtime.configuration()
                print('[LAB] Static fixture/Compose validation PASS; no daemon, writes or runtime readiness checks.')
            return 0
        data = load_installation(root)
        runtime = Runtime(root, data, runner)
        runtime.preflight()
        runtime.configuration()
        if args.action == 'status':
            owned = runtime.owned()
            require(len(owned['container']) == 1, 'Engine absent; status is not ready.')
            runtime.readiness(owned['container'][0])
            return 0
        with operation_lock(root, data['installation_id']):
            owned = runtime.owned()
            if args.action == 'up':
                # Only read existing files. Up never re-stages or truncates logs.
                for relative in ['config/installations/%s/acquis.d/%s.yaml' % (data['installation_id'], x) for x in ['ssh', 'web']] + [
                    'runtime/installations/%s/logs/%s' % (data['installation_id'], x) for x in ['ssh/auth.log', 'web/access.log']]:
                    require(safe_path(root, relative).is_file(), 'Installation file missing; no automatic repair: ' + relative)
                runtime.compose('up', '-d', '--wait', '--wait-timeout', '180', timeout=240)
                current = runtime.owned()
                require(len(current['container']) == 1, 'Engine absent after startup.')
                runtime.readiness(current['container'][0])
                print('[LAB] Startup/readiness checks passed; detection acceptance remains pending.')
            else:
                # Stop/remove only immutable IDs already verified; no Compose-wide deletion.
                for container in owned['container']:
                    if container.get('State', {}).get('Running'):
                        runtime.docker('container', 'stop', container['Id'], timeout=60)
                    runtime.docker('container', 'rm', container['Id'])
                for network in owned['network']:
                    runtime.docker('network', 'rm', network['Id'])
                print('[LAB] Owned container/network removed. Volumes, bind data, configuration, logs, images and ALL backups preserved.')
        return 0
    except (GuardError, ValueError, KeyError, TypeError, OSError) as error:
        print('[LAB] FAIL: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
