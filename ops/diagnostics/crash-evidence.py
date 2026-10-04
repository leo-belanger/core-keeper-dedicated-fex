#!/usr/bin/python3
"""Bounded private Core Keeper crash evidence; core routing preserves Apport."""
import datetime
import fcntl
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

BASE = Path('/data/corekeeper/diagnostics')
CONTAINER = os.environ.get('COREKEEPER_EVIDENCE_CONTAINER', 'core-keeper-dedicated')
CORE_CAP = 2 * 1024**3
RAW_CAP = 16 * 1024**3
RUNTIME_CAP = 768 * 1024**2
FREE_FLOOR = 6 * 1024**3


def command(args, timeout=15):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
        return result.stdout[:4 * 1024**2].decode(errors='replace'), result.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        return str(error), -1


def write(path, value):
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2))
    path.chmod(0o600)


def prepare():
    if not os.path.ismount('/data'):
        raise RuntimeError('Data disk is not mounted')
    if BASE.parent.is_symlink() or not BASE.parent.is_dir() or BASE.is_symlink():
        raise RuntimeError('Unexpected managed diagnostics directory')
    BASE.mkdir(mode=0o700, exist_ok=True)
    BASE.chmod(0o700)


def retain():
    bundles = sorted((p for p in BASE.glob('crash-*') if p.is_dir() and not p.is_symlink()),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    for old in bundles[2:]:
        shutil.rmtree(old)


def create_bundle(epoch, pid):
    # Prune before collecting a new potentially large dump, retaining one old one.
    bundles = sorted((p for p in BASE.glob('crash-*') if p.is_dir() and not p.is_symlink()),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    for old in bundles[1:]:
        shutil.rmtree(old)
    stamp = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = BASE / f'crash-{stamp}-{pid}'
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def snapshot(bundle):
    for filename, args in [
        ('container.json', ['docker', 'inspect', CONTAINER]),
        ('docker-tail.log', ['docker', 'logs', '--timestamps', '--tail', '2000', CONTAINER]),
        ('host.txt', ['uname', '-a']),
        ('kernel.log', ['journalctl', '-k', '--since', '-10min', '-n', '150', '--no-pager']),
        ('packages.txt', ['docker', 'exec', CONTAINER, 'dpkg-query', '-W']),
        ('fex-version.txt', ['docker', 'exec', CONTAINER, 'dpkg-query', '-W', 'fex-emu-armv8.0']),
    ]:
        if filename == 'docker-tail.log':
            # Docker writes diagnostics to either stdout or stderr.
            try:
                result = subprocess.run(args, capture_output=True, timeout=15, check=False)
                write(bundle / filename, (result.stdout + result.stderr)[-4 * 1024**2:].decode(errors='replace'))
            except (OSError, subprocess.TimeoutExpired) as error:
                write(bundle / filename, str(error))
        else:
            output, status = command(args)
            write(bundle / filename, output)
            if status:
                write(bundle / (filename + '.error'), str(status))


def is_target(pid):
    try:
        root = Path(f'/proc/{pid}/root')
        host = os.stat('/data/corekeeper/server-data')
        guest = os.stat(root / 'home/steam/core-keeper-data')
        cmdline = Path(f'/proc/{pid}/cmdline').read_bytes()
        return (host.st_dev, host.st_ino) == (guest.st_dev, guest.st_ino) and b'CoreKeeperServer' in cmdline
    except OSError:
        return False


def runtime(bundle, pid):
    proc = Path(f'/proc/{pid}')
    maps = (proc / 'maps').read_text()
    write(bundle / 'maps.txt', maps)
    for name in ['status', 'limits', 'smaps_rollup']:
        try:
            write(bundle / (name + '.txt'), (proc / name).read_text())
        except OSError:
            pass
    paths = {os.readlink(proc / 'exe')}
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5].startswith('/') and 'x' in fields[1]:
            paths.add(fields[5].removesuffix(' (deleted)'))
    packed, missing, total = [], [], 0
    with tarfile.open(bundle / 'runtime.tar.gz', 'w:gz', compresslevel=1) as archive:
        for name in sorted(paths):
            source = proc / 'root' / name.lstrip('/')
            try:
                size = source.stat().st_size
                if total + size > RUNTIME_CAP:
                    missing.append(name + ': runtime size cap')
                    continue
                # Follow in-container symlinks through the proc root namespace.
                with source.open('rb') as stream:
                    info = tarfile.TarInfo(name.lstrip('/'))
                    info.size, info.mode = size, 0o600
                    archive.addfile(info, stream)
                total += size
                packed.append(name)
            except (OSError, tarfile.TarError) as error:
                missing.append(name + ': ' + str(error))
    write(bundle / 'runtime-index.json', {'packed': packed, 'missing': missing, 'raw_bytes': total})


def core(args):
    # kernel args: global pid, namespace pid, signal, epoch, uid, gid, limit,
    # dump mode, pidfd, executable. Forward unrelated programs unchanged.
    keys = ['P', 'p', 's', 't', 'u', 'g', 'c', 'd', 'F', 'E']
    if len(args) != len(keys):
        raise ValueError('Expected all ten kernel arguments')
    values = dict(zip(keys, args))
    if not is_target(values['P']):
        config = json.loads(Path('/etc/corekeeper-crash-router.json').read_text())
        original = config['apport_argv']
        argv = [token for token in original]
        for key, value in values.items():
            argv = [token.replace('%' + key, value) for token in argv]
        os.execv(argv[0], argv)
    prepare()
    with open('/run/lock/corekeeper-evidence.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        bundle = create_bundle(values['t'], values['P'])
        write(bundle / 'core-event.json', values)
        snapshot(bundle)
        try:
            runtime(bundle, values['P'])
        except Exception as error:
            write(bundle / 'runtime-error.txt', str(error))
        raw = 0
        target = bundle / 'core.gz'
        try:
            if shutil.disk_usage(BASE).free < FREE_FLOOR:
                raise RuntimeError('Less than 6 GiB free; core skipped')
            with target.open('wb') as output:
                with gzip.GzipFile(fileobj=output, mode='wb', compresslevel=1) as compressed:
                    while chunk := sys.stdin.buffer.read(1024**2):
                        raw += len(chunk)
                        if raw > RAW_CAP:
                            raise RuntimeError('Raw core exceeds 16 GiB')
                        compressed.write(chunk)
                        if output.tell() > CORE_CAP or shutil.disk_usage(BASE).free < FREE_FLOOR:
                            raise RuntimeError('Compressed core exceeds 2 GiB or low disk space')
                if output.tell() > CORE_CAP:
                    raise RuntimeError('Compressed core exceeds 2 GiB')
            target.chmod(0o600)
            write(bundle / 'core-result.json', {'complete': True, 'raw_bytes': raw, 'gzip_bytes': target.stat().st_size})
        except Exception as error:
            target.unlink(missing_ok=True)
            write(bundle / 'core-result.json', {'complete': False, 'raw_bytes': raw, 'error': str(error)})
        retain()


def monitor():
    prepare()
    since = int(time.time())
    while True:
        with subprocess.Popen(['docker', 'events', '--since', str(since), '--filter',
                               'type=container', '--filter', 'event=die',
                               '--format', '{{json .}}'], stdout=subprocess.PIPE, text=True) as stream:
            for line in stream.stdout:
                try:
                    event = json.loads(line)
                    epoch = int(event['time'])
                    since = epoch + 1
                    attributes = event.get('Actor', {}).get('Attributes', {})
                    if attributes.get('name') != CONTAINER or attributes.get('exitCode') in ['0', '143']:
                        continue
                    with open('/run/lock/corekeeper-evidence.lock', 'w') as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX)
                        recent = [p for p in BASE.glob('crash-*') if p.is_dir() and not p.is_symlink()
                                  and abs(p.stat().st_mtime - epoch) < 300]
                        bundle = max(recent, key=lambda p: p.stat().st_mtime) if recent else create_bundle(epoch, 'docker')
                        write(bundle / 'docker-event.json', event)
                        if not (bundle / 'container.json').exists():
                            snapshot(bundle)
                        retain()
                    print('Crash evidence saved: ' + str(bundle), flush=True)
                except Exception as error:
                    print('Evidence error: ' + str(error), flush=True)
        time.sleep(5)


if __name__ == '__main__':
    os.umask(0o077)
    if len(sys.argv) < 2:
        raise SystemExit('Usage: crash-evidence.py core ARGS | monitor')
    if sys.argv[1] == 'core':
        core(sys.argv[2:])
    elif sys.argv[1] == 'monitor':
        monitor()
    else:
        raise SystemExit('Usage: crash-evidence.py core ARGS | monitor')
