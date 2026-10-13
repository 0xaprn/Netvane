#!/usr/bin/env python3
"""Install a user-local `netvane` command without pip, sudo or downloads (Unix)."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

MARKER = '# installed by Netvane/install.py'


def install(force: bool = False) -> None:
    if os.name != 'posix':
        raise ValueError('this installer supports Linux/macOS; Windows can use pipx or a venv')
    if sys.version_info < (3, 10):
        raise ValueError('Python 3.10 or newer is required')

    project = Path(__file__).resolve().parent
    home = Path.home()
    destination = home / '.local' / 'share' / 'netvane'
    executable = home / '.local' / 'bin' / 'netvane'

    if destination.is_symlink() or executable.is_symlink():
        raise ValueError('refusing to replace a symbolic link')
    if executable.exists() and MARKER not in executable.read_text(encoding='utf-8', errors='replace'):
        raise ValueError(f'not replacing unrelated command: {executable}')
    if destination.exists() and not (destination / '.netvane-managed').is_file():
        raise ValueError(f'not replacing unrelated directory: {destination}')
    if (destination.exists() or executable.exists()) and not force:
        raise ValueError('Netvane is already installed; use --force to update the managed copy')

    executable.parent.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(mode=0o700)
    shutil.copytree(project / 'src' / 'netvane', destination / 'netvane',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copy2(project / 'run.py', destination / 'run.py')
    (destination / '.netvane-managed').write_text('Managed by install.py\n', encoding='utf-8')
    executable.write_text(
        '#!/bin/sh\n' + MARKER + '\n'
        'exec python3 "$HOME/.local/share/netvane/run.py" "$@"\n',
        encoding='utf-8',
    )
    executable.chmod(0o700)
    print(f'Installed: {executable}')
    print('Launch with: netvane')
    if str(executable.parent) not in os.environ.get('PATH', '').split(os.pathsep):
        print('Add ~/.local/bin to your PATH, then open a new shell.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true', help='update an existing Netvane-managed installation')
    args = parser.parse_args()
    try:
        install(force=args.force)
        return 0
    except (OSError, ValueError) as exc:
        print(f'Installation stopped: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
