"""Short interactive setup for humans; every setting also has a CLI flag."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .ui import ACCENT, BRIGHT, MUTED, RESET

PRESETS = (
    ('IPv4 only', 'ipv4'),
    ('IPv6 only', 'ipv6'),
    ('Domains only', 'domain'),
    ('IPv4 + IPv6', 'ipv4,ipv6'),
    ('IPv4 + domains', 'ipv4,domain'),
    ('IPv6 + domains', 'ipv6,domain'),
    ('IPv4 + IPv6 + domains', 'ipv4,ipv6,domain'),
    ('Everything / include URLs + CIDRs', 'ipv4,ipv6,domain,url,cidr'),
)
KINDS = {'ipv4', 'ipv6', 'domain', 'url', 'cidr'}


def _color(text: str, shade: str) -> str:
    if sys.stdout.isatty() and 'NO_COLOR' not in os.environ:
        return shade + text + RESET
    return text


def _ask(message: str, default: str = '') -> str:
    prompt = f"  {_color('›', ACCENT)} {message}"
    if default:
        prompt += _color(f' [{default}]', MUTED)
    return input(prompt + ': ').strip() or default


def _yes(message: str, default: bool = False) -> bool:
    while True:
        reply = _ask(message + (' (Y/n)' if default else ' (y/N)')).casefold()
        if not reply:
            return default
        if reply in ('y', 'yes'):
            return True
        if reply in ('n', 'no'):
            return False
        print('  Enter y or n.')


def _filename(prompt: str) -> str:
    while True:
        value = _ask(prompt)
        if not value:
            return ''
        path = Path(value).expanduser()
        if path.is_file():
            return str(path)
        print(f'  File not found: {value}')


def _optional_file(prompt: str) -> str:
    while True:
        value = _ask(prompt)
        if not value:
            return ''
        if Path(value).expanduser().is_file():
            return str(Path(value).expanduser())
        print(f'  File not found: {value}')


def wizard(parser: argparse.ArgumentParser) -> argparse.Namespace | None:
    if not sys.stdin.isatty():
        raise ValueError('interactive mode requires a terminal; use --help for CLI mode')
    try:
        print()
        print(_color('  ╭─ NETVANE ────────────────────────────╮', ACCENT))
        print('  │  TARGET EXTRACTION  /  INTERACTIVE   │')
        print(_color('  ╰──────────────────────────────────────╯', ACCENT))
        print(_color('\n  01 / SELECT MODE', BRIGHT))
        for number, (name, _) in enumerate(PRESETS, 1):
            print(f'  {_color(f"[{number:02}]", ACCENT)}  {name}')
        print(f'  {_color("[09]", ACCENT)}  Custom types')
        while True:
            choice = _ask('Select mode', '7')
            if choice.isdigit() and 1 <= int(choice) <= 8:
                types = PRESETS[int(choice) - 1][1]
                break
            if choice == '9':
                types = _ask('Types (ipv4,ipv6,domain,url,cidr)', 'ipv4,domain')
                selected = {item.strip().lower() for item in types.split(',')}
                if selected and selected <= KINDS and '' not in selected:
                    break
            print('  Choose 1–9, or enter valid custom types.')

        print(_color('\n  02 / SOURCE', BRIGHT))
        source = _filename('Input file (blank = paste text)')
        print(_color('\n  03 / CLEANUP', BRIGHT))
        fang = _yes('Decode defanged text')
        strip_ports = _yes('Strip ports from hosts')
        public_only = _yes('Filter non-global IPs')
        sort = _yes('Sort output')

        print(_color('\n  04 / EXPORT', BRIGHT))
        output = str(Path(_ask('Output filename', 'targets.txt')).expanduser())
        advanced = _yes('Configure advanced settings')
        extra: list[str] = []
        if advanced:
            fmt = _ask('Export format (lines/csv/jsonl)', 'lines').lower()
            while fmt not in ('lines', 'csv', 'jsonl'):
                print('  Choose lines, csv, or jsonl.')
                fmt = _ask('Export format', 'lines').lower()
            extra += ['--format', fmt]
            if _yes('Keep full HTTP(S) URLs'):
                extra.append('--keep-urls')
            if _yes('Include ambiguous filename-like domains'):
                extra.append('--include-ambiguous')
            if _yes('Write a separate IP list'):
                extra += ['--ips-out', str(Path(_ask('IP output filename', 'ips.txt')).expanduser())]
            if _yes('Write a separate domain list'):
                extra += ['--domains-out', str(Path(_ask('Domain output filename', 'domains.txt')).expanduser())]
            if _yes('Write a JSONL audit file (includes source text)'):
                extra += ['--audit', str(Path(_ask('Audit filename', 'audit.jsonl')).expanduser())]
            scope = _optional_file('Scope file (blank = none)')
            exclude = _optional_file('Exclusion file (blank = none)')
            if scope:
                extra += ['--scope', scope]
            if exclude:
                extra += ['--exclude', exclude]

        outputs = [output]
        for flag in ('--ips-out', '--domains-out', '--audit'):
            if flag in extra:
                outputs.append(extra[extra.index(flag) + 1])
        existing = [path for path in outputs if path != '-' and (Path(path).exists() or Path(path).is_symlink())]
        force = False
        if existing:
            print(_color(f'  Existing output: {existing[0]}', ACCENT))
            force = _yes('Overwrite existing output(s)')
            if not force:
                print('  Cancelled. Nothing was written.')
                return None

        flags = ['--types', types, '-o', output, *extra]
        if source:
            flags.insert(0, source)
        if fang:
            flags.append('--fang')
        if strip_ports:
            flags.append('--strip-ports')
        if public_only:
            flags.append('--public-only')
        if sort:
            flags.append('--sort')
        if force:
            flags.append('--force')
        print(_color('\n  ──────────────────────────────────────', ACCENT))
        print(f'  MODE    {types}')
        print(f'  OUTPUT  {output}')
        if not source:
            print('  Paste text now. Finish with Ctrl-D (Linux/macOS).\n')
        else:
            print()
        return parser.parse_intermixed_args(flags)
    except (KeyboardInterrupt, EOFError):
        print('\n  Cancelled. Nothing was written.')
        return None
