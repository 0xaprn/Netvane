"""Minimal ANSI terminal presentation. Machine-readable results never share stdout."""
from __future__ import annotations

import os
import sys

ACCENT = '\x1b[38;5;160m'     # deep red; no background overrides
MUTED = '\x1b[90m'
BRIGHT = '\x1b[97m'
RESET = '\x1b[0m'


def safe_label(value: str) -> str:
    """User-supplied paths must not inject control sequences into the terminal."""
    return ''.join(char if char.isprintable() and char != '\x1b' else '?' for char in value)


class Console:
    def __init__(self, ui: str = 'auto', no_color: bool = False, quiet: bool = False):
        self.active = not quiet and (ui == 'always' or (ui == 'auto' and sys.stderr.isatty()))
        self.color = self.active and not no_color and sys.stderr.isatty() and 'NO_COLOR' not in os.environ

    def style(self, value: str, shade: str) -> str:
        return f'{shade}{value}{RESET}' if self.color else value

    def emit(self, line: str = '') -> None:
        print(line, file=sys.stderr)

    def intro(self, sources: int, mode: str, version: str) -> None:
        if not self.active:
            return
        self.emit()
        border = '  ╭' + '─ NETVANE ' + '─' * 34 + '╮'
        title = f'  TARGET EXTRACTION  /  v{version}'
        self.emit(self.style(border, ACCENT))
        self.emit('  │' + self.style(title, BRIGHT) + ' ' * max(0, 44 - len(title)) + '│')
        self.emit(self.style('  ╰' + '─' * 44 + '╯', ACCENT))
        self.emit(self.style(f'  SOURCE  {sources} file(s)   //   MODE  {mode}', MUTED))
        self.emit()

    def progress(self, count: int) -> None:
        if self.active and sys.stderr.isatty():
            self.emit(self.style(f'  ... {count:,} records processed', MUTED))

    def finish(self, stats: dict, output: str, elapsed: float) -> None:
        if not self.active:
            return
        counts = stats['by_kind']
        self.emit(self.style('  ── RESULTS / COMPLETE ───────────────────────', ACCENT))
        for label, kind in [('IPv4', 'ipv4'), ('IPv6', 'ipv6'), ('DOMAINS', 'domain'), ('URLs', 'url'), ('CIDRs', 'cidr')]:
            self.emit(f'  {label:<18} {counts.get(kind, 0):>8,}')
        self.emit(self.style('  ─────────────────────────────────────────────', MUTED))
        self.emit(f"  UNIQUE             {stats['unique']:>8,}    DUPLICATES  {stats['duplicates']:,}")
        self.emit(f"  FILTERED           {stats['filtered']:>8,}    REVIEW      {stats['ambiguous']:,}")
        self.emit(f"  REJECTED           {stats['rejected']:>8,}")
        self.emit(self.style(f"  FINISHED  {elapsed:.2f}s  /  {stats['records']:,} records", BRIGHT))
        self.emit(self.style(f'  OUTPUT    {safe_label(output)}', MUTED))
        self.emit()
