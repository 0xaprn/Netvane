"""Netvane command line interface."""
from __future__ import annotations
import argparse
import ipaddress
from collections import Counter
from contextlib import ExitStack
from dataclasses import replace
import csv
import json
import os
import sys
import time
from pathlib import Path

from .core import Finding, KIND_ORDER, extract_line
from .filters import Scope, is_global_indicator
from .readers import read_records
from .store import Deduper
from .ui import Console
from . import __version__

VERSION = __version__


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='netvane',
        description='Netvane — extract, validate, normalize and trace IPs, domains and URLs from messy data.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog='Examples: netvane findings.log -o targets.txt | netvane data.jsonl --field url --fang -o -',
    )
    p.add_argument('inputs', nargs='*', metavar='FILE', help='input file(s); use - or omit for stdin')
    p.add_argument('-o', '--output', default='targets.txt', help='combined output; use - for stdout')
    p.add_argument('--wizard', action='store_true', help='interactive, numbered setup (also starts with no arguments on a terminal)')
    p.add_argument('--types', metavar='LIST', help='only emit selected kinds: ipv4,ipv6,domain,url,cidr (comma-separated)')
    p.add_argument('-f', '--force', action='store_true', help='allow replacing existing output files')
    p.add_argument('--input-format', choices=('auto', 'text', 'csv', 'tsv', 'json', 'jsonl'), default='auto')
    p.add_argument('--field', action='append', default=[], help='CSV column or JSON key to extract (repeatable)')
    p.add_argument('--format', choices=('lines', 'csv', 'jsonl'), default='lines', help='combined output format')
    p.add_argument('--ips-out', help='IPv4 and IPv6 output as plain lines')
    p.add_argument('--domains-out', help='domain output as plain lines')
    p.add_argument('--urls-out', help='URL output as plain lines (--keep-urls or --types url)')
    p.add_argument('--cidrs-out', help='network output as plain lines (--cidr or --types cidr)')
    p.add_argument('--audit', help='JSONL audit of accepted, rejected, duplicate and filtered candidates (can contain sensitive data)')
    p.add_argument('--rejects-out', help='JSONL of rejected and ambiguous candidates')
    p.add_argument('--stats-json', help='write processing metrics as JSON')
    p.add_argument('--fang', action='store_true', help='decode common defanged indicators like hxxps://example[.]com')
    p.add_argument('--strip-ports', action='store_true', help='remove ports from emitted host/IP values; retained for URL records')
    p.add_argument('--keep-urls', action='store_true', help='also retain normalized HTTP(S) URLs (may contain query secrets)')
    p.add_argument('--cidr', action='store_true', help='recognize IP networks with CIDR prefixes')
    p.add_argument('--include-ambiguous', action='store_true', help='include filename-like potential domains')
    p.add_argument('--public-only', action='store_true', help='only globally routable IP literals and networks; does not resolve domains')
    p.add_argument('--scope', metavar='FILE', help='include only IPs/CIDRs or domains matching entries in a scope file')
    p.add_argument('--exclude', metavar='FILE', help='exclude IPs/CIDRs or domains matching entries in an exclusion file')
    p.add_argument('--dedupe', choices=('memory', 'sqlite'), default='memory', help='SQLite is useful for very large input sets')
    p.add_argument('--sort', action='store_true', help='sort all accepted items (uses memory proportional to output size)')
    p.add_argument('--max-line-chars', type=int, default=1_000_000, help='skip unreasonably long source fields; 0 disables limit')
    p.add_argument('--ui', choices=('auto', 'always', 'never'), default='auto', help='terminal presentation; auto only when stderr is a TTY')
    p.add_argument('--no-color', action='store_true')
    p.add_argument('-q', '--quiet', action='store_true', help='disable informational messages')
    p.add_argument('--version', action='version', version=f'Netvane {VERSION}')
    return p


def _valid_paths(inputs: list[str], args: argparse.Namespace) -> None:
    outputs = [args.output, args.ips_out, args.domains_out, args.urls_out, args.cidrs_out, args.audit, args.rejects_out, args.stats_json]
    if outputs.count('-') > 1:
        raise ValueError('only one output may write to stdout (-)')
    for output in outputs:
        if output and output != '-' and Path(output).is_symlink():
            raise ValueError(f'refusing to write through an output symlink: {output}')
    output_paths = [Path(p).expanduser().resolve() for p in outputs if p and p != '-']
    if len(set(output_paths)) != len(output_paths):
        raise ValueError('two outputs cannot use the same path')
    input_paths = {Path(p).expanduser().resolve() for p in [*inputs, args.scope, args.exclude] if p and p != '-'}
    if input_paths.intersection(output_paths):
        raise ValueError('output path would overwrite an input file')
    if not args.force:
        existing = [p for p in outputs if p and p != '-' and (Path(p).exists() or Path(p).is_symlink())]
        if existing:
            raise ValueError(f'output exists: {existing[0]} (use --force to replace it)')
    if args.max_line_chars < 0:
        raise ValueError('--max-line-chars must be nonnegative')
    if args.urls_out and not (args.keep_urls or (args.types and 'url' in args.types.split(','))):
        raise ValueError('--urls-out requires --keep-urls or --types url')
    if args.cidrs_out and not (args.cidr or (args.types and 'cidr' in args.types.split(','))):
        raise ValueError('--cidrs-out requires --cidr or --types cidr')
    if '-' in inputs and (len(inputs) > 1 and inputs.count('-') > 1):
        raise ValueError('stdin (-) can only be supplied once')
    for path in inputs:
        if path != '-' and not os.path.isfile(path):
            raise ValueError(f'input file not found: {path}')


def _serialize(finding: Finding, status: str | None = None, reason: str | None = None) -> dict:
    data = finding.as_dict()
    if status:
        data['status'] = status
    if reason:
        data['reason'] = reason
    return data


def _sortkey(finding: Finding):
    if finding.kind in ('ipv4', 'ipv6'):
        value = finding.value
        port = 0
        if value.startswith('['):
            host, _, tail = value[1:].partition(']')
            port = int(tail[1:]) if tail.startswith(':') else 0
        elif finding.kind == 'ipv4' and ':' in value:
            host, p = value.rsplit(':', 1)
            port = int(p)
        else:
            host = value
        return (KIND_ORDER[finding.kind], int(ipaddress.ip_address(host)), port)
    if finding.kind == 'cidr':
        network = ipaddress.ip_network(finding.value)
        return (KIND_ORDER['cidr'], network.version, int(network.network_address), network.prefixlen)
    return (KIND_ORDER.get(finding.kind, 9), finding.value)


def _open_text(stack: ExitStack, filename: str | None, force: bool = False):
    if not filename:
        return None
    if filename == '-':
        return sys.stdout
    # Atomically reject output symlinks where the platform supports O_NOFOLLOW.
    # New files receive user-only permissions because input may contain secrets.
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(filename, flags, 0o600)
    return stack.enter_context(os.fdopen(fd, 'w', encoding='utf-8', newline=''))


def _write_combined(finding: Finding, stream, mode: str, writer=None):
    if mode == 'lines':
        stream.write(finding.value + '\n')
    elif mode == 'jsonl':
        stream.write(json.dumps(finding.as_dict(), ensure_ascii=False) + '\n')
    else:
        writer.writerow([finding.kind, finding.value, finding.source, finding.line, finding.location, finding.raw, finding.reason])


def run(args: argparse.Namespace) -> dict:
    start = time.monotonic()
    inputs = args.inputs or ['-']
    if not args.output:
        raise ValueError('--output cannot be empty')
    kinds = set(KIND_ORDER)
    if args.types is not None:
        kinds = {kind.strip().lower() for kind in args.types.split(',')}
        unknown = kinds - set(KIND_ORDER)
        if not kinds or '' in kinds or unknown:
            raise ValueError(f'invalid --types; choose from {", ".join(KIND_ORDER)}')
    _valid_paths(inputs, args)
    allow = Scope(args.scope)
    deny = Scope(args.exclude)
    ui = Console(args.ui, args.no_color, args.quiet)
    ui.intro(len(inputs), 'fang + strict' if args.fang else 'strict', VERSION)
    stats = {'records': 0, 'unique': 0, 'duplicates': 0, 'rejected': 0, 'ambiguous': 0,
             'filtered': 0, 'skipped_long': 0, 'by_kind': Counter()}
    with ExitStack() as stack:
        combined = _open_text(stack, args.output, args.force)
        ips = _open_text(stack, args.ips_out, args.force)
        domains = _open_text(stack, args.domains_out, args.force)
        urls = _open_text(stack, args.urls_out, args.force)
        cidrs = _open_text(stack, args.cidrs_out, args.force)
        audit = _open_text(stack, args.audit, args.force)
        rejects = _open_text(stack, args.rejects_out, args.force)
        metrics = _open_text(stack, args.stats_json, args.force)
        csv_writer = csv.writer(combined) if args.format == 'csv' else None
        if csv_writer:
            csv_writer.writerow(['kind','value','source','line','location','raw','reason'])
        pending: list[Finding] = []
        with Deduper(args.dedupe) as deduper:
            def write_accepted(finding: Finding):
                _write_combined(finding, combined, args.format, csv_writer)
                if finding.kind in ('ipv4', 'ipv6') and ips:
                    ips.write(finding.value + '\n')
                elif finding.kind == 'domain' and domains:
                    domains.write(finding.value + '\n')
                elif finding.kind == 'url' and urls:
                    urls.write(finding.value + '\n')
                elif finding.kind == 'cidr' and cidrs:
                    cidrs.write(finding.value + '\n')

            def accept(finding: Finding):
                if args.sort:
                    pending.append(finding)
                else:
                    write_accepted(finding)

            def process(finding: Finding):
                if args.strip_ports and finding.status == 'accepted' and finding.kind in ('ipv4','ipv6','domain'):
                    value = finding.value
                    if value.startswith('[') and ']:' in value:
                        value = value[1:value.index(']')]
                    elif finding.kind in ('ipv4', 'domain') and ':' in value:
                        value = value.rsplit(':', 1)[0]
                    finding = replace(finding, value=value)
                status = finding.status
                reason = finding.reason
                if status == 'rejected':
                    stats['rejected'] += 1
                elif status == 'ambiguous':
                    stats['ambiguous'] += 1
                elif finding.kind not in kinds:
                    status, reason = 'filtered', 'not in selected types'
                    stats['filtered'] += 1
                elif args.public_only and not is_global_indicator(finding):
                    status, reason = 'filtered', 'non-global IP or network'
                    stats['filtered'] += 1
                elif allow.active and not allow.matches(finding):
                    status, reason = 'filtered', 'not in selected scope'
                    stats['filtered'] += 1
                elif deny.active and deny.matches(finding):
                    status, reason = 'filtered', 'explicitly excluded'
                    stats['filtered'] += 1
                elif not deduper.add(finding.kind, finding.value):
                    status, reason = 'duplicate', 'previously encountered'
                    stats['duplicates'] += 1
                else:
                    stats['unique'] += 1
                    stats['by_kind'][finding.kind] += 1
                    accept(finding)
                record = _serialize(finding, status, reason)
                if audit:
                    audit.write(json.dumps(record, ensure_ascii=False) + '\n')
                if rejects and status in ('rejected', 'ambiguous'):
                    rejects.write(json.dumps(record, ensure_ascii=False) + '\n')

            for path in inputs:
                for source, line, location, text in read_records(path, args.input_format, frozenset(args.field)):
                    stats['records'] += 1
                    if args.max_line_chars and len(text) > args.max_line_chars:
                        stats['skipped_long'] += 1
                        finding = Finding('rejected','line','', '',source,line,location, 'input field exceeds --max-line-chars')
                        process(finding)
                        continue
                    for finding in extract_line(text, source, line, location=location, fang=args.fang,
                                                allow_cidr=args.cidr or (args.types is not None and 'cidr' in kinds),
                                                include_ambiguous=args.include_ambiguous,
                                                keep_urls=args.keep_urls or (args.types is not None and 'url' in kinds)):
                        process(finding)
                    if stats['records'] % 100_000 == 0:
                        ui.progress(stats['records'])
            if args.sort:
                for finding in sorted(pending, key=_sortkey):
                    write_accepted(finding)
        stats['by_kind'] = dict(stats['by_kind'])
        stats['duration_seconds'] = round(time.monotonic() - start, 4)
        if metrics:
            metrics.write(json.dumps(stats, indent=2) + '\n')
    ui.finish(stats, args.output, stats['duration_seconds'])
    if not ui.active and not args.quiet:
        print(f"[+] {stats['unique']:,} unique · {stats['duplicates']:,} duplicates · {stats['rejected']:,} rejected · {stats['ambiguous']:,} review → {args.output}", file=sys.stderr)
    return stats


def main(argv: list[str] | None = None) -> int:
    p = parser()
    raw_args = sys.argv[1:] if argv is None else argv
    args = p.parse_intermixed_args(raw_args)
    try:
        if args.wizard or (not raw_args and sys.stdin.isatty() and sys.stdout.isatty()):
            from .wizard import wizard
            if args.wizard and raw_args != ['--wizard']:
                raise ValueError('--wizard must be run without other flags; answer the prompts instead')
            args = wizard(p)
            if args is None:
                return 0
        run(args)
        return 0
    except (OSError, ValueError) as exc:
        print(f'[!] Netvane: {exc}', file=sys.stderr)
        return 2
    except BrokenPipeError:
        # Friendly behavior in `netvane ... -o - | head` pipelines.
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
