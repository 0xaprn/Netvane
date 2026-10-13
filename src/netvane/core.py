"""Validation-first indicator extraction. This module never performs network I/O."""
from __future__ import annotations

from dataclasses import dataclass, asdict
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit
from typing import Iterator

# Recognition deliberately does not imply validity: every candidate is parsed.
ANSI_RE = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))')
FANG_RE = re.compile(r'\[\.\]|\(\.\)|\{\.\}|\[:\]|hxxps?', re.IGNORECASE)
URL_RE = re.compile(r'(?i)(?<![\w])https?://[^\s<>"\'`]+')
IPV4_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/[\w+-]+)?(?::[\w+-]+)?(?![\w.])')
BRACKET_V6_RE = re.compile(r'(?<![\w])\[(?=[^\]]*:)[0-9a-fA-F:.%\w-]+\](?::[\w+-]+)?(?!\w)')
# Bracketed forms and URL IPv6 are handled separately. Validate every bare match.
BARE_V6_RE = re.compile(r'(?<![\w.:])(?:[0-9a-fA-F]{0,4}:){2,7}(?:[0-9a-fA-F]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?:%[\w.-]+)?(?:/\d{1,3})?(?![\w.:])')
DOMAIN_RE = re.compile(r'(?<![\w.-])(?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+[^\W_](?:[\w-]{0,61}[^\W_])?(?::[\w+-]+)?(?![\w.-])')
IPV4_SHAPE = re.compile(r'^(?:\d+\.){3}\d+$')
VALID_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.ASCII)
# An isolated name with a likely file extension should be surfaced, not asserted to be a domain.
FILE_SUFFIXES = frozenset('txt pdf csv json jsonl xml html htm php py js ts css md yaml yml ini log conf cfg sh exe dll so png jpg jpeg gif svg ico zip tar gz rar 7z doc docx xls xlsx ppt pptx db sqlite sql bak key pem crt cer mp4 mp3 wasm jar lock toml'.split())
KIND_ORDER = {'ipv4': 0, 'ipv6': 1, 'cidr': 2, 'domain': 3, 'url': 4}


@dataclass(frozen=True)
class Finding:
    status: str  # accepted | rejected | ambiguous
    kind: str
    value: str
    raw: str
    source: str
    line: int
    location: str = ''
    reason: str = ''

    def as_dict(self) -> dict:
        return asdict(self)


def _transform(text: str, pattern: re.Pattern, replacement) -> tuple[str, list[int], list[int]]:
    """Apply substitution while tracking original character offsets."""
    starts: list[int] = []
    ends: list[int] = []
    output: list[str] = []
    cursor = 0
    for match in pattern.finditer(text):
        for i in range(cursor, match.start()):
            output.append(text[i])
            starts.append(i)
            ends.append(i + 1)
        rep = replacement(match)
        for ch in rep:
            output.append(ch)
            starts.append(match.start())
            ends.append(match.end())
        cursor = match.end()
    for i in range(cursor, len(text)):
        output.append(text[i])
        starts.append(i)
        ends.append(i + 1)
    return ''.join(output), starts, ends


def prepare_line(line: str, fang: bool = False) -> tuple[str, list[int], list[int]]:
    # Preserve raw source text even if ANSI escapes or defanging change lengths.
    clean, starts, ends = _transform(line, ANSI_RE, lambda _: '')
    if not fang:
        return clean, starts, ends
    def replacement(match: re.Match) -> str:
        val = match.group(0).lower()
        return 'https' if val == 'hxxps' else 'http' if val == 'hxxp' else ':' if val == '[:]' else '.'
    converted, indices, end_indices = _transform(clean, FANG_RE, replacement)
    return converted, [starts[i] for i in indices], [ends[i - 1] for i in end_indices]


def _host_type(host: str) -> tuple[str, str]:
    host = host.strip().rstrip('.')
    if not host:
        raise ValueError('empty hostname')
    try:
        ip = ipaddress.ip_address(host)
        return ('ipv4' if ip.version == 4 else 'ipv6'), str(ip).lower()
    except ValueError:
        if IPV4_SHAPE.fullmatch(host):
            raise ValueError('invalid IPv4 address')
    try:
        ascii_host = host.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ValueError('invalid internationalized hostname') from exc
    if len(ascii_host) > 253 or '.' not in ascii_host:
        raise ValueError('hostname must be a dotted name of at most 253 characters')
    labels = ascii_host.split('.')
    if any(not VALID_LABEL.fullmatch(label) for label in labels):
        raise ValueError('invalid DNS label')
    tld = labels[-1]
    if len(tld) < 2 or not (tld.isalpha() or tld.startswith('xn--')):
        raise ValueError('invalid or unsupported top-level label')
    return 'domain', ascii_host


def _port(value: str | None) -> str:
    if value is None:
        return ''
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise ValueError('port must be between 1 and 65535')
    return str(int(value))


def _hostport(host: str, kind: str, port: str) -> str:
    return f'[{host}]:{port}' if kind == 'ipv6' and port else f'{host}:{port}' if port else host


def _parse_ip_candidate(candidate: str, allow_cidr: bool) -> tuple[str, str, str]:
    if '/' in candidate:
        addr, _, suffix = candidate.partition('/')
        if not allow_cidr:
            return '', '', 'CIDR not enabled (use --cidr)'
        if ':' in suffix:
            raise ValueError('CIDR cannot include a port')
        try:
            net = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise ValueError('invalid IP network or prefix') from exc
        return 'cidr', str(net), 'network address normalized' if addr != str(net.network_address) else ''
    if candidate.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\](?::(\d+))?', candidate)
        if not match:
            raise ValueError('invalid bracketed IPv6')
        ip = ipaddress.IPv6Address(match.group(1))
        port = _port(match.group(2))
    else:
        ip_part = candidate
        port = ''
        if candidate.count(':') == 1 and '.' in candidate:
            ip_part, port_part = candidate.rsplit(':', 1)
            port = _port(port_part)
        ip = ipaddress.ip_address(ip_part)
    kind = 'ipv4' if ip.version == 4 else 'ipv6'
    return kind, _hostport(str(ip).lower(), kind, port), ''


def _clean_url(raw: str) -> str:
    url = raw.rstrip('.,;!?')
    for closing, opening in ((')', '('), (']', '['), ('}', '{')):
        while url.endswith(closing) and url.count(closing) > url.count(opening):
            url = url[:-1]
    return url


def _parse_url(value: str) -> tuple[str, str, str]:
    parts = urlsplit(value)
    if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
        raise ValueError('invalid HTTP(S) URL')
    host_kind, host = _host_type(parts.hostname)
    port = _port(str(parts.port) if parts.port is not None else None)
    # Userinfo is not preserved in the output to avoid propagating embedded credentials.
    netloc = _hostport(host, host_kind, port)
    if host_kind == 'ipv6' and not port:
        netloc = f'[{host}]'
    url = urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))
    return host_kind, _hostport(host, host_kind, port), url


def extract_line(
    line: str, source: str, lineno: int, *, fang: bool = False,
    allow_cidr: bool = False, include_ambiguous: bool = False,
    keep_urls: bool = False, location: str = ''
) -> Iterator[Finding]:
    text, start_map, end_map = prepare_line(line, fang=fang)
    def finding(status: str, kind: str, value: str, a: int, b: int, reason: str = '') -> Finding:
        raw = line[start_map[a]:end_map[b - 1]] if a < b and start_map else ''
        return Finding(status, kind, value, raw, source, lineno, location, reason)

    # Sort candidates by source position, with high-precedence patterns first at the
    # same position. One sweep avoids quadratic repeated overlap checks.
    matches = []
    for priority, pattern, tag in (
        (0, URL_RE, 'url'), (1, IPV4_RE, 'ip'), (2, BRACKET_V6_RE, 'ip'),
        (3, BARE_V6_RE, 'ip'), (4, DOMAIN_RE, 'domain')
    ):
        for match in pattern.finditer(text):
            matches.append((match.start(), priority, match.end(), tag, match.group()))
    matches.sort(key=lambda item: (item[0], item[1]))
    last_end = 0
    for a, _, end, tag, value in matches:
        if a < last_end:
            continue
        if tag == 'url':
            cleaned = _clean_url(value)
            last_end = end
            try:
                kind, host, url = _parse_url(cleaned)
            except (ValueError, UnicodeError) as exc:
                yield finding('rejected', 'url', cleaned, a, a + len(cleaned), str(exc))
                continue
            yield finding('accepted', kind, host, a, a + len(cleaned), 'hostname extracted from URL')
            if keep_urls:
                yield finding('accepted', 'url', url, a, a + len(cleaned), 'normalized HTTP(S) URL')
        elif tag == 'ip':
            # Avoid interpreting a clock like 12:30:00 as an IPv6 address.
            if ':' in value and '[' not in value and '.' not in value and '::' not in value and value.count(':') < 3:
                continue
            last_end = end
            try:
                kind, norm, reason = _parse_ip_candidate(value, allow_cidr)
            except (ValueError, UnicodeError) as exc:
                yield finding('rejected', 'ip', value, a, end, str(exc))
                continue
            if kind:
                yield finding('accepted', kind, norm, a, end, reason)
            else:
                yield finding('rejected', 'cidr', value, a, end, reason)
        else:
            last_end = end
            host, sep, port_raw = value.partition(':')
            try:
                kind, norm = _host_type(host)
                if kind != 'domain':
                    continue
                port = _port(port_raw) if sep else ''
            except ValueError as exc:
                yield finding('rejected', 'domain', value, a, end, str(exc))
                continue
            reason = ''
            if norm.count('.') == 1 and norm.rsplit('.', 1)[-1] in FILE_SUFFIXES and not sep:
                reason = 'ambiguous file extension / domain; use --include-ambiguous'
                if not include_ambiguous:
                    yield finding('ambiguous', 'domain', norm, a, end, reason)
                    continue
            yield finding('accepted', 'domain', _hostport(norm, kind, port), a, end, reason)
