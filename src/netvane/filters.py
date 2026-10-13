"""Explicit scope constraints with no DNS lookups."""
from __future__ import annotations
import ipaddress
from pathlib import Path
from .core import Finding


class Scope:
    def __init__(self, filename: str | None):
        self.active = filename is not None
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.domains: list[tuple[str, str]] = []
        if filename:
            for lineno, line in enumerate(Path(filename).read_text(encoding='utf-8').splitlines(), 1):
                rule = line.split('#', 1)[0].strip().lower()
                if not rule:
                    continue
                try:
                    self.networks.append(ipaddress.ip_network(rule, strict=False))
                    continue
                except ValueError:
                    pass
                mode = 'base'
                if rule.startswith('*.'):
                    mode, rule = 'children', rule[2:]
                elif rule.startswith('='):
                    mode, rule = 'exact', rule[1:]
                try:
                    rule = rule.encode('idna').decode('ascii').lower()
                except UnicodeError as exc:
                    raise ValueError(f'{filename}:{lineno}: invalid scope entry') from exc
                if '.' not in rule or not all(x and len(x) <= 63 for x in rule.split('.')) or not all(x.replace('-', '').isalnum() for x in rule.split('.')):
                    raise ValueError(f'{filename}:{lineno}: invalid scope entry: {rule}')
                self.domains.append((mode, rule))

    def matches(self, finding: Finding) -> bool:
        if not self.active:
            return True
        if finding.kind == 'url':
            from urllib.parse import urlsplit
            from .core import _host_type
            try:
                kind, host = _host_type(urlsplit(finding.value).hostname or '')
            except ValueError:
                return False
            finding = Finding(finding.status, kind, host, finding.raw, finding.source, finding.line, finding.location, finding.reason)
        if finding.kind in ('ipv4', 'ipv6', 'cidr'):
            s = finding.value
            if finding.kind != 'cidr':
                if s.startswith('['):
                    s = s[1:s.index(']')]
                elif s.count(':') == 1 and '.' in s:
                    s = s.rsplit(':', 1)[0]
            try:
                obj = ipaddress.ip_network(s, strict=False) if finding.kind == 'cidr' else ipaddress.ip_address(s)
            except ValueError:
                return False
            for network in self.networks:
                if obj.version == network.version:
                    if finding.kind == 'cidr' and obj.subnet_of(network):
                        return True
                    if finding.kind != 'cidr' and obj in network:
                        return True
            return False
        if finding.kind == 'domain':
            hostname = finding.value.split(':', 1)[0]
            return any(
                hostname == dom if mode == 'exact' else
                hostname.endswith('.' + dom) if mode == 'children' else
                hostname == dom or hostname.endswith('.' + dom)
                for mode, dom in self.domains
            )
        return False


def is_global_indicator(finding: Finding) -> bool:
    if finding.kind == 'url':
        from urllib.parse import urlsplit
        from .core import _host_type
        try:
            kind, host = _host_type(urlsplit(finding.value).hostname or '')
            finding = Finding(finding.status, kind, host, finding.raw, finding.source, finding.line, finding.location, finding.reason)
        except ValueError:
            return False
    if finding.kind not in ('ipv4', 'ipv6', 'cidr'):
        return True  # No DNS resolution: a domain is never classified by resolved IP.
    value = finding.value
    if finding.kind != 'cidr':
        if value.startswith('['):
            value = value[1:value.index(']')]
        elif value.count(':') == 1 and '.' in value:
            value = value.rsplit(':', 1)[0]
    try:
        if finding.kind == 'cidr':
            network = ipaddress.ip_network(value, strict=False)
            return network.network_address.is_global and network.broadcast_address.is_global
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False
