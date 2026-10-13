"""Input readers. Text, CSV, and JSONL stream; JSON is loaded as a document."""
from __future__ import annotations
import csv
import gzip
import json
import sys
from pathlib import Path
from typing import Iterator


def select_format(name: str, chosen: str) -> str:
    if chosen != 'auto':
        return chosen
    suffixes = Path(name).suffixes
    ext = (suffixes[-2] if len(suffixes) > 1 and suffixes[-1].lower() == '.gz' else suffixes[-1]) if suffixes else ''
    return {'.csv': 'csv', '.tsv': 'tsv', '.json': 'json', '.jsonl': 'jsonl', '.ndjson': 'jsonl'}.get(ext.lower(), 'text')


def _strings(obj, path: str = '', fields: frozenset[str] = frozenset(), selected: bool = False) -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            pointer = f'{path}/{str(key).replace("~", "~0").replace("/", "~1")}'
            yield from _strings(value, pointer, fields, selected or str(key) in fields)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _strings(value, f'{path}/{i}', fields, selected)
    elif isinstance(obj, str) and (not fields or selected):
        yield path or '/', obj


def read_records(path: str, input_format: str, fields: frozenset[str]) -> Iterator[tuple[str, int, str, str]]:
    opener = gzip.open if path.lower().endswith('.gz') else open
    stream = sys.stdin if path == '-' else opener(path, 'rt', encoding='utf-8-sig', errors='replace', newline='')
    try:
        kind = select_format(path, input_format)
        if kind == 'text':
            for line_number, value in enumerate(stream, 1):
                yield path, line_number, '', value.rstrip('\r\n')
        elif kind in ('csv', 'tsv'):
            reader = csv.DictReader(stream, delimiter='\t' if kind == 'tsv' else ',')
            if reader.fieldnames is None:
                return
            if fields and not fields.intersection(reader.fieldnames):
                raise ValueError(f'{path}: selected columns not found: {", ".join(sorted(fields))}')
            for row in reader:
                for key, value in row.items():
                    if key is not None and (not fields or key in fields) and isinstance(value, str):
                        yield path, reader.line_num, key, value
        elif kind == 'jsonl':
            for lineno, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    document = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f'{path}:{lineno}: invalid JSONL: {exc.msg}') from exc
                for pointer, value in _strings(document, fields=fields):
                    yield path, lineno, pointer, value
        elif kind == 'json':
            try:
                document = json.load(stream)
            except json.JSONDecodeError as exc:
                raise ValueError(f'{path}: invalid JSON at line {exc.lineno}: {exc.msg}') from exc
            for pointer, value in _strings(document, fields=fields):
                yield path, 1, pointer, value
        else:
            raise ValueError(f'unsupported input format: {kind}')
    finally:
        if path != '-':
            stream.close()
