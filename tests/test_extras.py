import contextlib
import gzip
import io
from pathlib import Path
import tempfile
import unittest

from netvane.cli import main
from netvane.core import extract_line
from netvane.readers import read_records


class Extras(unittest.TestCase):
    def test_gzip_jsonl(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl.gz'
            with gzip.open(path, 'wt') as f:
                f.write('{"url":"https://example.com"}\n')
            items = list(read_records(str(path), 'auto', frozenset()))
            self.assertEqual(items[0][-1], 'https://example.com')

    def test_tsv(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.tsv'
            path.write_text('host\tnote\na.example.net\tinteresting\n')
            items = list(read_records(str(path), 'auto', frozenset(['host'])))
            self.assertEqual(items[0][-1], 'a.example.net')

    def test_stripped_ports(self):
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / 's.txt'
            out = Path(folder) / 'o.txt'
            src.write_text('https://a.example.net:8443/a and 8.8.8.8:443')
            with contextlib.redirect_stderr(io.StringIO()):
                ret = main([str(src),'-o',str(out),'--strip-ports','--quiet'])
            self.assertEqual(ret, 0)
            self.assertEqual(out.read_text().splitlines(), ['a.example.net','8.8.8.8'])

    def test_invalid_utf8_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder)/'text.txt'
            f.write_bytes(b'\xffexample.org\n')
            items = list(read_records(str(f), 'auto', frozenset()))
            self.assertIn('example.org', items[0][-1])

if __name__ == '__main__':
    unittest.main()
