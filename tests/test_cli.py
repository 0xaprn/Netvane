import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from netvane.cli import main
from netvane.filters import Scope, is_global_indicator
from netvane.core import Finding
from netvane.readers import read_records


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def path(self, name, text):
        p = self.root / name
        p.write_text(text, encoding='utf-8')
        return str(p)

    def run_cli(self, *args):
        with contextlib.redirect_stderr(io.StringIO()):
            return main([*args, '--ui', 'never', '--quiet'])

    def test_dedupe_and_separate_outputs(self):
        src = self.path('findings.txt', 'one.example.com 8.8.8.8\none.example.com 8.8.8.8\n')
        out = str(self.root / 'targets.txt')
        ips = str(self.root / 'ips.txt')
        domains = str(self.root / 'domains.txt')
        self.assertEqual(self.run_cli(src, '-o', out, '--ips-out', ips, '--domains-out', domains), 0)
        self.assertEqual(Path(out).read_text().splitlines(), ['one.example.com', '8.8.8.8'])
        self.assertEqual(Path(ips).read_text().strip(), '8.8.8.8')
        self.assertEqual(Path(domains).read_text().strip(), 'one.example.com')

    def test_public_only_checks_ip_and_url(self):
        src = self.path('a.log', '10.0.0.1 https://10.0.0.1/admin 8.8.8.8 example.com')
        out = str(self.root / 'a.txt')
        self.assertEqual(self.run_cli(src, '-o', out, '--keep-urls', '--public-only'), 0)
        self.assertEqual(Path(out).read_text().splitlines(), ['8.8.8.8', 'example.com'])

    def test_scope_with_url(self):
        scope = self.path('scope.txt', '10.0.0.0/8\n*.example.org\n')
        src = self.path('findings.log', '10.4.3.2 https://10.1.2.3/x example.org a.example.org bad.com')
        out = str(self.root / 'f.txt')
        self.assertEqual(self.run_cli(src, '-o', out, '--scope', scope, '--keep-urls'), 0)
        self.assertEqual(Path(out).read_text().splitlines(),
                         ['10.4.3.2', '10.1.2.3', 'https://10.1.2.3/x', 'a.example.org'])

    def test_exclusions(self):
        ex = self.path('no.txt', 'example.com\n8.8.8.0/24\n')
        src = self.path('data.txt', 'example.com x.example.com cool.org 8.8.8.8 1.1.1.1')
        out = str(self.root / 'x.txt')
        self.assertEqual(self.run_cli(src, '-o', out, '--exclude', ex), 0)
        self.assertEqual(Path(out).read_text().splitlines(), ['cool.org','1.1.1.1'])

    def test_audit_and_rejections(self):
        src = self.path('logs.txt', 'bad.pdf\n999.1.2.3\nexample.com example.com\n')
        out = str(self.root / 'out.txt')
        audit = str(self.root / 'audit.jsonl')
        reject = str(self.root / 'reject.jsonl')
        self.assertEqual(self.run_cli(src, '-o', out, '--audit', audit, '--rejects-out', reject), 0)
        entries = [json.loads(x) for x in Path(audit).read_text().splitlines()]
        self.assertEqual([e['status'] for e in entries], ['ambiguous','rejected','accepted','duplicate'])
        self.assertEqual(len(Path(reject).read_text().splitlines()), 2)
        self.assertEqual(entries[2]['line'], 3)

    def test_jsonl_and_nested_field(self):
        src = self.path('log.jsonl', '{"url": "https://example.org/a", "noise": "junk.com"}\n{"data": {"url": ["x.example.net"]}}\n')
        out = str(self.root / 'hosts.txt')
        self.assertEqual(self.run_cli(src, '-o', out, '--field', 'url'), 0)
        self.assertEqual(Path(out).read_text().splitlines(), ['example.org','x.example.net'])

    def test_csv_and_formats(self):
        src = self.path('report.csv', 'url,detail\nhttps://example.org/a,foo.com\nhttps://example.net/b,bar.com\n')
        dest = str(self.root / 'out.jsonl')
        self.assertEqual(self.run_cli(src, '-o', dest, '--field','url','--format','jsonl'), 0)
        values = [json.loads(x)['value'] for x in Path(dest).read_text().splitlines()]
        self.assertEqual(values, ['example.org','example.net'])

    def test_json_document(self):
        src = self.path('report.json', '[{"host":"first.example.org"},{"host":"second.example.org"}]')
        self.assertEqual([x[3] for x in read_records(src, 'auto', frozenset(['host']))], ['first.example.org', 'second.example.org'])

    def test_sqlite_and_sort(self):
        src = self.path('data.txt', 'z.com a.com z.com 1.1.1.1 8.8.8.8')
        dest = str(self.root / 'out.txt')
        self.assertEqual(self.run_cli(src,'-o',dest,'--sort','--dedupe','sqlite'), 0)
        self.assertEqual(Path(dest).read_text().splitlines(), ['1.1.1.1', '8.8.8.8', 'a.com', 'z.com'])

    def test_refuse_overwriting_input(self):
        src = self.path('orig.txt', 'example.com\n')
        self.assertEqual(self.run_cli(src, '-o', src), 2)
        self.assertEqual(Path(src).read_text(), 'example.com\n')

    def test_csv_output(self):
        src = self.path('src.txt', 'abc.example.org')
        dest = str(self.root / 'out.csv')
        self.assertEqual(self.run_cli(src, '-o', dest, '--format','csv'), 0)
        self.assertEqual(Path(dest).read_text().splitlines()[0], 'kind,value,source,line,location,raw,reason')

    def test_stats(self):
        src = self.path('a.txt','example.com example.com')
        out = str(self.root/'targets.txt')
        stats = str(self.root/'stats.json')
        self.assertEqual(self.run_cli(src,'-o',out,'--stats-json',stats), 0)
        result = json.loads(Path(stats).read_text())
        self.assertEqual(result['duplicates'],1)
        self.assertEqual(result['unique'],1)


if __name__ == '__main__':
    unittest.main()
