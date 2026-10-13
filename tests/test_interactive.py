"""CLI safety and user-facing preset behavior."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netvane.cli import main


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


class UserFacingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.source = self.root / 'input.txt'
        self.source.write_text('8.8.8.8 2001:db8::10 alpha.example.org https://beta.example.org/a 10.10.10.10/8\n')

    def run_cli(self, *args):
        with contextlib.redirect_stderr(io.StringIO()):
            return main([str(self.source), *args, '--quiet'])

    def output(self, *args):
        path = self.root / 'out.txt'
        self.assertEqual(self.run_cli('-o', str(path), *args), 0)
        return path.read_text().splitlines()

    def test_ipv4_only(self):
        self.assertEqual(self.output('--types', 'ipv4'), ['8.8.8.8'])

    def test_ipv6_only(self):
        self.assertEqual(self.output('--types', 'ipv6'), ['2001:db8::10'])

    def test_ipv4_and_domains(self):
        self.assertEqual(self.output('--types', 'ipv4,domain'),
                         ['8.8.8.8', 'alpha.example.org', 'beta.example.org'])

    def test_urls_explicitly_requested(self):
        self.assertEqual(self.output('--types', 'url'), ['https://beta.example.org/a'])

    def test_cidr_explicitly_requested(self):
        self.assertEqual(self.output('--types', 'cidr'), ['10.0.0.0/8'])

    def test_unknown_type_refuses_output(self):
        output = self.root / 'nothing.txt'
        self.assertEqual(self.run_cli('-o', str(output), '--types', 'ipv4,host'), 2)
        self.assertFalse(output.exists())

    def test_existing_output_is_protected(self):
        output = self.root / 'out.txt'
        output.write_text('DO NOT DELETE\n')
        self.assertEqual(self.run_cli('-o', str(output)), 2)
        self.assertEqual(output.read_text(), 'DO NOT DELETE\n')
        self.assertEqual(self.run_cli('-o', str(output), '--force', '--types', 'ipv4'), 0)
        self.assertEqual(output.read_text().splitlines(), ['8.8.8.8'])

    def test_output_symlink_to_input_is_protected_even_with_force(self):
        output = self.root / 'alias.txt'
        output.symlink_to(self.source)
        self.assertEqual(self.run_cli('-o', str(output), '--force'), 2)
        self.assertIn('alpha.example.org', self.source.read_text())

    def test_reject_duplicate_output_paths(self):
        output = str(self.root / 'out.txt')
        self.assertEqual(self.run_cli('-o', output, '--ips-out', output), 2)
        self.assertFalse(Path(output).exists())

    def test_wizard_preset_and_output_name(self):
        output = self.root / 'selection.txt'
        answers = ['5', str(self.source), 'n', 'n', 'n', 'n', str(output), 'n']
        with patch('sys.stdin', FakeTTY()), patch('builtins.input', side_effect=answers), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--wizard']), 0)
        self.assertEqual(output.read_text().splitlines(),
                         ['8.8.8.8', 'alpha.example.org', 'beta.example.org'])

    def test_wizard_declines_overwrite(self):
        output = self.root / 'important.txt'
        output.write_text('leave me alone')
        answers = ['1', str(self.source), 'n', 'n', 'n', 'n', str(output), 'n', 'n']
        with patch('sys.stdin', FakeTTY()), patch('builtins.input', side_effect=answers), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--wizard']), 0)
        self.assertEqual(output.read_text(), 'leave me alone')

    def test_wizard_with_extra_flags_errors(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--wizard', '--types', 'ipv4']), 2)



class ThemeAndAdvancedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'sample.txt'
        self.source.write_text('hxxps://example[.]org/path 8.8.8.8 [2001:db8::9]:0443\n')

    def test_advanced_wizard_generates_multiple_exports(self):
        out = self.root / 'results.jsonl'
        ips = self.root / 'ips.txt'
        domains = self.root / 'domains.txt'
        audit = self.root / 'audit.jsonl'
        answers = ['8', str(self.source), 'y', 'y', 'n', 'y', str(out), 'y',
                   'jsonl', 'y', 'n', 'y', str(ips), 'y', str(domains),
                   'y', str(audit), '', '']
        with patch('sys.stdin', FakeTTY()), patch('builtins.input', side_effect=answers), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--wizard']), 0)
        records = [json.loads(line) for line in out.read_text().splitlines()]
        self.assertTrue(any(x['kind'] == 'url' for x in records))
        self.assertIn('8.8.8.8', ips.read_text())
        self.assertIn('example.org', domains.read_text())
        self.assertTrue(audit.is_file())

    def test_metric_symlinks_rejected_even_with_force(self):
        out = self.root / 'list.txt'
        dest = self.root / 'valuable.txt'
        dest.write_text('keep this safe')
        alias = self.root / 'stats.json'
        alias.symlink_to(dest)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.source), '-o', str(out),
                                   '--stats-json', str(alias), '--force']), 2)
        self.assertFalse(out.exists())
        self.assertEqual(dest.read_text(), 'keep this safe')

    def test_no_color_forced_non_tty(self):
        from netvane.ui import Console
        with patch('sys.stderr', io.StringIO()):
            ui = Console(ui='always')
            self.assertTrue(ui.active)
            self.assertFalse(ui.color)

    def test_version_is_new_name(self):
        from netvane import __version__
        self.assertEqual(__version__, '1.0.0')


if __name__ == '__main__':
    unittest.main()
