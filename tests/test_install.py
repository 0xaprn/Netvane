"""User-local installation without pip or privileged files."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = Path(self.folder.name)
        self.env = dict(os.environ, HOME=str(self.home))

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(PROJECT / 'install.py'), *args],
                              text=True, capture_output=True, env=self.env)

    @unittest.skipUnless(os.name == 'posix', 'Unix user installer')
    def test_install_and_launch_command(self):
        self.assertEqual(self.invoke().returncode, 0)
        launcher = self.home / '.local/bin/netvane'
        output = subprocess.run([str(launcher), '--version'], text=True,
                                capture_output=True, env=self.env)
        self.assertEqual(output.returncode, 0)
        self.assertIn('Netvane 1.0.0', output.stdout)
        self.assertNotEqual(self.invoke().returncode, 0)  # explicit update only
        self.assertEqual(self.invoke('--force').returncode, 0)

    @unittest.skipUnless(os.name == 'posix', 'Unix user installer')
    def test_refuse_to_replace_unrelated_launcher(self):
        bin_dir = self.home / '.local/bin'
        bin_dir.mkdir(parents=True)
        launcher = bin_dir / 'netvane'
        launcher.write_text('important unrelated command')
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(launcher.read_text(), 'important unrelated command')
