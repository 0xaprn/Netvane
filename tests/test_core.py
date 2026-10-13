import ipaddress
import unittest

from netvane.core import extract_line, prepare_line


def results(text, **options):
    return list(extract_line(text, 'demo.txt', 9, **options))


def accepted(text, **options):
    return [(f.kind, f.value) for f in results(text, **options) if f.status == 'accepted']


class ExtractTests(unittest.TestCase):
    def test_mixed_order(self):
        self.assertEqual(accepted('z.example.org 8.8.8.8 https://example.com:443/a'),
                         [('domain', 'z.example.org'), ('ipv4', '8.8.8.8'), ('domain', 'example.com:443')])

    def test_ipv4_port(self):
        self.assertIn(('ipv4', '8.8.8.8:443'), accepted('8.8.8.8:00443'))

    def test_invalid_ip(self):
        f = results('999.1.2.3')[0]
        self.assertEqual(f.status, 'rejected')

    def test_bad_url_port(self):
        self.assertEqual(results('https://example.org:99999')[0].status, 'rejected')

    def test_bad_port_suffix_is_not_accepted_as_host(self):
        for raw in ('one.example.org:bad', '8.8.8.8:bad', '[2001:db8::1]:nope', '8.8.8.8/88junk'):
            with self.subTest(raw=raw):
                item = results(raw, allow_cidr=True)[0]
                self.assertEqual(item.status, 'rejected')

    def test_status_labels_are_ignored(self):
        self.assertEqual(accepted('[200] [403] 1.2.3.4'), [('ipv4', '1.2.3.4')])

    def test_bad_domain_port(self):
        self.assertEqual(results('foo.example.com:00000')[0].status, 'rejected')

    def test_ipv6(self):
        self.assertEqual(accepted('2001:0db8::0001 [2001:db8::2]:0443'),
                         [('ipv6', '2001:db8::1'), ('ipv6', '[2001:db8::2]:443')])

    def test_ipv6_url_and_mapped(self):
        self.assertEqual(accepted('http://[::ffff:192.0.2.1]:8080/hello', keep_urls=True),
                         [('ipv6', '[::ffff:192.0.2.1]:8080'), ('url', 'http://[::ffff:192.0.2.1]:8080/hello')])

    def test_clock_not_ipv6(self):
        self.assertEqual(results('12:30:00'), [])

    def test_cidr(self):
        self.assertIn(('cidr', '10.0.0.0/8'), accepted('10.23.45.67/8', allow_cidr=True))
        self.assertEqual(results('10.23.45.67/8')[0].status, 'rejected')

    def test_defanged_and_raw(self):
        f = results('hxxps://t[.]example[.]com/xyz', fang=True, keep_urls=True)
        self.assertEqual(f[0].value, 't.example.com')
        self.assertEqual(f[1].value, 'https://t.example.com/xyz')
        self.assertEqual(f[1].raw, 'hxxps://t[.]example[.]com/xyz')

    def test_ansi_and_line_provenance(self):
        f = results('\x1b[31mexample.org\x1b[0m')[0]
        self.assertEqual(f.raw, 'example.org')
        self.assertEqual(f.line, 9)

    def test_idn(self):
        self.assertIn(('domain', 'xn--bcher-kva.de'), accepted('bücher.de'))

    def test_ambiguous(self):
        f = results('report.pdf')[0]
        self.assertEqual(f.status, 'ambiguous')
        self.assertEqual(results('report.pdf', include_ambiguous=True)[0].status, 'accepted')

    def test_trailing_punctuation(self):
        self.assertEqual(accepted('(https://www.example.org/test).', keep_urls=True)[1],
                         ('url', 'https://www.example.org/test'))

    def test_url_credentials_removed(self):
        self.assertIn(('url', 'https://example.org/path'), accepted('https://user:secret@example.org/path', keep_urls=True))

    def test_no_ip_fragment_from_malformed_url(self):
        res = results('http://127.0.0.1:99999', keep_urls=True)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].status, 'rejected')

    def test_long_text_does_not_duplicate(self):
        txt = ' '.join(['alpha.example.com'] * 100)
        self.assertEqual(len(results(txt)), 100)  # dedupe is a CLI concern

    def test_scope_compounds(self):
        self.assertEqual(prepare_line('abc[.]com', fang=True)[0], 'abc.com')


if __name__ == '__main__':
    unittest.main()
