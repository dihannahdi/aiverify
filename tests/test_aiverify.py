import datetime
import ipaddress
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aiverify import apache, fetch, store as store_mod  # noqa: E402
from aiverify.ranges import RangeSet, VersionedList  # noqa: E402
from aiverify.vendors import classify  # noqa: E402
from aiverify.verify import Verifier, client_ip  # noqa: E402


def ip(text):
    return ipaddress.ip_address(text)


def day(iso):
    return datetime.date.fromisoformat(iso).toordinal()


class RangeSetTest(unittest.TestCase):
    def test_ipv4_edges(self):
        r = RangeSet(["10.0.0.0/24"])
        self.assertIn(ip("10.0.0.0"), r)
        self.assertIn(ip("10.0.0.255"), r)
        self.assertNotIn(ip("10.0.1.0"), r)
        self.assertNotIn(ip("9.255.255.255"), r)

    def test_ipv6_and_families_are_separate(self):
        r = RangeSet(["2001:db8::/32", "10.0.0.0/8"])
        self.assertIn(ip("2001:db8:ffff::1"), r)
        self.assertNotIn(ip("2001:db9::1"), r)
        self.assertNotIn(ip("::ffff:10.0.0.1"), r)  # v4-mapped v6 is not the v4 address

    def test_overlapping_and_adjacent_prefixes_merge(self):
        r = RangeSet(["10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/24", "10.0.0.7/32"])
        self.assertEqual(r.starts[4], [int(ip("10.0.0.0"))])
        self.assertEqual(r.ends[4], [int(ip("10.0.0.255"))])

    def test_host_bits_and_bare_addresses(self):
        r = RangeSet(["192.0.2.77/24", "198.51.100.9"])
        self.assertIn(ip("192.0.2.1"), r)
        self.assertIn(ip("198.51.100.9"), r)
        self.assertNotIn(ip("198.51.100.10"), r)

    def test_empty(self):
        self.assertNotIn(ip("1.1.1.1"), RangeSet([]))


class VersionedListTest(unittest.TestCase):
    # A: 1 Jan - 31 Jan holds 10.0.0.0/24; B from 1 Feb drops it and adds 10.0.1.0/24; A again from 1 Apr.
    def setUp(self):
        contents = {"A": ["10.0.0.0/24"], "B": ["10.0.1.0/24"]}
        self.vl = VersionedList([(day("2025-01-01"), day("2025-01-20"), "A"),
                                 (day("2025-02-01"), day("2025-03-10"), "B"),
                                 (day("2025-04-01"), day("2025-04-01"), "A")], contents)

    def test_in_force(self):
        self.assertEqual(self.vl.in_force(day("2024-12-01")), 0)  # before history: first version
        self.assertEqual(self.vl.in_force(day("2025-01-31")), 0)  # in force until the next version starts
        self.assertEqual(self.vl.in_force(day("2025-02-01")), 1)
        self.assertEqual(self.vl.in_force(day("2026-01-01")), 2)

    def test_verdicts(self):
        a, b = ip("10.0.0.5"), ip("10.0.1.5")
        self.assertEqual(self.vl.verdict(a, day("2025-01-31")), "verified")
        self.assertEqual(self.vl.verdict(a, day("2025-02-10")), "other_time")
        self.assertEqual(self.vl.verdict(a, day("2025-02-10"), tolerance=10), "tolerance")  # A ended 31 Jan
        self.assertEqual(self.vl.verdict(a, day("2025-03-25"), tolerance=7), "tolerance")  # A again on 1 Apr
        self.assertEqual(self.vl.verdict(b, day("2025-04-02")), "other_time")
        self.assertEqual(self.vl.verdict(ip("10.0.2.1"), day("2025-02-10"), tolerance=999), "never")

    def test_distance(self):
        a = ip("10.0.0.5")
        self.assertEqual(self.vl.distance(a, day("2025-01-15")), 0)
        self.assertEqual(self.vl.distance(a, day("2025-02-05")), 5)
        self.assertEqual(self.vl.distance(a, day("2025-03-29")), 3)
        self.assertIsNone(self.vl.distance(ip("8.8.8.8"), day("2025-03-29")))

    def test_allowed_prefixes_window(self):
        self.assertEqual(self.vl.allowed_prefixes(day("2025-03-15"), 0), ["10.0.1.0/24"])
        self.assertEqual(self.vl.allowed_prefixes(day("2025-03-15"), 60), ["10.0.0.0/24", "10.0.1.0/24"])
        self.assertEqual(self.vl.allowed_prefixes(day("2025-05-01"), 0), ["10.0.0.0/24"])


class StoreTest(unittest.TestCase):
    def test_observe_extends_and_flaps(self):
        s = {"lists": {}}
        self.assertTrue(store_mod.observe(s, "x", ["10.0.0.0/24"], "2025-01-01T00:00:00Z", "t"))
        self.assertFalse(store_mod.observe(s, "x", ["10.0.0.0/24"], "2025-01-05T00:00:00Z", "t"))
        self.assertTrue(store_mod.observe(s, "x", ["10.0.1.0/24"], "2025-02-01T00:00:00Z", "t"))
        self.assertTrue(store_mod.observe(s, "x", ["10.0.0.0/24"], "2025-03-01T00:00:00Z", "t"))
        v = s["lists"]["x"]["versions"]
        self.assertEqual(len(v), 3)
        self.assertEqual(v[0][1], "2025-01-05T00:00:00Z")
        self.assertEqual(len(s["lists"]["x"]["contents"]), 2)

    def test_out_of_order_rejected(self):
        s = {"lists": {}}
        store_mod.observe(s, "x", ["10.0.0.0/24"], "2025-02-01T00:00:00Z", "t")
        with self.assertRaises(ValueError):
            store_mod.observe(s, "x", ["10.0.1.0/24"], "2025-01-01T00:00:00Z", "t")

    def test_content_id_ignores_order(self):
        self.assertEqual(store_mod.content_id(["b", "a"]), store_mod.content_id(["a", "b"]))

    def test_save_load_roundtrip(self):
        s = {"lists": {}}
        store_mod.observe(s, "x", ["10.0.0.0/24"], "2025-01-01T00:00:00Z", "t")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            store_mod.save(s, path)
            self.assertEqual(store_mod.load(path), s)


class ParseTest(unittest.TestCase):
    def test_json_variants(self):
        raw = json.dumps({"prefixes": [{"ipv4Prefix": "10.0.0.0/24"}, {"ipv6Prefix": "2001:db8::/32"},
                                       {"ip_prefix": "3.82.67.224/32"}, {"ipv4Prefix": "3.81.245.78"},
                                       {"ipv4Prefix": "not-an-ip"}]}).encode()
        self.assertEqual(fetch.parse_json(raw),
                         ["10.0.0.0/24", "2001:db8::/32", "3.81.245.78/32", "3.82.67.224/32"])

    def test_gzip(self):
        import gzip
        raw = gzip.compress(json.dumps({"prefixes": [{"ipv4Prefix": "10.0.0.0/24"}]}).encode())
        self.assertEqual(fetch.parse_json(raw), ["10.0.0.0/24"])

    def test_garbage(self):
        self.assertIsNone(fetch.parse_json(b"<html>blocked</html>"))
        self.assertIsNone(fetch.parse_json(json.dumps({"prefixes": []}).encode()))

    def test_amazon_html(self):
        page = ('<pre><code class="container">{\n  &quot;creationTime&quot;: &quot;x&quot;,\n  &quot;prefixes&quot;:'
                ' [ { &quot;ipv4Prefix&quot;: &quot;3.81.245.78&quot; } ] }</code></pre>').encode()
        self.assertEqual(fetch.parse_amazon_html(page), ["3.81.245.78/32"])


class ClassifyTest(unittest.TestCase):
    def test_specific_before_generic(self):
        self.assertEqual(classify("Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)"),
                         "oai-searchbot")
        self.assertEqual(classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0;"
                                  " +https://openai.com/bot"), "chatgpt-user")
        self.assertEqual(classify(b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
                         "googlebot")
        self.assertEqual(classify("Perplexity-User/1.0"), "perplexity-user")
        self.assertIsNone(classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0"))


class ClientIpTest(unittest.TestCase):
    cf = RangeSet(["173.245.48.0/20"])

    def test_header_trusted_only_from_cloudflare(self):
        self.assertEqual(client_ip("173.245.48.1", "66.249.66.1", self.cf), (ip("66.249.66.1"), "via_cloudflare"))
        self.assertEqual(client_ip("203.0.113.9", "66.249.66.1", self.cf), (ip("203.0.113.9"), "direct"))
        self.assertEqual(client_ip("173.245.48.1", "-", self.cf), (None, "proxy"))
        self.assertEqual(client_ip("garbage", "-", self.cf), (None, "bad_ip"))


class VerifierTest(unittest.TestCase):
    def setUp(self):
        s = {"lists": {}}
        store_mod.observe(s, "gptbot", ["20.0.0.0/24"], "2025-01-01T00:00:00Z", "t")
        store_mod.observe(s, "chatgpt-user", ["30.0.0.0/24"], "2025-01-01T00:00:00Z", "t")
        store_mod.observe(s, "chatgpt-user", ["30.0.1.0/24"], "2025-03-01T00:00:00Z", "t")
        self.v = Verifier(s)

    def test_check(self):
        d = day("2025-03-15")
        self.assertEqual(self.v.check(ip("20.0.0.9"), "GPTBot/1.1", d), ("gptbot", "verified"))
        self.assertEqual(self.v.check(ip("34.1.1.1"), "GPTBot/1.1", d), ("gptbot", "never"))
        self.assertEqual(self.v.check(ip("30.0.0.9"), "ChatGPT-User/1.0", d), ("chatgpt-user", "tolerance"))
        self.assertEqual(self.v.check(ip("34.1.1.1"), "Bytespider", d), ("bytespider", "unverifiable"))
        self.assertEqual(self.v.check(ip("34.1.1.1"), "ClaudeBot/1.0", d), ("claudebot", "unverifiable"))
        self.assertEqual(self.v.check(ip("34.1.1.1"), "Firefox", d), (None, "not_crawler"))


class ApacheConfTest(unittest.TestCase):
    def test_enforce_conf(self):
        s = {"lists": {}}
        store_mod.observe(s, "gptbot", ["20.0.0.0/24", "2001:db8::/32"], "2025-01-01T00:00:00Z", "t")
        text, counts = apache.enforce_conf(store_mod.all_versioned(s), day("2025-03-01"), {})
        self.assertEqual(counts, {"gptbot": 2})
        self.assertIn("AuthMerging And", text)
        self.assertIn("Require ip 20.0.0.0/24 2001:db8::/32", text)
        self.assertIn("reqenv('aiv_cls') != 'gptbot'", text)
        # the generic token must be set before the specific one, so the specific one wins
        self.assertLess(text.index('"gptbot" aiv_cls'), text.index('"oai-searchbot" aiv_cls'))
        self.assertNotIn("'bytespider'", text)
        text2, _ = apache.enforce_conf(store_mod.all_versioned(s), day("2025-03-01"), {}, deny_unverifiable=True)
        self.assertIn("reqenv('aiv_cls') != 'bytespider'", text2)
        # gated by default, so requests that claim no crawler skip the authz tree
        self.assertIn("<If \"-n reqenv('aiv_cls')\">", text)
        self.assertTrue(text.rstrip().endswith("</If>"))
        text3, _ = apache.enforce_conf(store_mod.all_versioned(s), day("2025-03-01"), {}, gate="location")
        self.assertIn('<Location "/">', text3)
        self.assertTrue(text3.rstrip().endswith("</Location>"))

    def test_claims_conf(self):
        text = apache.claims_log_conf("/www/wwwlogs/aiverify-claims.log")
        self.assertIn("GlobalLog \"/www/wwwlogs/aiverify-claims.log\"", text)
        self.assertIn("env=aiv_claim", text)


class MonitorLineTest(unittest.TestCase):
    def test_line_format_matches_claims_log(self):
        from aiverify.monitor import LINE, kind_of
        raw = (b'1760000000 app.example.id 173.245.48.1 "66.249.66.1" "GET /robots.txt HTTP/1.1" 200 1234 '
               b'"-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) \\"q\\""')
        m = LINE.match(raw)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(2), b"app.example.id")
        self.assertEqual(m.group(4), b"66.249.66.1")
        self.assertEqual(kind_of(m.group(5)), "robots")
        self.assertEqual(kind_of(b"GET /a/b.css?v=1 HTTP/1.1"), "static")
        self.assertEqual(kind_of(b"GET /artikel HTTP/1.1"), "page")


if __name__ == "__main__":
    unittest.main()
