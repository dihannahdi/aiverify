import datetime
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aiverify import apache, monitor, store as store_mod  # noqa: E402
from aiverify.ranges import RangeSet  # noqa: E402

GOOGLEBOT = b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def line(ip, ua=GOOGLEBOT, status=b"200"):
    now = int(time.time())
    return b'%d site.example %s "-" "GET / HTTP/1.1" %s 100 "-" "%s"\n' % (now, ip.encode(), status, ua)


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        s = {"lists": {}}
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        store_mod.observe(s, "googlebot", ["66.249.64.0/27"], today, "test")
        self.store = os.path.join(self.dir.name, "store.json")
        store_mod.save(s, self.store)
        self.db = os.path.join(self.dir.name, "m.sqlite")
        patches = [mock.patch.object(monitor, "cloudflare_ranges", return_value=RangeSet(["173.245.48.0/20"]))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.dir.cleanup()

    def run_lines(self, lines, rdns_result):
        with mock.patch.object(monitor, "fcrdns", return_value=rdns_result):
            m = monitor.Monitor(self.store, os.path.join(self.dir.name, "claims.log"), self.db)
            for raw in lines:
                m.handle(raw)
            for _, _, _, _, _, fut in m.rdns_pending:
                fut.result(timeout=5)
            m.flush()
            # a second request from the same IP is decided from the cache, without a new lookup
            for raw in lines:
                m.handle(raw)
            m.flush()
            m.db.close()
        db = sqlite3.connect(self.db)
        guard = db.execute("SELECT site, cls FROM guard").fetchall()
        status = db.execute("SELECT verdict, status, n FROM status").fetchall()
        db.close()
        return guard, status

    def test_unlisted_ip_that_passes_fcrdns_trips(self):
        guard, _ = self.run_lines([line("203.0.113.9", status=b"403")], ("pass", "googlebot.com"))
        self.assertEqual(guard, [("site.example", "googlebot"), ("site.example", "googlebot")])

    def test_unlisted_ip_that_fails_fcrdns_is_quiet(self):
        guard, status = self.run_lines([line("203.0.113.9", status=b"403")], ("wrong_domain", "googleusercontent.com"))
        self.assertEqual(guard, [])
        self.assertEqual(status, [("never", "403", 2)])

    def test_listed_ip_that_passes_fcrdns_is_quiet(self):
        guard, status = self.run_lines([line("66.249.64.5")], ("pass", "googlebot.com"))
        self.assertEqual(guard, [])
        self.assertEqual(status, [("verified", "200", 2)])


class ExemptTest(unittest.TestCase):
    def test_exempt_cidrs_in_every_class_block(self):
        s = {"lists": {}}
        store_mod.observe(s, "googlebot", ["66.249.64.0/27"], "2025-01-01T00:00:00Z", "t")
        store_mod.observe(s, "gptbot", ["20.0.0.0/24"], "2025-01-01T00:00:00Z", "t")
        text, _ = apache.enforce_conf(store_mod.all_versioned(s), datetime.date(2025, 3, 1).toordinal(), {},
                                      exempt=["173.245.48.0/20"])
        self.assertEqual(text.count("Require ip 173.245.48.0/20"), 2)
        self.assertEqual(text.count("<RequireAny>"), 2)


if __name__ == "__main__":
    unittest.main()
