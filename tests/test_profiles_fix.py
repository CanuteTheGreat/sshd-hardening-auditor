import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sshd_audit as sa  # noqa: E402

L2_ONLY = {"X11Forwarding", "AllowTcpForwarding", "GSSAPIAuthentication"}


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sa.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestProfiles(unittest.TestCase):
    def test_l1_drops_exactly_the_level_2_rules(self):
        l2 = {r["key"] for r in sa.audit({}, "l2")}
        l1 = {r["key"] for r in sa.audit({}, "l1")}
        self.assertEqual(l2 - l1, L2_ONLY)
        self.assertTrue(l1 < l2)

    def test_default_is_all_rules(self):
        self.assertEqual(sa.audit({}), sa.audit({}, "l2"))

    def test_cli_profile_l1_hides_level_2_findings(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            open(p, "w").write("X11Forwarding yes\nAllowTcpForwarding yes\n")
            _, out1, _ = run(["--no-file-checks", "--fail-on", "never", "--profile", "l1", p])
            _, out2, _ = run(["--no-file-checks", "--fail-on", "never", "--profile", "l2", p])
        self.assertNotIn("X11Forwarding", out1)
        self.assertNotIn("AllowTcpForwarding", out1)
        self.assertIn("X11Forwarding = yes", out2)
        self.assertIn("AllowTcpForwarding = yes", out2)

    def test_algorithms_stay_in_level_1(self):
        cfg = sa.parse_sshd_config("Ciphers 3des-cbc\n")
        keys = [r["key"] for r in sa.audit(cfg, "l1") if not r["pass"]]
        self.assertTrue(any("cipher" in k.lower() for k in keys), keys)

    def test_invalid_profile_rejected(self):
        with self.assertRaises(SystemExit):
            run(["--profile", "l3"])


class TestFix(unittest.TestCase):
    BAD = ("PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\nMaxAuthTries 10\n"
           "LoginGraceTime 3m\nLogLevel QUIET\n")

    def _results(self, text, profile="l2"):
        return sa.audit(sa.parse_sshd_config(text), profile)

    def test_snippet_sets_failing_directives(self):
        snip = sa.fix_snippet(self._results(self.BAD))
        for line in ("PermitRootLogin no", "PasswordAuthentication no", "X11Forwarding no",
                     "MaxAuthTries 4", "LoginGraceTime 60", "LogLevel VERBOSE"):
            self.assertIn("\n" + line + "\n", snip)
        self.assertIn("locks you out", snip)
        self.assertIn("sshd -t", snip)

    def test_applying_the_snippet_fixes_the_config(self):
        snip = sa.fix_snippet(self._results(self.BAD))
        # sshd: first value wins, so the drop-in goes first
        res = self._results(snip + "\n" + self.BAD)
        failing = {r["key"] for r in res if not r["pass"]}
        for k in ("PermitRootLogin", "PasswordAuthentication", "X11Forwarding", "MaxAuthTries",
                  "LoginGraceTime", "LogLevel"):
            self.assertNotIn(k, failing)

    def test_every_fix_value_passes_its_own_rule(self):
        by_key = {r.key: r for r in sa.RULES}
        for key, val in sa.FIXES.items():
            self.assertIn(key, by_key)
            res = sa.audit(sa.parse_sshd_config("%s %s\n" % (key, val)))
            self.assertTrue([r for r in res if r["key"] == key][0]["pass"], key)

    def test_level_2_findings_not_fixed_under_l1(self):
        snip = sa.fix_snippet(self._results(self.BAD, "l1"))
        self.assertNotIn("X11Forwarding", snip)

    def test_allowusers_is_left_to_the_owner(self):
        snip = sa.fix_snippet(self._results(""))
        self.assertIn("# AllowUsers/AllowGroups: needs your list", snip)
        self.assertNotIn("\nAllowUsers ", snip)

    def test_clean_config_has_nothing_to_fix(self):
        good = "".join("%s %s\n" % kv for kv in sa.FIXES.items()) + "AllowGroups ssh\n"
        res = [r for r in self._results(good) if r["key"] in sa.FIXES or r["key"] == "AllowUsers/AllowGroups"]
        self.assertEqual(sa.fix_snippet(res).count("\n" + "PermitRootLogin"), 0)
        self.assertIn("# Nothing to fix.", sa.fix_snippet(res))

    def test_cli_fix_writes_file_and_never_touches_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            open(p, "w").write(self.BAD)
            f = os.path.join(d, "fix.conf")
            rc, out, _ = run(["--no-file-checks", "--fix", f, p])
            self.assertEqual(rc, 1)
            self.assertIn("PermitRootLogin no\n", open(f).read())
            self.assertEqual(open(p).read(), self.BAD)

    def test_cli_fix_stdout_and_json_keeps_stdout_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            open(p, "w").write(self.BAD)
            _, out, _ = run(["--no-file-checks", "--fix", "-", p])
            self.assertIn("PermitRootLogin no", out)
            _, out, err = run(["--no-file-checks", "--json", "--fix", "-", p])
            import json
            json.loads(out)
            self.assertIn("PermitRootLogin no", err)

    def test_cli_fix_unwritable_path_is_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            open(p, "w").write(self.BAD)
            rc, _, err = run(["--no-file-checks", "--fix", os.path.join(d, "no", "such", "f"), p])
            self.assertEqual(rc, 2)
            self.assertIn("ERROR", err)


if __name__ == "__main__":
    unittest.main()
