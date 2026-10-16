"""End-to-end tests for sshd_audit.py: every documented option and check.

The tool is always run as a real subprocess (the way users run it). The
--live tests and the parser-vs-sshd cross-checks use the real OpenSSH
server (`sshd -T`), which ci/setup.sh installs in the CI container.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "sshd_audit.py")
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"

HARDENED = """\
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
Protocol 2
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
LoginGraceTime 30
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
AllowTcpForwarding no
UsePAM yes
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
"""


def run(*args, env=None):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True,
                          text=True, env=env)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cfg(self, text, name="sshd_config"):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def audit_json(self, text):
        p = run("--json", self.cfg(text))
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return p.returncode, {r["key"]: r for r in json.loads(p.stdout)}

    def with_override(self, key, value):
        lines = [l for l in HARDENED.splitlines() if not l.startswith(key + " ")]
        return f"{key} {value}\n" + "\n".join(lines) + "\n"


class TestChecks(Base):
    def test_hardened_config_passes_everything(self):
        code, res = self.audit_json(HARDENED)
        self.assertEqual(code, 0)
        self.assertTrue(all(r["pass"] for r in res.values()), res)
        self.assertEqual(len(res), 13)

    def test_each_high_rule_fails_and_sets_exit_1(self):
        for key, bad in [("PermitRootLogin", "yes"), ("PasswordAuthentication", "yes"),
                         ("PermitEmptyPasswords", "yes"), ("HostbasedAuthentication", "yes"),
                         ("Protocol", "1")]:
            with self.subTest(key=key):
                code, res = self.audit_json(self.with_override(key, bad))
                self.assertEqual(code, 1)
                self.assertFalse(res[key]["pass"])
                self.assertEqual(res[key]["severity"], "HIGH")
                self.assertEqual(res[key]["value"], bad)

    def test_medium_and_low_rules_fail_without_failing_exit_code(self):
        for key, bad, sev in [("X11Forwarding", "yes", "MEDIUM"), ("MaxAuthTries", "6", "MEDIUM"),
                              ("PermitUserEnvironment", "yes", "MEDIUM"), ("IgnoreRhosts", "no", "MEDIUM"),
                              ("ClientAliveInterval", "0", "LOW"), ("LoginGraceTime", "120", "LOW"),
                              ("AllowTcpForwarding", "yes", "LOW"), ("UsePAM", "no", "LOW")]:
            with self.subTest(key=key):
                code, res = self.audit_json(self.with_override(key, bad))
                self.assertEqual(code, 0)
                self.assertFalse(res[key]["pass"])
                self.assertEqual(res[key]["severity"], sev)

    def test_prohibit_password_and_its_old_alias_are_accepted_for_root(self):
        for v in ("prohibit-password", "without-password"):
            with self.subTest(v=v):
                _, res = self.audit_json(self.with_override("PermitRootLogin", v))
                self.assertTrue(res["PermitRootLogin"]["pass"])

    def test_unset_directives_are_judged_on_openssh_defaults(self):
        code, res = self.audit_json("UsePAM yes\n")
        self.assertEqual(res["PermitRootLogin"]["value"], "prohibit-password (default)")
        self.assertTrue(res["PermitRootLogin"]["pass"])
        self.assertTrue(res["X11Forwarding"]["pass"])
        self.assertTrue(res["Protocol"]["pass"])
        self.assertEqual(res["MaxAuthTries"]["value"], "6 (default)")
        self.assertFalse(res["MaxAuthTries"]["pass"])
        self.assertFalse(res["PasswordAuthentication"]["pass"])  # defaults to yes
        self.assertEqual(code, 1)

    def test_weak_kex_cipher_mac_are_high(self):
        for directive, weak in [("KexAlgorithms", "diffie-hellman-group1-sha1"),
                                ("Ciphers", "aes128-cbc"), ("MACs", "hmac-md5")]:
            with self.subTest(directive=directive):
                code, res = self.audit_json(self.with_override(directive, "+" + weak))
                self.assertEqual(code, 1)
                f = res[directive.lower()]
                self.assertFalse(f["pass"])
                self.assertIn(weak, f["rationale"])

    def test_first_value_wins_like_sshd(self):
        _, res = self.audit_json("PermitRootLogin no\n" + HARDENED + "PermitRootLogin yes\n")
        self.assertTrue(res["PermitRootLogin"]["pass"])

    def test_match_block_does_not_override_global(self):
        text = HARDENED + "Match User deploy\n    PasswordAuthentication yes\n    PermitRootLogin yes\n"
        code, res = self.audit_json(text)
        self.assertEqual(code, 0)
        self.assertTrue(res["PasswordAuthentication"]["pass"])

    def test_include_dropin_is_applied_first(self):
        d = os.path.join(self.tmp, "sshd_config.d")
        os.mkdir(d)
        with open(os.path.join(d, "50-cloud-init.conf"), "w") as f:
            f.write("PasswordAuthentication yes\n")
        code, res = self.audit_json(f"Include {d}/*.conf\n" + HARDENED)
        self.assertEqual(code, 1)
        self.assertEqual(res["PasswordAuthentication"]["value"], "yes")

    def test_keyword_equals_value_syntax(self):
        _, res = self.audit_json(HARDENED.replace("X11Forwarding no", "X11Forwarding=yes"))
        self.assertFalse(res["X11Forwarding"]["pass"])


class TestOutputs(Base):
    def test_text_report(self):
        p = run(self.cfg(self.with_override("PermitRootLogin", "yes")))
        self.assertEqual(p.returncode, 1)
        self.assertIn("[HIGH] PermitRootLogin = yes", p.stdout)
        self.assertIn("Summary: 1 finding(s), 12 check(s) passed, 13 total.", p.stdout)

    def test_clean_text_report(self):
        p = run(self.cfg(HARDENED))
        self.assertEqual(p.returncode, 0)
        self.assertIn("No findings", p.stdout)

    def test_html_report_written_and_escaped(self):
        out = os.path.join(self.tmp, "report.html")
        p = run("--html", out, self.cfg("Ciphers aes128-cbc,<b>x</b>\n"))
        self.assertEqual(p.returncode, 1)
        with open(out) as f:
            page = f.read()
        self.assertIn("<title>SSH Hardening Audit Report</title>", page)
        self.assertIn("FAIL (HIGH)", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)

    def test_missing_file_is_usage_error(self):
        p = run(os.path.join(self.tmp, "nope"))
        self.assertEqual(p.returncode, 2)
        self.assertIn("ERROR", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_help(self):
        p = run("--help")
        self.assertEqual(p.returncode, 0)
        for opt in ("--live", "--json", "--html"):
            self.assertIn(opt, p.stdout)


class TestAgainstRealSshd(Base):
    """Uses the real OpenSSH server binary (installed by ci/setup.sh)."""

    def setUp(self):
        super().setUp()
        self.assertTrue(os.path.exists(SSHD), "OpenSSH server (sshd) must be installed for these tests")

    def sshd_T(self, path):
        p = subprocess.run([SSHD, "-T", "-f", path], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def test_parser_agrees_with_sshd_on_precedence(self):
        d = os.path.join(self.tmp, "conf.d")
        os.mkdir(d)
        with open(os.path.join(d, "10.conf"), "w") as f:
            f.write("X11Forwarding yes\n")
        cases = [
            "",
            HARDENED.replace("Protocol 2\n", ""),
            "PermitRootLogin no\nPermitRootLogin yes\n",
            "PasswordAuthentication no\nMatch User bob\n  PasswordAuthentication yes\n",
            f"Include {d}/*.conf\nX11Forwarding no\n",
            "MaxAuthTries=3\n",
        ]
        for text in cases:
            with self.subTest(text=text):
                path = self.cfg(text, "case.conf")
                live = {r["key"]: r["pass"] for r in json.loads(run("--json", self.cfg(self.sshd_T(path), "T.out")).stdout)}
                ours = {r["key"]: r["pass"] for r in json.loads(run("--json", path).stdout)}
                self.assertEqual(len(ours), 13)
                for key in ours:
                    self.assertEqual(ours[key], live[key], f"{key}: file-mode verdict differs from sshd -T")

    def test_live_mode_reads_effective_config(self):
        if os.geteuid() != 0:
            self.fail("--live test must run as root (sshd -T needs to read host keys)")
        with open("/etc/ssh/sshd_config", "w") as f:
            f.write(HARDENED.replace("Protocol 2\n", ""))
        p = run("--live", "--json")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        res = {r["key"]: r for r in json.loads(p.stdout)}
        self.assertEqual(res["PermitRootLogin"]["value"], "no")
        self.assertEqual(res["MaxAuthTries"]["value"], "3")
        with open("/etc/ssh/sshd_config", "w") as f:
            f.write("PermitRootLogin yes\nPasswordAuthentication yes\n")
        p = run("--live")
        self.assertEqual(p.returncode, 1)
        self.assertIn("[high] permitrootlogin = yes", p.stdout.lower())

    def test_live_without_sshd_is_a_clean_error(self):
        env = dict(os.environ, PATH=self.tmp)
        p = run("--live", env=env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("sshd", p.stderr)
        self.assertNotIn("Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
