"""End-to-end tests for sshd_audit.py: every documented option and check.

The tool is always run as a real subprocess (the way users run it). The
--live tests and the parser-vs-sshd cross-checks use the real OpenSSH
server (`sshd -T`), which ci/setup.sh installs in the CI container.
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
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
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
LogLevel VERBOSE
MaxSessions 4
MaxStartups 10:30:60
Banner /etc/issue.net
StrictModes yes
GSSAPIAuthentication no
KbdInteractiveAuthentication no
AllowGroups ssh-users
ClientAliveCountMax 3
"""
N_RULES = 22          # config rules, one result each
N_HARDENED = N_RULES + 4  # + kex/ciphers/macs set explicitly + post-quantum


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

    def audit_json(self, text, *extra):
        p = run("--json", "--no-file-checks", *extra, self.cfg(text))
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return p.returncode, {r["key"]: r for r in json.loads(p.stdout)}

    def with_override(self, key, value):
        lines = [l for l in HARDENED.splitlines() if not l.startswith(key + " ")]
        return f"{key} {value}\n" + "\n".join(lines) + "\n"


class TestChecks(Base):
    def test_hardened_config_passes_everything(self):
        code, res = self.audit_json(HARDENED)
        self.assertEqual(code, 0)
        self.assertTrue(all(r["pass"] for r in res.values()), [r for r in res.values() if not r["pass"]])
        self.assertEqual(len(res), N_HARDENED)

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
                              ("AllowTcpForwarding", "yes", "LOW"), ("UsePAM", "no", "LOW"),
                              ("LogLevel", "QUIET", "LOW"), ("MaxSessions", "20", "LOW"),
                              ("MaxStartups", "10:30:100", "LOW"), ("Banner", "none", "LOW"),
                              ("StrictModes", "no", "MEDIUM"), ("GSSAPIAuthentication", "yes", "LOW"),
                              ("KbdInteractiveAuthentication", "yes", "MEDIUM"), ("ClientAliveCountMax", "10", "LOW")]:
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

    def test_cis_details(self):
        for v, ok in (("10:30:60", True), ("5:50:20", True), ("10", True), ("10:30:100", False), ("20:30:60", False),
                      ("x", False)):
            with self.subTest(maxstartups=v):
                self.assertEqual(self.audit_json(self.with_override("MaxStartups", v))[1]["MaxStartups"]["pass"], ok)
        text = HARDENED.replace("KbdInteractiveAuthentication no\n", "ChallengeResponseAuthentication no\n")
        self.assertTrue(self.audit_json(text)[1]["KbdInteractiveAuthentication"]["pass"])  # pre-8.7 alias
        res = self.audit_json(HARDENED.replace("AllowGroups ssh-users\n", ""))[1]
        self.assertFalse(res["AllowUsers/AllowGroups"]["pass"])
        res = self.audit_json(HARDENED.replace("AllowGroups ssh-users\n", "DenyUsers guest\n"))[1]
        self.assertTrue(res["AllowUsers/AllowGroups"]["pass"])
        self.assertEqual(res["AllowUsers/AllowGroups"]["value"], "denyusers guest")

    def test_algorithm_severities_and_post_quantum(self):
        code, res = self.audit_json(self.with_override("MACs", "hmac-sha1,umac-64@openssh.com,hmac-sha2-256"))
        self.assertEqual((code, res["macs"]["severity"]), (0, "MEDIUM"))
        self.assertIn("umac-64@openssh.com (MEDIUM, 64-bit tag", res["macs"]["rationale"])
        self.assertIn("hmac-sha2-256 (LOW, encrypt-and-MAC", res["macs"]["rationale"])
        self.assertEqual(self.audit_json(self.with_override("MACs", "hmac-sha1"), "--fail-on", "medium")[0], 1)
        code, res = self.audit_json(self.with_override("HostKeyAlgorithms", "ssh-ed25519,ssh-rsa"))
        self.assertEqual(res["hostkeyalgorithms"]["severity"], "MEDIUM")
        code, res = self.audit_json(self.with_override("KexAlgorithms", "curve25519-sha256,ecdh-sha2-nistp256"))
        self.assertEqual(res["kexalgorithms"]["severity"], "LOW")
        self.assertFalse(res["post-quantum-kex"]["pass"])
        self.assertFalse(res["kexalgorithms"]["pass"])
        code, res = self.audit_json(self.with_override("KexAlgorithms", "-diffie-hellman-group14-sha1"))
        self.assertTrue(res["kexalgorithms"]["pass"])  # removing from the default list can't add weakness

    def test_fail_on(self):
        text = self.with_override("X11Forwarding", "yes")
        self.assertEqual(self.audit_json(text)[0], 0)
        self.assertEqual(self.audit_json(text, "--fail-on", "medium")[0], 1)
        self.assertEqual(self.audit_json(self.with_override("PermitRootLogin", "yes"), "--fail-on", "never")[0], 0)

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
        p = run("--no-file-checks", self.cfg(self.with_override("PermitRootLogin", "yes")))
        self.assertEqual(p.returncode, 1)
        self.assertIn("[HIGH] PermitRootLogin = yes", p.stdout)
        self.assertIn("Summary: 1 finding(s), %d check(s) passed, %d total." % (N_HARDENED - 1, N_HARDENED), p.stdout)

    def test_clean_text_report(self):
        p = run("--no-file-checks", self.cfg(HARDENED))
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
        for opt in ("--live", "--json", "--html", "--remote", "--fail-on", "--no-file-checks"):
            self.assertIn(opt, p.stdout)


RULE_KEYS = {"PermitRootLogin", "PasswordAuthentication", "PermitEmptyPasswords", "Protocol", "X11Forwarding",
             "MaxAuthTries", "ClientAliveInterval", "LoginGraceTime", "PermitUserEnvironment", "IgnoreRhosts",
             "HostbasedAuthentication", "AllowTcpForwarding", "UsePAM", "LogLevel", "MaxSessions", "MaxStartups",
             "Banner", "StrictModes", "GSSAPIAuthentication", "KbdInteractiveAuthentication",
             "AllowUsers/AllowGroups", "ClientAliveCountMax"}


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
                live = {r["key"]: r["pass"] for r in json.loads(run("--json", "--no-file-checks",
                                                                        self.cfg(self.sshd_T(path), "T.out")).stdout)}
                ours = {r["key"]: r["pass"] for r in json.loads(run("--json", "--no-file-checks", path).stdout)
                        if r["key"] in RULE_KEYS}
                self.assertEqual(len(ours), N_RULES)
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


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestRemoteScan(Base):
    """--remote against a real OpenSSH server started for the test (and a crafted KEXINIT for Terrapin)."""

    def start_sshd(self, algs):
        if os.geteuid() != 0:
            self.fail("remote-scan tests must run as root (sshd refuses to start otherwise)")
        key = os.path.join(self.tmp, "hostkey_ed25519")
        rsa = os.path.join(self.tmp, "hostkey_rsa")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-N", "", "-f", rsa], check=True)
        port = free_port()
        cfg = self.cfg("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nHostKey %s\nPidFile %s/sshd.pid\n%s"
                       % (port, key, rsa, self.tmp, algs), "remote_sshd_config")
        proc = subprocess.Popen([SSHD, "-D", "-e", "-f", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (proc.terminate(), proc.wait(5)))
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if proc.poll() is not None:
                    self.fail("sshd exited: " + proc.stderr.read().decode())
                time.sleep(0.05)
        return port, cfg

    def remote(self, port, *extra):
        p = run("--remote", "127.0.0.1:%d" % port, "--json", *extra)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return p.returncode, {r["key"]: r for r in json.loads(p.stdout)}

    def test_weak_server_matches_sshd_T_and_fails(self):
        port, cfg = self.start_sshd("KexAlgorithms diffie-hellman-group14-sha1,curve25519-sha256\n"
                                    "Ciphers aes128-cbc,aes256-ctr\nMACs hmac-sha1,hmac-sha2-256-etm@openssh.com\n"
                                    "HostKeyAlgorithms ssh-ed25519,ssh-rsa\n")
        code, res = self.remote(port)
        self.assertEqual(code, 1)
        self.assertEqual((res["kexalgorithms"]["severity"], res["ciphers"]["severity"]), ("HIGH", "HIGH"))
        self.assertEqual((res["macs"]["severity"], res["hostkeyalgorithms"]["severity"]), ("MEDIUM", "MEDIUM"))
        self.assertIn("aes128-cbc (HIGH", res["ciphers"]["rationale"])
        self.assertFalse(res["post-quantum-kex"]["pass"])
        # what the server offered on the wire == what sshd -T says it's configured to offer
        T = {l.split(" ", 1)[0]: l.split(" ", 1)[1] for l in self.sshd_T(cfg).splitlines() if " " in l}
        for k in ("kexalgorithms", "ciphers", "macs"):
            self.assertEqual(res[k]["value"], T[k], k)
        self.assertEqual(set(res["hostkeyalgorithms"]["value"].split(",")) & {"ssh-ed25519", "ssh-rsa"},
                         {"ssh-ed25519", "ssh-rsa"})
        p = run("--remote", "127.0.0.1:%d" % port)
        self.assertIn("Server: SSH-2.0-OpenSSH_", p.stdout)

    def test_hardened_server_passes(self):
        port, _ = self.start_sshd("KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256\n"
                                  "Ciphers aes256-gcm@openssh.com,aes256-ctr\nMACs hmac-sha2-512-etm@openssh.com\n"
                                  "HostKeyAlgorithms ssh-ed25519,rsa-sha2-512\n")
        code, res = self.remote(port)
        self.assertEqual(code, 0, [r for r in res.values() if not r["pass"]])
        self.assertTrue(all(r["pass"] for r in res.values()), res)

    def sshd_T(self, path):
        p = subprocess.run([SSHD, "-T", "-f", path], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def fake_server(self, kex, ciphers, macs, comp="none"):
        """Sends an identification string and a hand-built KEXINIT, then hangs up."""
        lst = socket.socket()
        lst.bind(("127.0.0.1", 0))
        lst.listen(1)
        self.addCleanup(lst.close)

        def serve():
            conn, _ = lst.accept()
            conn.sendall(b"SSH-2.0-FakeSSH_1.0\r\n")
            def nl(items):
                b = ",".join(items).encode()
                return struct.pack(">I", len(b)) + b
            payload = (b"\x14" + b"\x00" * 16 + nl(kex) + nl(["ssh-ed25519"]) + nl(ciphers) + nl(ciphers)
                       + nl(macs) + nl(macs) + nl([comp]) + nl([comp]) + nl([]) + nl([]) + b"\x00" + b"\x00" * 4)
            pad = 8 - (len(payload) + 5) % 8 + 8
            conn.sendall(struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad)
            conn.recv(100)
            conn.close()
        threading.Thread(target=serve, daemon=True).start()
        return lst.getsockname()[1]

    def test_terrapin_and_pre_auth_compression(self):
        port = self.fake_server(["curve25519-sha256", "ext-info-s"], ["chacha20-poly1305@openssh.com"],
                                ["hmac-sha2-256-etm@openssh.com"], comp="zlib")
        code, res = self.remote(port, "--fail-on", "medium")
        self.assertFalse(res["terrapin"]["pass"])
        self.assertIn("chacha20-poly1305@openssh.com", res["terrapin"]["value"])
        self.assertFalse(res["compression"]["pass"])
        self.assertEqual(res["kexalgorithms"]["value"], "curve25519-sha256")  # ext-info-s is a pseudo-algorithm
        self.assertEqual(code, 1)
        port = self.fake_server(["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
                                ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256-etm@openssh.com"])
        code, res = self.remote(port)
        self.assertTrue(res["terrapin"]["pass"])
        self.assertEqual(res["terrapin"]["value"], "strict kex")

    def test_unreachable_is_exit_2(self):
        p = run("--remote", "127.0.0.1:%d" % free_port(), "--timeout", "2")
        self.assertEqual(p.returncode, 2)
        self.assertIn("ERROR", p.stderr)
        self.assertNotIn("Traceback", p.stderr)


class TestFileChecks(Base):
    def test_config_and_host_key_permissions_and_size(self):
        if os.geteuid() != 0:
            self.fail("file-permission tests must run as root (ownership is part of the check)")
        weak = os.path.join(self.tmp, "weak_rsa")
        subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "1024", "-N", "", "-f", weak], check=True)
        os.chmod(weak, 0o644)
        good = os.path.join(self.tmp, "good_ed25519")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", good], check=True)
        path = self.cfg(HARDENED + "HostKey %s\nHostKey %s\n" % (weak, good))
        os.chmod(path, 0o644)
        p = run("--json", path)
        res = {r["key"]: r for r in json.loads(p.stdout)}
        self.assertEqual(p.returncode, 1)  # RSA 1024 host key is HIGH
        self.assertEqual(res["hostkey:" + weak]["value"], "RSA 1024")
        self.assertEqual(res["hostkey:" + weak]["severity"], "HIGH")
        self.assertFalse(res["perms:" + weak]["pass"])
        self.assertEqual(res["perms:" + weak]["severity"], "MEDIUM")
        self.assertTrue(res["perms:" + good]["pass"])
        self.assertNotIn("hostkey:" + good, res)  # ed25519: nothing to size-check
        self.assertFalse(res["perms:" + path]["pass"])
        self.assertEqual(res["perms:" + path]["severity"], "LOW")
        os.chmod(path, 0o600)
        res = {r["key"]: r for r in json.loads(run("--json", path).stdout)}
        self.assertTrue(res["perms:" + path]["pass"])
        p = run("--json", "--no-file-checks", path)
        self.assertFalse(any(r["key"].startswith(("perms:", "hostkey:")) for r in json.loads(p.stdout)))

    def test_version(self):
        p = run("--version")
        self.assertRegex(p.stdout, r"^sshd-hardening-auditor \d+\.\d+\.\d+$")


class TestCoreFunctions(unittest.TestCase):
    """Direct checks of the parsing and judging helpers every report depends on (mutation testing
    showed these paths were only exercised end to end, where many wrong answers still passed)."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.dirname(TOOL))
        import sshd_audit
        cls.m = sshd_audit

    def test_time_formats_follow_sshd_convtime(self):
        cases = {"90": 90, "90s": 90, "90S": 90, "1m30s": 90, "1m30": 90, "0m45": 45, "2h": 7200, "1d": 86400,
                 "1w": 604800, "1h1m1s": 3661, "1h1m1": 3661, " 5m ": 300, "0": 0}
        for value, seconds in cases.items():
            self.assertEqual(self.m._seconds(value), seconds, value)
        for bad in ("", None, "x", "1x", "m", "1.5m", "-5", "5 m"):
            self.assertIsNone(self.m._seconds(bad), bad)

    def test_worst_severity_wins_per_directive(self):
        res = {r["key"]: r for r in self.m.judge_algorithms({
            "kexalgorithms": ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group1-sha1"],
            "hostkeyalgorithms": ["ssh-ed25519", "ssh-rsa"],
            "ciphers": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
            "macs": ["hmac-sha2-256-etm@openssh.com", "hmac-sha1", "umac-64@openssh.com"]})}
        self.assertEqual((res["kexalgorithms"]["severity"], res["kexalgorithms"]["pass"]), ("HIGH", False))
        self.assertEqual((res["hostkeyalgorithms"]["severity"], res["hostkeyalgorithms"]["pass"]), ("MEDIUM", False))
        self.assertEqual((res["macs"]["severity"], res["macs"]["pass"]), ("MEDIUM", False))
        self.assertTrue(res["ciphers"]["pass"])
        self.assertEqual(res["ciphers"]["rationale"], "Only modern cipher algorithms.")
        self.assertIn("diffie-hellman-group1-sha1 (HIGH, 1024-bit DH group with SHA-1)", res["kexalgorithms"]["rationale"])
        self.assertIn("ecdh-sha2-nistp256 (LOW,", res["kexalgorithms"]["rationale"])
        self.assertIn("permitted", res["kexalgorithms"]["rationale"])
        self.assertIn("offered", self.m.judge_algorithms({"macs": ["hmac-md5"]}, "remote")[0]["rationale"])
        self.assertEqual(res["post-quantum-kex"]["pass"], False)
        self.assertEqual(res["post-quantum-kex"]["value"], "(none)")
        pq = self.m.judge_algorithms({"kexalgorithms": ["mlkem768x25519-sha256", "curve25519-sha256"]})
        self.assertEqual([(r["key"], r["pass"], r["value"]) for r in pq],
                         [("kexalgorithms", True, "mlkem768x25519-sha256,curve25519-sha256"),
                          ("post-quantum-kex", True, "mlkem768x25519-sha256")])
        self.assertEqual(self.m.judge_algorithms({}), [])

    def test_gssapi_kex_prefixes_and_modifier_lists(self):
        self.assertIsNone(self.m._alg_policy("kexalgorithms", "curve25519-sha256"))
        lists = self.m._algorithm_lists({"ciphers": "+aes128-cbc, 3des-cbc", "macs": "-hmac-md5",
                                         "kexalgorithms": "^sntrup761x25519-sha512@openssh.com"})
        self.assertEqual(lists, {"ciphers": ["aes128-cbc", "3des-cbc"], "macs": [],
                                 "kexalgorithms": ["sntrup761x25519-sha512@openssh.com"]})


if __name__ == "__main__":
    unittest.main()
