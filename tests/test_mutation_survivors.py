"""Tests written from the survivors of the 2.0.0 mutation run (nightly run 90): the whole --help body, the
defaults and call arguments of _main, the JSON byte layout, and every field of audit_files / get_live_config
(stat, host keys and subprocess are stubbed, so these also run as a normal user)."""
import base64
import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sshd_audit as sa  # noqa: E402

HELP_BODY = (
    "positional arguments: config path to sshd_config options: -h, --help show this help message and exit "
    "--version show program's version number and exit --live run `sshd -T` instead of reading a file "
    "--remote HOST[:PORT] scan a running SSH server's offered algorithms over the network (no login) "
    "--timeout TIMEOUT --remote connection timeout in seconds (default 10) "
    "--no-file-checks skip sshd_config/host key permission and host key size checks "
    "--json output JSON instead of text "
    "--quiet, -q print nothing to stdout (no report, no JSON); the exit code and stderr errors remain "
    "--html FILE also write an HTML report to FILE "
    "--profile {l1,l2} CIS profile: l1 = Level 1 rules only (X11Forwarding, AllowTcpForwarding and "
    "GSSAPIAuthentication are Level 2), l2 = all rules (default) "
    "--fix FILE write an sshd_config drop-in that sets every failing directive to the recommended value "
    "('-' = stdout, stderr with --json); the config itself is never edited "
    "--fail-on {high,medium,low,never} lowest severity that makes the exit code 1 (default: high) "
    "exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage/input error, unreadable config, "
    "`sshd -T` failure or unreachable --remote server (legacy), 3 unexpected internal error")


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sa.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestHelpBody(unittest.TestCase):
    def test_whole_help_body(self):
        old = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                with self.assertRaises(SystemExit):
                    sa.main(["--help"])
        finally:
            if old is None:
                os.environ.pop("COLUMNS", None)
            else:
                os.environ["COLUMNS"] = old
        # RawDescriptionHelpFormatter keeps the docstring's own line breaks and column alignment
        self.assertIn("\n    sshd-hardening-auditor --json              # machine-readable output\n", out.getvalue())
        text = " ".join(out.getvalue().replace("optional arguments:", "options:").split())
        self.assertTrue(text.startswith("usage: sshd-hardening-auditor"), text[:80])
        self.assertIn(" ".join(sa.__doc__.split()), text)  # description is the module docstring
        self.assertEqual(text[text.index("positional arguments:"):], HELP_BODY)


class TestMainDefaults(unittest.TestCase):
    OK = "PermitRootLogin no\n"

    def test_default_config_path_is_etc_ssh_sshd_config(self):
        seen = {}

        def fake_read(p):
            seen["read"] = p
            return [self.OK]

        def fake_files(path, cfg):
            seen["files"] = path
            return []
        with mock.patch.object(sa, "_read_with_includes", fake_read), mock.patch.object(sa, "audit_files", fake_files):
            run([])
        self.assertEqual(seen, {"read": "/etc/ssh/sshd_config", "files": "/etc/ssh/sshd_config"})

    def test_live_mode_checks_files_of_etc_ssh_sshd_config(self):
        seen = {}

        def fake_files(path, cfg):
            seen["files"] = path
            return []
        with mock.patch.object(sa, "get_live_config", lambda: self.OK), mock.patch.object(sa, "audit_files", fake_files):
            run(["--live", "/somewhere/else"])
        self.assertEqual(seen, {"files": "/etc/ssh/sshd_config"})

    def test_remote_gets_host_port_and_timeout(self):
        calls = []

        def fake_remote(*a, **kw):
            calls.append((a, kw))
            return "SSH-2.0-test", []
        with mock.patch.object(sa, "audit_remote", fake_remote):
            rc, out, _ = run(["--remote", "example.test:2222", "--timeout", "3.5"])
            self.assertEqual(calls, [(("example.test", 2222, 3.5), {})])
            self.assertTrue(out.startswith("Server: SSH-2.0-test  (example.test:2222)\n\n"), out)
            del calls[:]
            run(["--remote", "example.test"])
            self.assertEqual(calls, [(("example.test", 22, 10.0), {})])

    def test_no_server_banner_line_without_remote(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            with open(p, "w") as f:
                f.write(self.OK)
            rc, out, err = run(["--no-file-checks", p])
        self.assertFalse(out.startswith("Server:"))

    def test_fix_snippet_only_built_with_fix(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            with open(p, "w") as f:
                f.write(self.OK)
            with mock.patch.object(sa, "fix_snippet", side_effect=AssertionError("called")) as fs:
                rc, out, err = run(["--no-file-checks", "--fail-on", "never", p])
            self.assertEqual((rc, err), (0, ""))
            fs.assert_not_called()

    def test_fix_dash_writes_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            with open(p, "w") as f:
                f.write("PermitRootLogin yes\n")
            cwd = os.getcwd()
            wd = os.path.join(d, "wd")
            os.mkdir(wd)
            os.chdir(wd)
            try:
                rc, out, err = run(["--no-file-checks", "--fix", "-", p])
            finally:
                os.chdir(cwd)
            self.assertEqual(os.listdir(wd), [])
        self.assertIn("PermitRootLogin no", out)

    def test_json_layout_is_indent_2(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            with open(p, "w") as f:
                f.write(self.OK)
            rc, out, err = run(["--no-file-checks", "--json", p])
        self.assertEqual(out, json.dumps(json.loads(out), indent=2) + "\n")
        self.assertTrue(out.startswith('{\n  "schema_version": 1,\n  "tool": "sshd-hardening-auditor",\n'), out[:90])

    def test_html_write_error_is_exit_2_with_message(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sshd_config")
            with open(p, "w") as f:
                f.write(self.OK)
            rc, out, err = run(["--no-file-checks", "--html", os.path.join(d, "no", "r.html"), p])
        self.assertEqual(rc, 2)
        self.assertTrue(err.startswith("sshd-hardening-auditor: ERROR -- "), err)
        self.assertIn("No such file", err)


class TestGetLiveConfig(unittest.TestCase):
    def fake(self, rc, out="", err=""):
        return mock.patch.object(sa.subprocess, "run", return_value=types.SimpleNamespace(
            returncode=rc, stdout=out, stderr=err))

    def test_failure_message_uses_stderr_when_present(self):
        with self.fake(255, "", "  permission denied \n"):
            with self.assertRaises(RuntimeError) as c:
                sa.get_live_config()
        self.assertEqual(str(c.exception), "`sshd -T` failed (exit 255): permission denied -- it usually needs root")

    def test_failure_message_without_stderr(self):
        with self.fake(1, "", "  "):
            with self.assertRaises(RuntimeError) as c:
                sa.get_live_config()
        self.assertEqual(str(c.exception), "`sshd -T` failed (exit 1): (no output) -- it usually needs root")

    def test_success_returns_stdout(self):
        with self.fake(0, "port 22\n", "warn"):
            self.assertEqual(sa.get_live_config(), "port 22\n")


def _mpint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return struct.pack(">I", len(b)) + b


def pub_rsa(bits):
    blob = struct.pack(">I", 7) + b"ssh-rsa" + _mpint(65537) + _mpint((1 << (bits - 1)) | 1)
    return "ssh-rsa " + base64.b64encode(blob).decode() + " host\n"


class TestAuditFilesStubbed(unittest.TestCase):
    """audit_files with os.stat / os.path.exists / open stubbed, so ownership is under the test's control."""

    def run_files(self, config_path, cfg, stats, pubs=None):
        pubs = pubs or {}

        def fake_stat(p):
            if p not in stats:
                raise OSError("no such file")
            mode, uid = stats[p]
            return types.SimpleNamespace(st_mode=0o100000 | mode, st_uid=uid)
        real_open = open

        def fake_open(p, *a, **kw):
            if p in pubs:
                return io.StringIO(pubs[p])
            if str(p).endswith(".pub"):
                raise OSError("no pub")
            return real_open(p, *a, **kw)
        with mock.patch.object(sa.os, "stat", fake_stat), \
                mock.patch.object(sa.os.path, "exists", lambda p: p in stats), \
                mock.patch("builtins.open", fake_open):
            return sa.audit_files(config_path, cfg)

    def test_config_perm_result_exact(self):
        r = self.run_files("/x/sshd_config", {}, {"/x/sshd_config": (0o600, 0)})
        self.assertEqual(r, [{"key": "perms:/x/sshd_config", "severity": "LOW", "value": "0600 uid=0",
                              "expected": "root, 0600 or stricter", "pass": True,
                              "rationale": "CIS: the sshd_config must be owned by root and not readable/writable by "
                                           "others."}])

    def test_group_or_other_readable_is_low_but_writable_by_others_is_medium(self):
        r = self.run_files("/c", {}, {"/c": (0o664, 0)})[0]
        self.assertEqual((r["severity"], r["pass"]), ("MEDIUM", False))  # group-write bit set, even though root owns it
        r = self.run_files("/c", {}, {"/c": (0o640, 0)})[0]
        self.assertEqual((r["severity"], r["pass"]), ("LOW", False))  # not writable by anyone else

    def test_non_root_owner_is_medium_even_with_strict_mode(self):
        r = self.run_files("/c", {}, {"/c": (0o600, 1000)})[0]
        self.assertEqual((r["severity"], r["pass"], r["value"]), ("MEDIUM", False, "0600 uid=1000"))
        self.assertEqual(r["rationale"], "CIS: the sshd_config must be owned by root and not readable/writable by "
                                         "others: owned by uid 1000 (want root)")

    def test_both_problems_joined_with_semicolon(self):
        r = self.run_files("/c", {}, {"/c": (0o666, 7)})[0]
        self.assertEqual(r["rationale"], "CIS: the sshd_config must be owned by root and not readable/writable by "
                                         "others: owned by uid 7 (want root); mode 0666 (want 0600 or stricter)")
        self.assertEqual(r["value"], "0666 uid=7")

    def test_default_host_keys_are_the_three_etc_ssh_ones(self):
        paths = ["/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"]
        r = self.run_files(None, {}, {p: (0o600, 0) for p in paths})
        self.assertEqual([x["key"] for x in r], ["perms:" + p for p in paths])
        self.assertTrue(all(x["severity"] == "MEDIUM" or x["pass"] for x in r))
        self.assertEqual(r[0]["rationale"], "CIS: the host private key must be owned by root and not "
                                            "readable/writable by others.")

    def test_host_key_perm_loose_severity_is_medium(self):
        r = self.run_files(None, {"_all": [("hostkey", "/k")]}, {"/k": (0o640, 0)})[0]
        self.assertEqual((r["severity"], r["pass"]), ("MEDIUM", False))

    def test_missing_host_key_does_not_stop_the_next_ones(self):
        cfg = {"_all": [("hostkey", "/missing"), ("hostkey", "/k")]}
        r = self.run_files(None, cfg, {"/k": (0o600, 0)})
        self.assertEqual([x["key"] for x in r], ["perms:/k"])

    def test_dsa_host_key_result_exact(self):
        cfg = {"_all": [("hostkey", "/k")]}
        r = self.run_files(None, cfg, {"/k": (0o600, 0)}, {"/k.pub": "ssh-dss AAAA host\n"})
        self.assertEqual(r[1], {"key": "hostkey:/k", "severity": "HIGH", "value": "ssh-dss",
                                "expected": "ed25519 / RSA >= 3072", "pass": False,
                                "rationale": "DSA host keys are 1024-bit and SHA-1 only."})
        self.assertEqual(len(r), 2)

    def test_unreadable_pub_does_not_stop_the_next_key(self):
        cfg = {"_all": [("hostkey", "/a"), ("hostkey", "/b")]}
        r = self.run_files(None, cfg, {"/a": (0o600, 0), "/b": (0o600, 0)}, {"/b.pub": pub_rsa(1024)})
        self.assertEqual([x["key"] for x in r], ["perms:/a", "perms:/b", "hostkey:/b"])

    def test_garbled_rsa_pub_does_not_stop_the_next_key(self):
        cfg = {"_all": [("hostkey", "/a"), ("hostkey", "/b")]}
        pubs = {"/a.pub": "ssh-rsa AAAA host\n", "/b.pub": pub_rsa(1024)}
        r = self.run_files(None, cfg, {"/a": (0o600, 0), "/b": (0o600, 0)}, pubs)
        self.assertEqual([x["key"] for x in r], ["perms:/a", "perms:/b", "hostkey:/b"])

    def test_rsa_sizes_severity_pass_and_text(self):
        want = {1024: ("HIGH", False), 2047: ("HIGH", False), 2048: ("LOW", False), 3071: ("LOW", False),
                3072: ("LOW", True), 4096: ("LOW", True)}
        for bits, (sev, ok) in want.items():
            r = self.run_files(None, {"_all": [("hostkey", "/k")]}, {"/k": (0o600, 0)}, {"/k.pub": pub_rsa(bits)})
            self.assertEqual(r[1], {
                "key": "hostkey:/k", "severity": sev, "value": "RSA %d" % bits,
                "expected": "RSA >= 3072 (or ed25519)", "pass": ok,
                "rationale": "RSA host keys under 2048 bits are breakable; NIST SP 800-57 asks for 3072 bits for use "
                             "past 2030."}, bits)
