"""Shared CLI contract tests: exit codes, --json schema, --quiet, errors on stderr (all offline)."""
import json
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
from contract_support import load_schema, run_cli, validate  # noqa: E402
import sshd_audit  # noqa: E402

TOOL = os.path.join(ROOT, "sshd_audit.py")
CLEAN = (
    "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nX11Forwarding no\n"
    "MaxAuthTries 3\nClientAliveInterval 300\nLoginGraceTime 30\nPermitUserEnvironment no\n"
    "IgnoreRhosts yes\nHostbasedAuthentication no\nAllowTcpForwarding no\nUsePAM yes\n"
    "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,diffie-hellman-group16-sha512\n"
    "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
    "LogLevel VERBOSE\nMaxSessions 4\nMaxStartups 10:30:60\nBanner /etc/issue.net\nStrictModes yes\n"
    "GSSAPIAuthentication no\nKbdInteractiveAuthentication no\nAllowGroups ssh-users\nClientAliveCountMax 3\n"
)
BAD = "PermitRootLogin yes\n"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestCliContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.schema = load_schema(ROOT, "sshd-hardening-auditor")

    def cfg(self, text):
        path = os.path.join(self.tmp, "sshd_config")
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_exit_codes_clean_findings_usage_runtime(self):
        self.assertEqual(run_cli(TOOL, ["--no-file-checks", self.cfg(CLEAN)])[0], 0)
        self.assertEqual(run_cli(TOOL, ["--no-file-checks", self.cfg(BAD)])[0], 1)
        for args in (["--no-such-flag"], ["--profile", "l9"], ["--timeout"]):
            rc, out, err = run_cli(TOOL, args)
            self.assertEqual(rc, 2, args)
            self.assertEqual(out, "")
            self.assertTrue(err)
        rc, out, err = run_cli(TOOL, [os.path.join(self.tmp, "missing")])
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)
        # legacy: unreachable --remote server is 2 (closed localhost port)
        rc, out, err = run_cli(TOOL, ["--remote", "127.0.0.1:%d" % free_port(), "--timeout", "2", "--json"])
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)
        self.assertNotIn("Traceback", err)
        # unwritable --html path is an input error too
        rc, out, err = run_cli(TOOL, ["--no-file-checks", "--html", os.path.join(self.tmp, "no", "r.html"),
                                      self.cfg(CLEAN)])
        self.assertEqual((rc, out), (2, ""))

    def test_unexpected_exception_is_exit_3(self):
        with mock.patch.object(sshd_audit, "audit", side_effect=KeyError("boom")), \
                mock.patch.object(sys, "stderr", new_callable=__import__("io").StringIO) as err:
            rc = sshd_audit.main(["--no-file-checks", self.cfg(CLEAN)])
        self.assertEqual(rc, 3)
        self.assertIn("unexpected KeyError", err.getvalue())

    def test_json_validates_clean_and_findings(self):
        for text, code in ((CLEAN, 0), (BAD, 1)):
            rc, out, err = run_cli(TOOL, ["--json", "--no-file-checks", self.cfg(text)])
            self.assertEqual(rc, code, err)
            doc = json.loads(out)
            self.assertEqual(validate(doc, self.schema), [])
            self.assertEqual(doc["exit_code"], rc)
            self.assertEqual(doc["schema_version"], 1)
            self.assertEqual(doc["tool"], "sshd-hardening-auditor")
            self.assertEqual(doc["version"], sshd_audit.__version__)
            self.assertTrue(doc["results"])
        self.assertEqual(validate({"schema_version": 1}, self.schema)[0][:20], "$: missing required ")

    def test_json_is_one_document_and_errors_go_to_stderr(self):
        rc, out, err = run_cli(TOOL, ["--json", "--no-file-checks", "--fix", "-", self.cfg(BAD)])
        self.assertEqual(rc, 1)
        self.assertEqual(json.JSONDecoder().raw_decode(out)[1], len(out.rstrip("\n")))
        self.assertIn("PermitRootLogin", err)  # the --fix snippet went to stderr
        rc, out, err = run_cli(TOOL, ["--json", os.path.join(self.tmp, "missing")])
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)

    def test_quiet_prints_nothing_but_keeps_exit_code_and_files(self):
        for flag in ("--quiet", "-q"):
            for text, code in ((CLEAN, 0), (BAD, 1)):
                for extra in ([], ["--json"]):
                    rc, out, err = run_cli(TOOL, [flag, "--no-file-checks"] + extra + [self.cfg(text)])
                    self.assertEqual((rc, out, err), (code, "", ""))
        html = os.path.join(self.tmp, "r.html")
        fix = os.path.join(self.tmp, "fix.conf")
        rc, out, err = run_cli(TOOL, ["-q", "--no-file-checks", "--html", html, "--fix", fix, self.cfg(BAD)])
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("<table>", open(html).read())
        self.assertIn("PermitRootLogin", open(fix).read())
        rc, out, err = run_cli(TOOL, ["-q", "--no-file-checks", "--fix", "-", self.cfg(BAD)])
        self.assertEqual((rc, out), (1, ""))
        rc, out, err = run_cli(TOOL, ["-q", os.path.join(self.tmp, "missing")])
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)

    def test_text_output_still_printed_without_quiet(self):
        rc, out, err = run_cli(TOOL, ["--no-file-checks", self.cfg(BAD)])
        self.assertEqual(rc, 1)
        self.assertIn("SSH Hardening Audit Report", out)

    def test_fail_on_never_is_reflected_in_json_exit_code(self):
        rc, out, err = run_cli(TOOL, ["--json", "--fail-on", "never", "--no-file-checks", self.cfg(BAD)])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
