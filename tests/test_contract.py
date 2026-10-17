"""--remote's wire contract, pinned (found as mutation-testing survivors): what the tool sends, how it
reads an SSH identification string and KEXINIT however the server's bytes are split, every way a
server can break that exchange (each must be exit 2 with a one-line error, never a traceback), how
client->server and server->client lists are merged, the Terrapin and compression verdicts, and the
text/HTML reports. A scripted fake server stands in for sshd so each byte sequence is exact.
"""
import html
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "sshd_audit.py")
sys.path.insert(0, os.path.dirname(TOOL))
import sshd_audit  # noqa: E402

GOOD_KEX = ["mlkem768x25519-sha256", "curve25519-sha256"]


def namelist(items):
    b = ",".join(items).encode()
    return struct.pack(">I", len(b)) + b


def kexinit(kex=GOOD_KEX, hostkeys=("ssh-ed25519",), c2s=("aes256-gcm@openssh.com",), s2c=None,
            mac_c2s=("hmac-sha2-512-etm@openssh.com",), mac_s2c=None, comp=("none",), msg_type=20, cut=None):
    payload = (bytes([msg_type]) + b"\x11" * 16 + namelist(kex) + namelist(hostkeys) + namelist(c2s)
               + namelist(s2c if s2c is not None else c2s) + namelist(mac_c2s)
               + namelist(mac_s2c if mac_s2c is not None else mac_c2s) + namelist(comp) + namelist(comp)
               + namelist([]) + namelist([]) + b"\x00" + b"\x00" * 4)
    if cut:
        payload = payload[:cut]
    pad = 8 - (len(payload) + 5) % 8 + 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


class FakeSSH:
    """Sends `chunks` (bytes, or a float = pause) to the first client, records what it sends, hangs up."""

    def __init__(self, chunks):
        self.chunks, self.received = chunks, b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.done = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        conn.settimeout(3)
        try:
            for c in self.chunks:
                if isinstance(c, float):
                    time.sleep(c)
                else:
                    conn.sendall(c)
            conn.shutdown(socket.SHUT_WR)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                self.received += data
        except OSError:
            pass
        finally:
            conn.close()
            self.done.set()

    def close(self):
        self.sock.close()


def run(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True, timeout=60)


class Base(unittest.TestCase):
    def serve(self, *chunks):
        srv = FakeSSH(list(chunks))
        self.addCleanup(srv.close)
        return srv


class TestKexinitReader(Base):
    def test_identification_string_sent(self):
        srv = self.serve(b"SSH-2.0-Fake_1\r\n", kexinit())
        sshd_audit.ssh_kexinit("127.0.0.1", srv.port, 5)
        srv.done.wait(5)
        self.assertEqual(srv.received, ("SSH-2.0-sshd_hardening_auditor_%s\r\n" % sshd_audit.__version__).encode())

    def test_fragmented_exchange_with_pre_banner_lines(self):
        pkt = kexinit(kex=["curve25519-sha256", "ext-info-s"], hostkeys=["ssh-ed25519", "rsa-sha2-512"],
                      c2s=["aes128-ctr", "aes256-cbc"], s2c=["aes256-gcm@openssh.com", "aes128-ctr"],
                      mac_c2s=["hmac-sha2-256-etm@openssh.com"], mac_s2c=["umac-128-etm@openssh.com"],
                      comp=["none", "zlib@openssh.com"])
        srv = self.serve(b"Welcome to the box\r\nplease be nice\r\nSSH-2.0-Fra", 0.05, b"g_9\r\n" + pkt[:3], 0.05,
                         pkt[3:40], 0.05, pkt[40:])
        k = sshd_audit.ssh_kexinit("127.0.0.1", srv.port, 5)
        self.assertEqual(k, {"banner": "SSH-2.0-Frag_9", "kexalgorithms": ["curve25519-sha256", "ext-info-s"],
                             "hostkeyalgorithms": ["ssh-ed25519", "rsa-sha2-512"],
                             "ciphers_c2s": ["aes128-ctr", "aes256-cbc"],
                             "ciphers": ["aes256-gcm@openssh.com", "aes128-ctr"],
                             "macs_c2s": ["hmac-sha2-256-etm@openssh.com"], "macs": ["umac-128-etm@openssh.com"],
                             "compression_c2s": ["none", "zlib@openssh.com"],
                             "compression": ["none", "zlib@openssh.com"], "languages_c2s": [], "languages": []})

    def test_broken_servers_are_exit_2_with_one_line_errors(self):
        good = kexinit()
        cases = [
            ([b"SSH-2.0-Half"], "connection closed before the SSH identification string"),
            ([b"x" * 70000], "no SSH identification string"),
            ([b"SSH-2.0-X\r\n"], "connection closed before KEXINIT"),
            ([b"SSH-2.0-X\r\n", struct.pack(">IB", 300 * 1024, 4)], "implausible packet length 307200"),
            ([b"SSH-2.0-X\r\n", good[:30]], "connection closed during KEXINIT"),
            ([b"SSH-2.0-X\r\n", kexinit(msg_type=21)], "first packet is not KEXINIT (type 21)"),
            ([b"SSH-2.0-X\r\n", struct.pack(">IB", 5, 4) + b"\x00" * 5], "first packet is not KEXINIT (type none)"),
            ([b"SSH-2.0-X\r\n", kexinit(cut=40)], "malformed KEXINIT"),       # name-lists cut short
            ([b"SSH-2.0-X\r\n", kexinit(cut=19)], "malformed KEXINIT"),       # inside a length field
        ]
        for chunks, want in cases:
            with self.subTest(want=want):
                srv = self.serve(*chunks)
                p = run("--remote", "127.0.0.1:%d" % srv.port, "--timeout", "5")
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertEqual(p.stderr.strip(), "sshd-hardening-auditor: ERROR -- " + want)
                self.assertEqual(p.stdout, "")


class TestRemoteVerdicts(Base):
    def remote(self, pkt, *extra):
        srv = self.serve(b"SSH-2.0-Fake_2\r\n", pkt)
        p = run("--remote", "127.0.0.1:%d" % srv.port, "--json", *extra)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return p.returncode, {r["key"]: r for r in json.loads(p.stdout)}

    def test_lists_from_both_directions_are_judged(self):
        code, res = self.remote(kexinit(c2s=["aes256-gcm@openssh.com", "aes128-ctr"],
                                         s2c=["aes256-gcm@openssh.com", "3des-cbc"],
                                         mac_c2s=["hmac-sha2-512-etm@openssh.com"], mac_s2c=["hmac-sha1"]))
        self.assertEqual(res["ciphers"]["value"], "aes256-gcm@openssh.com,3des-cbc,aes128-ctr")
        self.assertEqual(res["macs"]["value"], "hmac-sha1,hmac-sha2-512-etm@openssh.com")
        self.assertFalse(res["ciphers"]["pass"])
        self.assertEqual(code, 1)

    def test_terrapin_cbc_with_etm(self):
        code, res = self.remote(kexinit(c2s=["aes256-ctr", "aes128-cbc"],
                                         mac_c2s=["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512"]))
        t = res["terrapin"]
        self.assertEqual((t["severity"], t["pass"], t["value"]), ("MEDIUM", False, "hmac-sha2-256-etm@openssh.com"))
        self.assertEqual(t["expected"], "kex-strict-s-v00@openssh.com, or no chacha20-poly1305 / CBC+EtM")
        self.assertEqual(t["rationale"], "Terrapin (CVE-2023-48795): without strict key exchange, an attacker in the "
                                         "middle can strip messages at the start of the session when "
                                         "hmac-sha2-256-etm@openssh.com is used. Update OpenSSH (9.6+) or remove them.")
        code, res = self.remote(kexinit(c2s=["aes256-ctr"], mac_c2s=["hmac-sha2-256-etm@openssh.com"]))
        t = res["terrapin"]
        self.assertEqual((t["pass"], t["value"]), (True, "-"))
        self.assertIn("when chacha20-poly1305 or CBC+EtM is used", t["rationale"])
        code, res = self.remote(kexinit(kex=GOOD_KEX + ["kex-strict-s-v00@openssh.com"],
                                         c2s=["chacha20-poly1305@openssh.com", "aes128-cbc"],
                                         mac_c2s=["hmac-sha2-256-etm@openssh.com"]))
        self.assertEqual((res["terrapin"]["pass"], res["terrapin"]["value"]), (True, "strict kex"))
        self.assertEqual(res["kexalgorithms"]["value"], ",".join(GOOD_KEX))  # pseudo-algorithms dropped
        code, res = self.remote(kexinit(kex=GOOD_KEX + ["kex-strict-c-v00@openssh.com"],
                                         c2s=["chacha20-poly1305@openssh.com"]))
        self.assertFalse(res["terrapin"]["pass"])  # only the server-side marker means strict kex

    def test_compression(self):
        code, res = self.remote(kexinit(comp=["none", "zlib@openssh.com"]))
        c = res["compression"]
        self.assertEqual((c["severity"], c["pass"], c["value"]), ("LOW", True, "none,zlib@openssh.com"))
        self.assertEqual(c["expected"], "none or zlib@openssh.com (after authentication)")
        code, res = self.remote(kexinit(comp=["none", "zlib"]))
        self.assertEqual((res["compression"]["pass"], res["compression"]["value"]), (False, "none,zlib"))
        self.assertEqual(code, 0)  # LOW
        srv = self.serve(b"SSH-2.0-Fake_2\r\n", kexinit(comp=["none", "zlib"]))
        self.assertEqual(run("--remote", "127.0.0.1:%d" % srv.port, "--fail-on", "low").returncode, 1)

    def test_text_report_names_the_server(self):
        srv = self.serve(b"SSH-2.0-Fake_3 extra words\r\n", kexinit())
        p = run("--remote", "127.0.0.1:%d" % srv.port)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.startswith("Server: SSH-2.0-Fake_3 extra words  (127.0.0.1:%d)\n\n"
                                            "SSH Hardening Audit Report\n" % srv.port), p.stdout)


class TestParseRemote(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(sshd_audit.parse_remote("[::1]:2222"), ("::1", 2222))
        self.assertEqual(sshd_audit.parse_remote("[2001:db8::5]"), ("2001:db8::5", 22))
        self.assertEqual(sshd_audit.parse_remote("2001:db8::5"), ("2001:db8::5", 22))
        self.assertEqual(sshd_audit.parse_remote(" host.test:2200 "), ("host.test", 2200))
        self.assertEqual(sshd_audit.parse_remote("host.test"), ("host.test", 22))
        p = run("--remote", "host.test:notaport")
        self.assertEqual(p.returncode, 2)
        self.assertIn("ERROR -- invalid literal for int()", p.stderr)


RESULTS = [
    {"key": "permitrootlogin", "severity": "HIGH", "value": "yes", "expected": "no", "pass": False,
     "rationale": "Root can log in."},
    {"key": "x11forwarding", "severity": "LOW", "value": "yes", "expected": "no", "pass": False,
     "rationale": "X11 <forwarding> & friends."},
    {"key": "macs", "severity": "MEDIUM", "value": "hmac-sha1", "expected": "etm", "pass": False,
     "rationale": "SHA-1 MAC."},
    {"key": "maxauthtries", "severity": "MEDIUM", "value": "3", "expected": "<= 4", "pass": True, "rationale": "ok"},
]


class TestReports(unittest.TestCase):
    def test_text(self):
        self.assertEqual(sshd_audit.render_text(RESULTS), "\n".join([
            "SSH Hardening Audit Report", "=" * 40, "",
            "[HIGH] permitrootlogin = yes  (expected: no)", "    Root can log in.", "",
            "[MEDIUM] macs = hmac-sha1  (expected: etm)", "    SHA-1 MAC.", "",
            "[LOW] x11forwarding = yes  (expected: no)", "    X11 <forwarding> & friends.", "",
            "Summary: 3 finding(s), 1 check(s) passed, 4 total."]))
        self.assertEqual(sshd_audit.render_text([RESULTS[3]]), "\n".join([
            "SSH Hardening Audit Report", "=" * 40, "",
            "\u2705 No findings \u2014 configuration matches all checked hardening rules.",
            "Summary: 0 finding(s), 1 check(s) passed, 1 total."]))

    def test_html(self):
        doc = sshd_audit.render_html(RESULTS)
        rows = doc.split("<tr>")[2:]
        self.assertEqual([r.split("</td>")[0][4:] for r in rows], ["permitrootlogin", "macs", "x11forwarding",
                                                                     "maxauthtries"])
        self.assertIn('<td style="color:#ef4444;font-weight:600">FAIL (HIGH)</td>', rows[0])
        self.assertIn('<td style="color:#f59e0b;font-weight:600">FAIL (MEDIUM)</td>', rows[1])
        self.assertIn('<td style="color:#6b7280;font-weight:600">FAIL (LOW)</td>', rows[2])
        self.assertIn('<td style="color:#22c55e;font-weight:600">PASS</td>', rows[3])
        self.assertIn("<td>%s</td>" % html.escape("X11 <forwarding> & friends."), rows[2])
        self.assertIn("<td>&lt;= 4</td>", rows[3])
        self.assertTrue(doc.startswith('<!doctype html><html><head><meta charset="utf-8">\n'
                                       "<title>SSH Hardening Audit Report</title>"))
        self.assertIn("<tr><th>Directive</th><th>Value</th><th>Expected</th><th>Status</th><th>Rationale</th></tr>",
                      doc)


if __name__ == "__main__":
    unittest.main()
