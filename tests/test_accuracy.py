"""Detection accuracy against OpenSSH itself.

200 seeded random sshd_config files (every audited directive with valid values, time and
size formats, keyword case variants, `Keyword=value`, repeated keywords, a trailing Match
block, an Include drop-in) are audited twice: as written (the tool parses the file) and as
OpenSSH's own `sshd -T` prints the effective configuration. Every config rule must get the
same verdict both ways -- a disagreement means the tool reads a config differently from the
daemon that enforces it (a false positive or a false negative on a real server).

Plus two reference configs: Mozilla's "Modern" OpenSSH guideline (must pass every HIGH and
MEDIUM rule) and Debian's stock sshd_config (its known weak defaults must be reported).
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "sshd_audit.py")
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
RULE_KEYS = {"PermitRootLogin", "PasswordAuthentication", "PermitEmptyPasswords", "X11Forwarding", "MaxAuthTries",
             "ClientAliveInterval", "LoginGraceTime", "PermitUserEnvironment", "IgnoreRhosts",
             "HostbasedAuthentication", "AllowTcpForwarding", "UsePAM", "LogLevel", "MaxSessions", "MaxStartups",
             "Banner", "StrictModes", "GSSAPIAuthentication", "KbdInteractiveAuthentication",
             "AllowUsers/AllowGroups", "ClientAliveCountMax"}
YESNO = ["yes", "no"]
VALUES = {
    "PermitRootLogin": ["yes", "no", "prohibit-password", "without-password", "forced-commands-only"],
    "PasswordAuthentication": YESNO, "PermitEmptyPasswords": YESNO, "X11Forwarding": YESNO,
    "MaxAuthTries": ["1", "3", "4", "5", "6", "10"],
    "ClientAliveInterval": ["0", "15", "300", "5m", "1h"],
    "LoginGraceTime": ["0", "20", "30", "60", "61", "1m", "2m", "90s", "1m30s"],
    "PermitUserEnvironment": YESNO, "IgnoreRhosts": YESNO, "HostbasedAuthentication": YESNO,
    "AllowTcpForwarding": ["yes", "no", "local", "remote", "all"],
    "UsePAM": YESNO, "LogLevel": ["QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG3"],
    "MaxSessions": ["0", "1", "4", "10", "11", "64"],
    "MaxStartups": ["10", "10:30:60", "10:30:100", "5:50:20", "20:30:60", "10:20:60"],
    "Banner": ["none", "/etc/issue.net"], "StrictModes": YESNO, "GSSAPIAuthentication": YESNO,
    "KbdInteractiveAuthentication": YESNO, "ChallengeResponseAuthentication": YESNO,
    "AllowGroups": ["ssh-users", "wheel admins"], "AllowUsers": ["alice", "bob@10.0.0.0/8"],
    "DenyUsers": ["root"], "ClientAliveCountMax": ["0", "1", "3", "4", "10"],
}


def variant(rng, key):
    return rng.choice([key, key.lower(), key.upper()])


def random_config(rng, dropin):
    lines = []
    for key in rng.sample(sorted(VALUES), rng.randint(3, len(VALUES))):
        sep = rng.choice([" ", "=", " = ", "\t"])
        lines.append("%s%s%s" % (variant(rng, key), sep, rng.choice(VALUES[key])))
        # a repeated keyword: sshd keeps the first value (MaxStartups only since OpenSSH 10.1: older
        # releases such as Debian 12's 9.2 keep the last one, so it isn't repeated here)
        if rng.random() < 0.2 and key != "MaxStartups":
            lines.append("%s %s" % (key, rng.choice(VALUES[key])))
        if rng.random() < 0.1:
            lines.append("# %s %s" % (key, rng.choice(VALUES[key])))
    rng.shuffle(lines)
    if rng.random() < 0.3:
        lines.insert(rng.randint(0, len(lines)), "Include %s" % dropin)
    if rng.random() < 0.4:  # Match settings never change the global (default connection) verdict
        key = rng.choice(["PasswordAuthentication", "X11Forwarding", "PermitRootLogin", "AllowTcpForwarding"])
        lines += ["Match User build", "    %s %s" % (key, rng.choice(VALUES[key]))]
    return "\n".join(lines) + "\n"


def verdicts(path):
    p = subprocess.run([sys.executable, TOOL, "--json", "--no-file-checks", path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True)
    assert p.returncode in (0, 1), p.stderr
    return {r["key"]: r["pass"] for r in json.loads(p.stdout) if r["key"] in RULE_KEYS}


class TestAgainstSshdT(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(SSHD), "OpenSSH server (sshd) must be installed")
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_random_configs_match_sshd(self):
        rng = random.Random(4253)
        dropin = self.write("dropin.conf", "X11Forwarding yes\nMaxAuthTries 2\nLoginGraceTime 45\n")
        checked = 0
        for n in range(200):
            text = random_config(rng, dropin)
            path = self.write("case.conf", text)
            t = subprocess.run([SSHD, "-T", "-f", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True)
            if t.returncode != 0:  # a value this OpenSSH rejects: sshd wouldn't start, nothing to compare
                self.assertTrue(t.stderr, text)
                continue
            checked += 1
            live = verdicts(self.write("T.out", t.stdout))
            ours = verdicts(path)
            with self.subTest(n=n):
                self.assertEqual(set(ours), RULE_KEYS)
                diff = {k: (ours[k], live[k]) for k in RULE_KEYS if ours[k] != live[k]}
                self.assertEqual(diff, {}, "file-mode vs sshd -T verdicts (ours, sshd) for:\n" + text)
        self.assertGreater(checked, 150)

    def test_mozilla_modern_guideline_passes_high_and_medium(self):
        # https://infosec.mozilla.org/guidelines/openssh (Modern, OpenSSH 6.7+)
        path = self.write("mozilla.conf", (
            "HostKey /etc/ssh/ssh_host_ed25519_key\nHostKey /etc/ssh/ssh_host_rsa_key\n"
            "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
            "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,"
            "diffie-hellman-group-exchange-sha256\n"
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,"
            "aes192-ctr,aes128-ctr\n"
            "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,"
            "hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\n"
            "AuthenticationMethods publickey\nLogLevel VERBOSE\nPermitRootLogin No\nPasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\nMaxAuthTries 3\nUsePrivilegeSeparation sandbox\n"))
        p = subprocess.run([sys.executable, TOOL, "--json", "--no-file-checks", path], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True)
        bad = [(r["key"], r["severity"]) for r in json.loads(p.stdout)
               if not r["pass"] and r["severity"] in ("HIGH", "MEDIUM")]
        self.assertEqual(bad, [])
        self.assertEqual(p.returncode, 0)

    def test_debian_stock_config_reports_its_weak_defaults(self):
        # the active lines of Debian bookworm's /etc/ssh/sshd_config
        path = self.write("debian.conf", (
            "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n"
            "X11Forwarding yes\nPrintMotd no\nAcceptEnv LANG LC_*\nSubsystem\tsftp\t/usr/lib/openssh/sftp-server\n"))
        p = subprocess.run([sys.executable, TOOL, "--json", "--no-file-checks", path], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True)
        failing = {r["key"] for r in json.loads(p.stdout) if not r["pass"]}
        for key in ("PasswordAuthentication", "X11Forwarding", "MaxAuthTries"):
            self.assertIn(key, failing)
        for key in ("PermitRootLogin", "PermitEmptyPasswords", "KbdInteractiveAuthentication", "UsePAM"):
            self.assertNotIn(key, failing)
        self.assertEqual(p.returncode, 1)  # PasswordAuthentication defaults to yes: HIGH


if __name__ == "__main__":
    unittest.main()
