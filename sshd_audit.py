#!/usr/bin/env python3
"""
sshd-audit — SSH server hardening auditor
==========================================

Audits an sshd_config, a server's effective config via `sshd -T`, or what a
live SSH server actually offers on the wire (--remote host[:port]) against CIS
Benchmark / NIST-aligned SSH hardening recommendations: auth settings, the key
exchange / host key / cipher / MAC algorithms (SHA-1, CBC, 64-bit MACs,
encrypt-and-MAC, NIST curves, no post-quantum KEX, Terrapin CVE-2023-48795),
host key sizes and file permissions.
No third-party dependencies — stdlib only, works anywhere Python 3.8+ runs.

Usage:
    sshd-hardening-auditor [path/to/sshd_config]
    sshd-hardening-auditor --live              # runs `sshd -T` locally (needs sudo)
    sshd-hardening-auditor --remote host[:port] # reads the server's KEXINIT, no login
    sshd-hardening-auditor --json              # machine-readable output
    sshd-hardening-auditor --html report.html

Exit code: 0 if no finding at or above --fail-on (default: high), 1 otherwise
(CI-friendly), 2 if the config can't be read, `sshd -T` can't run or the
remote server can't be reached.

Parsing follows sshd's own rules: `Include` files are expanded in place,
the FIRST value of a directive wins, and settings inside `Match` blocks
don't override the global ones.

Copyright (c) 2026 Errant Solutions. MIT licensed (see LICENSE).
"""
__version__ = "1.2.1"

import argparse
import glob
import html
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import base64
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Rule:
    key: str
    expected: str          # expected value, or a predicate description
    severity: str           # HIGH, MEDIUM, LOW
    rationale: str
    check: callable = None  # optional custom check(value) -> bool


def _bool_true(v):
    return v is not None and v.strip().lower() in ("yes", "true", "1")


def _bool_false(v):
    return v is not None and v.strip().lower() in ("no", "false", "0")


def _int_at_most(n):
    def f(v):
        try:
            return v is not None and int(v.strip()) <= n
        except ValueError:
            return False
    return f


def _seconds(v):
    """sshd's time format (sshd_config(5) TIME FORMATS, misc.c convtime): '90', '90s', '1m30s',
    '2h', '1w'; a trailing bare number counts as seconds ('1m30' = 90, as sshd -T shows);
    None when it isn't one."""
    v = (v or "").strip().lower()
    if not v:
        return None
    if v.isdigit():
        return int(v)
    total, num = 0, ""
    for ch in v:
        if ch.isdigit():
            num += ch
        elif ch in "smhdw" and num:
            total += int(num) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[ch]
            num = ""
        else:
            return None
    return total + int(num) if num else total


def _between(lo, hi, parse=int):
    """lo <= value <= hi (0 means 'no limit' / 'disabled' for the directives this is used on)."""
    def f(v):
        try:
            n = parse(v.strip()) if v is not None else None
        except ValueError:
            return False
        return n is not None and lo <= n <= hi
    return f


def _int_at_least(n):
    def f(v):
        try:
            return v is not None and int(v.strip()) >= n
        except ValueError:
            return False
    return f


# Algorithm policy: name -> (severity, reason). Anything not listed is fine.
_SHA1_KEX = "SHA-1 based key exchange"
ALGORITHM_POLICY = {
    "kexalgorithms": {
        "diffie-hellman-group1-sha1": ("HIGH", "1024-bit DH group with SHA-1"),
        "diffie-hellman-group14-sha1": ("HIGH", _SHA1_KEX),
        "diffie-hellman-group-exchange-sha1": ("HIGH", _SHA1_KEX),
        "gss-group1-sha1-": ("HIGH", "GSSAPI 1024-bit DH with SHA-1"),
        "gss-group14-sha1-": ("HIGH", _SHA1_KEX),
        "gss-gex-sha1-": ("HIGH", _SHA1_KEX),
        "ecdh-sha2-nistp256": ("LOW", "NIST P-curve (prefer curve25519/sntrup761/mlkem768)"),
        "ecdh-sha2-nistp384": ("LOW", "NIST P-curve (prefer curve25519/sntrup761/mlkem768)"),
        "ecdh-sha2-nistp521": ("LOW", "NIST P-curve (prefer curve25519/sntrup761/mlkem768)"),
    },
    "hostkeyalgorithms": {
        "ssh-dss": ("HIGH", "DSA host keys are 1024-bit and SHA-1 signed"),
        "ssh-dss-cert-v01@openssh.com": ("HIGH", "DSA host certificates"),
        "ssh-rsa": ("MEDIUM", "RSA signatures with SHA-1 (use rsa-sha2-256/512)"),
        "ssh-rsa-cert-v01@openssh.com": ("MEDIUM", "RSA certificates signed with SHA-1"),
        "ecdsa-sha2-nistp256": ("LOW", "NIST P-curve host key (prefer ssh-ed25519)"),
        "ecdsa-sha2-nistp384": ("LOW", "NIST P-curve host key (prefer ssh-ed25519)"),
        "ecdsa-sha2-nistp521": ("LOW", "NIST P-curve host key (prefer ssh-ed25519)"),
    },
    "ciphers": dict({c: ("HIGH", "CBC mode / broken legacy cipher") for c in (
        "arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc",
        "cast128-cbc", "3des-cbc", "des-cbc", "rijndael-cbc@lysator.liu.se", "none")}),
    "macs": {
        "hmac-md5": ("HIGH", "MD5"), "hmac-md5-96": ("HIGH", "MD5, truncated"),
        "hmac-md5-etm@openssh.com": ("HIGH", "MD5"), "hmac-md5-96-etm@openssh.com": ("HIGH", "MD5, truncated"),
        "hmac-sha1-96": ("HIGH", "SHA-1, truncated to 96 bits"),
        "hmac-sha1-96-etm@openssh.com": ("HIGH", "SHA-1, truncated to 96 bits"),
        "hmac-sha1": ("MEDIUM", "SHA-1, encrypt-and-MAC"), "hmac-sha1-etm@openssh.com": ("MEDIUM", "SHA-1"),
        "umac-64@openssh.com": ("MEDIUM", "64-bit tag, encrypt-and-MAC"), "umac-64-etm@openssh.com": ("MEDIUM", "64-bit tag"),
        "hmac-ripemd160": ("MEDIUM", "RIPEMD-160"), "hmac-ripemd160@openssh.com": ("MEDIUM", "RIPEMD-160"),
        "hmac-sha2-256": ("LOW", "encrypt-and-MAC (prefer the -etm@openssh.com variant)"),
        "hmac-sha2-512": ("LOW", "encrypt-and-MAC (prefer the -etm@openssh.com variant)"),
        "umac-128@openssh.com": ("LOW", "encrypt-and-MAC (prefer the -etm@openssh.com variant)"),
    },
}
# kept for callers of 1.1: the HIGH sets
WEAK_KEX = {k for k, v in ALGORITHM_POLICY["kexalgorithms"].items() if v[0] == "HIGH"}
WEAK_CIPHERS = set(ALGORITHM_POLICY["ciphers"])
WEAK_MACS = {k for k, v in ALGORITHM_POLICY["macs"].items() if v[0] == "HIGH"}
PQ_KEX = ("sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512", "mlkem768x25519-sha256")
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _alg_policy(directive, alg):
    pol = ALGORITHM_POLICY[directive]
    if alg in pol:
        return pol[alg]
    for prefix, v in pol.items():  # GSSAPI KEX names carry a mechanism suffix
        if prefix.endswith("-") and alg.startswith(prefix):
            return v
    return None


RULES = [
    Rule("PermitRootLogin", "no", "HIGH",
         "Root login over SSH bypasses per-user accountability and audit trails; use sudo/su after a normal-user login instead.",
         check=lambda v: v is not None and v.strip().lower() in ("no", "prohibit-password", "without-password", "forced-commands-only")),
    Rule("PasswordAuthentication", "no", "HIGH",
         "Password auth is brute-forceable; key-based (or hardware-token) auth should be the only path in.",
         check=_bool_false),
    Rule("PermitEmptyPasswords", "no", "HIGH",
         "Empty passwords are a trivial full compromise if PasswordAuthentication is ever re-enabled.",
         check=_bool_false),
    Rule("Protocol", "2", "HIGH",
         "SSH protocol 1 has known cryptographic breaks; only protocol 2 should be permitted.",
         check=lambda v: v is None or v.strip() == "2"),
    Rule("X11Forwarding", "no", "MEDIUM",
         "X11 forwarding expands the attack surface and is rarely needed on servers.",
         check=_bool_false),
    Rule("MaxAuthTries", "<=4", "MEDIUM",
         "Lower auth-attempt ceilings slow down credential-guessing.",
         check=_int_at_most(4)),
    Rule("ClientAliveInterval", ">0", "LOW",
         "Idle sessions should eventually be reaped to limit exposure of unattended terminals.",
         check=lambda v: (_seconds(v) or 0) > 0),
    Rule("LoginGraceTime", "1-60 seconds", "LOW",
         "A short grace time limits how long a half-open connection can be held (0 means no limit at all).",
         check=_between(1, 60, _seconds)),
    Rule("PermitUserEnvironment", "no", "MEDIUM",
         "User-controlled environment variables can be used to bypass restrictions in some configurations.",
         check=_bool_false),
    Rule("IgnoreRhosts", "yes", "MEDIUM",
         "Rhosts-based trust is legacy and easily spoofed; it should always be ignored.",
         check=_bool_true),
    Rule("HostbasedAuthentication", "no", "HIGH",
         "Host-based auth trusts the source machine's identity rather than a credential — avoid it.",
         check=_bool_false),
    Rule("AllowTcpForwarding", "no", "LOW",
         "Arbitrary TCP forwarding can be used to pivot through the server into internal networks; disable unless required.",
         check=_bool_false),
    Rule("UsePAM", "yes", "LOW",
         "PAM integration centralizes auth policy (lockouts, MFA modules) — usually desirable.",
         check=_bool_true),
    Rule("LogLevel", "INFO or VERBOSE", "LOW",
         "CIS: INFO or VERBOSE logging records logins (VERBOSE also records the key fingerprint used).",
         check=lambda v: v is not None and v.strip().upper() in ("INFO", "VERBOSE")),
    Rule("MaxSessions", "<=10", "LOW",
         "CIS: limit concurrent sessions per connection.", check=_int_at_most(10)),
    Rule("MaxStartups", "10:30:60 or stricter", "LOW",
         "CIS: throttling unauthenticated connections limits pre-auth DoS and brute forcing.",
         check=lambda v: _maxstartups_ok(v)),
    Rule("Banner", "a warning banner file", "LOW",
         "CIS: a legal/warning banner before authentication.",
         check=lambda v: v is not None and v.strip().lower() not in ("none", "")),
    Rule("StrictModes", "yes", "MEDIUM",
         "sshd should refuse logins when the user's files (~/.ssh, authorized_keys) are writable by others.",
         check=_bool_true),
    Rule("GSSAPIAuthentication", "no", "LOW",
         "CIS: disable GSSAPI (Kerberos) authentication unless it's used.", check=_bool_false),
    Rule("KbdInteractiveAuthentication", "no", "MEDIUM",
         "Keyboard-interactive auth is a second password path (through PAM) even with PasswordAuthentication no.",
         check=_bool_false),
    Rule("AllowUsers/AllowGroups", "an allow/deny list", "LOW",
         "CIS: restrict which accounts may log in over SSH (AllowUsers/AllowGroups/DenyUsers/DenyGroups).",
         check=lambda v: v is not None),
    Rule("ClientAliveCountMax", "1-3", "LOW",
         "CIS: unresponsive clients are dropped after ClientAliveInterval x ClientAliveCountMax "
         "(0 disables dropping them, OpenSSH 8.2+).",
         check=_between(1, 3)),
]


def _maxstartups_ok(v):
    if v is None:
        return False
    parts = v.strip().split(":")
    try:
        nums = [int(x) for x in parts]
    except ValueError:
        return False
    if len(nums) == 1:
        return nums[0] <= 10
    if len(nums) != 3:
        return False
    start, rate, full = nums
    return start <= 10 and rate >= 30 and full <= 60


DEFAULT_SSH_DIR = "/etc/ssh"


def _read_with_includes(path: str, depth: int = 0, base_dir: str = DEFAULT_SSH_DIR) -> list:
    """Return the config's lines with every `Include` directive expanded in place.

    sshd expands Include (glob patterns allowed; relative paths are taken as
    relative to /etc/ssh) before it applies "first value wins", so a drop-in
    such as /etc/ssh/sshd_config.d/50-cloud-init.conf that sets
    `PasswordAuthentication yes` overrides a later `PasswordAuthentication no`
    in the main file. Auditing the main file alone would miss exactly that.
    """
    if depth > 16:
        raise ValueError(f"Include nesting too deep at {path}")
    with open(path) as f:
        text = f.read()
    return _expand_includes(text, depth, base_dir)


def _expand_includes(text: str, depth: int = 0, base_dir: str = DEFAULT_SSH_DIR) -> list:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "include":
            for pattern in parts[1].split():
                if not os.path.isabs(pattern):
                    pattern = os.path.join(base_dir, pattern)
                for inc in sorted(glob.glob(pattern)):
                    out.extend(_read_with_includes(inc, depth + 1, base_dir))
            continue
        out.append(raw)
    return out


KEYWORD_ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}


def parse_sshd_config(text: str) -> dict:
    """Parse sshd_config text into {directive_lower: value} with sshd's own rules.

    sshd_config(5): "Unless noted otherwise, for each keyword, the first
    obtained value will be used." Directives after the first `Match` line
    only apply to connections matching that block, so they never override
    the global value and are not used for the global audit.
    """
    cfg = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        # sshd accepts "Keyword value", "Keyword=value" and "Keyword = value".
        m = re.match(r"([A-Za-z0-9]+)\s*(?:=\s*|\s+)(.*)$", line)
        key = (m.group(1) if m else line).lower()
        # deprecated spellings are the same option inside sshd, so the first of EITHER wins
        key = KEYWORD_ALIASES.get(key, key)
        if key == "match":
            break
        if not m or not m.group(2).strip():
            continue
        cfg.setdefault(key, m.group(2).strip())
        cfg.setdefault("_all", []).append((key, m.group(2).strip()))
    return cfg


def judge_algorithms(lists: dict, source: str = "config") -> list:
    """lists: {directive: [algorithm, ...]} -> one result per directive (worst severity wins)."""
    results = []
    labels = {"kexalgorithms": "key exchange", "hostkeyalgorithms": "host key", "ciphers": "cipher", "macs": "MAC"}
    for directive in ("kexalgorithms", "hostkeyalgorithms", "ciphers", "macs"):
        algs = lists.get(directive)
        if algs is None:
            continue
        bad = [(a,) + _alg_policy(directive, a) for a in algs if _alg_policy(directive, a)]
        sev = min((b[1] for b in bad), key=lambda x: SEVERITY_ORDER[x], default="HIGH")
        results.append({
            "key": directive,
            "severity": sev,
            "value": ",".join(algs),
            "expected": f"no weak {labels[directive]} algorithms",
            "pass": not bad,
            "rationale": ("Weak %s algorithm(s) %s: %s." % (labels[directive], "offered" if source == "remote" else "permitted",
                                                            "; ".join("%s (%s, %s)" % b for b in bad)))
                         if bad else f"Only modern {labels[directive]} algorithms.",
        })
    kex = lists.get("kexalgorithms")
    if kex is not None:
        pq = [a for a in kex if a in PQ_KEX]
        results.append({
            "key": "post-quantum-kex", "severity": "LOW", "value": ",".join(pq) or "(none)",
            "expected": "sntrup761x25519-sha512 or mlkem768x25519-sha256",
            "pass": bool(pq),
            "rationale": "A hybrid post-quantum key exchange protects recorded sessions against later quantum "
                         "decryption (\"harvest now, decrypt later\"); OpenSSH 9.0+ offers sntrup761, 9.9+ mlkem768.",
        })
    return results


def _algorithm_lists(cfg: dict) -> dict:
    """Explicitly configured (or sshd -T expanded) algorithm lists. A list using +/-/^ modifiers is relative
    to OpenSSH's compiled-in default: only the named algorithms are judged then."""
    out = {}
    for directive in ("kexalgorithms", "hostkeyalgorithms", "ciphers", "macs"):
        val = cfg.get(directive)
        if val:
            out[directive] = [a.strip() for a in val.lstrip("+-^").split(",") if a.strip()]
            if val.startswith("-"):
                out[directive] = []  # removing algorithms can only make the default list safer
    return out


def get_kex_ciphers_macs(cfg: dict):
    """Failing algorithm results only (1.1 behaviour, kept for importers)."""
    return [r for r in judge_algorithms(_algorithm_lists(cfg)) if not r["pass"] and r["key"] != "post-quantum-kex"]


# --------------------------------------------------------------------------- remote scan

def ssh_kexinit(host: str, port: int = 22, timeout: float = 10) -> dict:
    """Connect, exchange identification strings and read the server's SSH_MSG_KEXINIT
    (RFC 4253 7.1). No authentication is attempted; nothing past KEXINIT is sent."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(("SSH-2.0-sshd_hardening_auditor_%s\r\n" % __version__).encode())
        buf, banner = b"", None
        while banner is None:
            data = s.recv(4096)
            if not data:
                raise OSError("connection closed before the SSH identification string")
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.startswith(b"SSH-"):
                    banner = line.rstrip(b"\r").decode("utf-8", "replace")
                    break
            if banner is None and len(buf) > 65536:
                raise OSError("no SSH identification string")
        while len(buf) < 5:
            data = s.recv(4096)
            if not data:
                raise OSError("connection closed before KEXINIT")
            buf += data
        plen, pad = struct.unpack(">IB", buf[:5])
        if plen > 256 * 1024:
            raise OSError("implausible packet length %d" % plen)
        while len(buf) < 4 + plen:
            data = s.recv(65536)
            if not data:
                raise OSError("connection closed during KEXINIT")
            buf += data
    payload = buf[5:4 + plen - pad]
    if not payload or payload[0] != 20:
        raise OSError("first packet is not KEXINIT (type %s)" % (payload[0] if payload else "none"))
    names = ["kexalgorithms", "hostkeyalgorithms", "ciphers_c2s", "ciphers", "macs_c2s", "macs",
             "compression_c2s", "compression", "languages_c2s", "languages"]
    out, p = {"banner": banner}, 17
    for n in names:
        (ln,) = struct.unpack(">I", payload[p:p + 4])
        p += 4
        out[n] = [x for x in payload[p:p + ln].decode("ascii", "replace").split(",") if x]
        p += ln
    return out


def audit_remote(host: str, port: int, timeout: float = 10):
    k = ssh_kexinit(host, port, timeout)
    real_kex = [a for a in k["kexalgorithms"] if not a.startswith(("ext-info-", "kex-strict-"))]
    lists = {"kexalgorithms": real_kex, "hostkeyalgorithms": k["hostkeyalgorithms"],
             "ciphers": sorted(set(k["ciphers"]) | set(k["ciphers_c2s"]), key=(k["ciphers"] + k["ciphers_c2s"]).index),
             "macs": sorted(set(k["macs"]) | set(k["macs_c2s"]), key=(k["macs"] + k["macs_c2s"]).index)}
    results = judge_algorithms(lists, "remote")
    strict = "kex-strict-s-v00@openssh.com" in k["kexalgorithms"]
    affected = [c for c in lists["ciphers"] if c == "chacha20-poly1305@openssh.com"]
    if any(c.endswith("-cbc") for c in lists["ciphers"]):
        affected += [m for m in lists["macs"] if m.endswith("-etm@openssh.com")]
    results.append({
        "key": "terrapin", "severity": "MEDIUM", "value": "strict kex" if strict else ",".join(affected) or "-",
        "expected": "kex-strict-s-v00@openssh.com, or no chacha20-poly1305 / CBC+EtM",
        "pass": strict or not affected,
        "rationale": "Terrapin (CVE-2023-48795): without strict key exchange, an attacker in the middle can strip "
                     "messages at the start of the session when %s is used. Update OpenSSH (9.6+) or remove them."
                     % (", ".join(affected) or "chacha20-poly1305 or CBC+EtM"),
    })
    zlib = "zlib" in k["compression"]
    results.append({
        "key": "compression", "severity": "LOW", "value": ",".join(k["compression"]),
        "expected": "none or zlib@openssh.com (after authentication)", "pass": not zlib,
        "rationale": "Pre-authentication zlib compression exposes the decompressor to unauthenticated clients.",
    })
    return k["banner"], results


# --------------------------------------------------------------------------- host keys and file permissions

def _rsa_bits_from_pub(b64):
    blob = base64.b64decode(b64)
    fields, p = [], 0
    while p < len(blob) and len(fields) < 3:
        (n,) = struct.unpack(">I", blob[p:p + 4])
        fields.append(blob[p + 4:p + 4 + n])
        p += 4 + n
    return int.from_bytes(fields[2], "big").bit_length()


def audit_files(config_path, cfg: dict) -> list:
    """CIS 5.2.1-5.2.3: sshd_config and host key file ownership/permissions, plus host key types/sizes."""
    results = []

    def perm(path, max_mode, label, sev_loose="LOW"):
        try:
            st = os.stat(path)
        except OSError:
            return
        mode = stat.S_IMODE(st.st_mode)
        bad = []
        if st.st_uid != 0:
            bad.append("owned by uid %d (want root)" % st.st_uid)
        if mode & ~max_mode:
            bad.append("mode %04o (want %04o or stricter)" % (mode, max_mode))
        writable = mode & 0o022 or st.st_uid != 0
        sev = "MEDIUM" if writable else sev_loose
        results.append({"key": f"perms:{path}", "severity": sev, "value": "%04o uid=%d" % (mode, st.st_uid),
                        "expected": "root, %04o or stricter" % max_mode, "pass": not bad,
                        "rationale": f"CIS: the {label} must be owned by root and not readable/writable by others"
                                     + (": " + "; ".join(bad) if bad else ".")})

    if config_path:
        perm(config_path, 0o600, "sshd_config")
    keys = [v for k, v in cfg.get("_all", []) if k == "hostkey"] or [
        "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"]
    for key in keys:
        if not os.path.exists(key):
            continue
        perm(key, 0o600, "host private key", "MEDIUM")
        try:
            with open(key + ".pub") as f:
                typ, b64 = f.read().split()[:2]
        except (OSError, ValueError):
            continue
        if typ == "ssh-dss":
            results.append({"key": f"hostkey:{key}", "severity": "HIGH", "value": typ, "expected": "ed25519 / RSA >= 3072",
                            "pass": False, "rationale": "DSA host keys are 1024-bit and SHA-1 only."})
        elif typ == "ssh-rsa":
            try:
                bits = _rsa_bits_from_pub(b64)
            except (ValueError, struct.error, IndexError):
                continue
            sev = "HIGH" if bits < 2048 else "LOW"
            results.append({"key": f"hostkey:{key}", "severity": sev, "value": "RSA %d" % bits,
                            "expected": "RSA >= 3072 (or ed25519)", "pass": bits >= 3072,
                            "rationale": "RSA host keys under 2048 bits are breakable; NIST SP 800-57 asks for 3072 "
                                         "bits for use past 2030."})
    return results


# What OpenSSH's sshd uses when a directive is not set at all (sshd_config(5),
# OpenSSH 7.0+). An unset directive is judged on this value -- e.g. an unset
# PermitRootLogin is "prohibit-password", which is fine, while an unset
# MaxAuthTries is 6, which is not.
OPENSSH_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "protocol": "2",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "clientaliveinterval": "0",
    "logingracetime": "120",
    "permituserenvironment": "no",
    "ignorerhosts": "yes",
    "hostbasedauthentication": "no",
    "allowtcpforwarding": "yes",
    "usepam": "no",
    "loglevel": "INFO",
    "maxsessions": "10",
    "maxstartups": "10:30:100",
    "banner": "none",
    "strictmodes": "yes",
    "gssapiauthentication": "no",
    "kbdinteractiveauthentication": "yes",
    "clientalivecountmax": "3",
}
ALIASES = {"kbdinteractiveauthentication": ("challengeresponseauthentication",)}


def audit(cfg: dict) -> list:
    results = []
    for rule in RULES:
        if rule.key == "AllowUsers/AllowGroups":
            lists = [f"{k} {cfg[k]}" for k in ("allowusers", "allowgroups", "denyusers", "denygroups") if k in cfg]
            results.append({"key": rule.key, "value": "; ".join(lists) or "(none)", "expected": rule.expected,
                            "severity": rule.severity, "pass": bool(lists), "rationale": rule.rationale})
            continue
        val = cfg.get(rule.key.lower())
        for alias in ALIASES.get(rule.key.lower(), ()):
            if val is None:
                val = cfg.get(alias)
        shown = val
        if val is None:
            val = OPENSSH_DEFAULTS.get(rule.key.lower())
            shown = f"{val} (default)" if val is not None else "(default)"
        ok = rule.check(val) if rule.check else (val == rule.expected)
        results.append({
            "key": rule.key,
            "value": shown,
            "expected": rule.expected,
            "severity": rule.severity,
            "pass": bool(ok),
            "rationale": rule.rationale,
        })
    results.extend(judge_algorithms(_algorithm_lists(cfg)))
    return results


def render_text(results: list) -> str:
    lines = ["SSH Hardening Audit Report", "=" * 40, ""]
    fails = [r for r in results if not r["pass"]]
    passes = [r for r in results if r["pass"]]
    order = SEVERITY_ORDER
    fails.sort(key=lambda r: order.get(r["severity"], 9))
    if not fails:
        lines.append("✅ No findings — configuration matches all checked hardening rules.")
    for r in fails:
        lines.append(f"[{r['severity']}] {r['key']} = {r['value']}  (expected: {r['expected']})")
        lines.append(f"    {r['rationale']}")
        lines.append("")
    lines.append(f"Summary: {len(fails)} finding(s), {len(passes)} check(s) passed, {len(results)} total.")
    return "\n".join(lines)


def render_html(results: list) -> str:
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    rows = []
    for r in sorted(results, key=lambda r: (r["pass"], order.get(r["severity"], 9))):
        color = "#22c55e" if r["pass"] else {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#6b7280"}[r["severity"]]
        status = "PASS" if r["pass"] else f"FAIL ({r['severity']})"
        rows.append(
            f'<tr><td>{html.escape(str(r["key"]))}</td><td>{html.escape(str(r["value"]))}</td>'
            f'<td>{html.escape(str(r["expected"]))}</td>'
            f'<td style="color:{color};font-weight:600">{status}</td><td>{html.escape(str(r["rationale"]))}</td></tr>'
        )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>SSH Hardening Audit Report</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#0b0d12;color:#e6e8ee;padding:2rem}}
table{{width:100%;border-collapse:collapse}} td,th{{padding:8px 12px;border-bottom:1px solid #232734;text-align:left;font-size:0.9rem}}
th{{color:#8b93a3;text-transform:uppercase;font-size:0.75rem}}
</style></head><body>
<h1>SSH Hardening Audit Report</h1>
<table><tr><th>Directive</th><th>Value</th><th>Expected</th><th>Status</th><th>Rationale</th></tr>
{"".join(rows)}
</table></body></html>"""


def get_live_config() -> str:
    try:
        out = subprocess.run(["sshd", "-T"], capture_output=True, text=True)
    except FileNotFoundError:
        raise RuntimeError("`sshd` not found on PATH -- --live needs the OpenSSH server installed (try /usr/sbin in PATH, or run as root)")
    if out.returncode != 0:
        raise RuntimeError(f"`sshd -T` failed (exit {out.returncode}): {out.stderr.strip() or '(no output)'} -- it usually needs root")
    return out.stdout


def parse_remote(spec):
    spec = spec.strip()
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else 22
    if spec.count(":") == 1:
        host, port = spec.split(":")
        return host, int(port)
    return spec, 22


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sshd-hardening-auditor", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("config", nargs="?", default="/etc/ssh/sshd_config", help="path to sshd_config")
    ap.add_argument("--live", action="store_true", help="run `sshd -T` instead of reading a file")
    ap.add_argument("--remote", metavar="HOST[:PORT]",
                    help="scan a running SSH server's offered algorithms over the network (no login)")
    ap.add_argument("--timeout", type=float, default=10, help="--remote connection timeout in seconds (default 10)")
    ap.add_argument("--no-file-checks", action="store_true",
                    help="skip sshd_config/host key permission and host key size checks")
    ap.add_argument("--json", action="store_true", help="output JSON instead of text")
    ap.add_argument("--html", metavar="FILE", help="also write an HTML report to FILE")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                    help="lowest severity that makes the exit code 1 (default: high)")
    args = ap.parse_args(argv)

    banner = None
    try:
        if args.remote:
            host, port = parse_remote(args.remote)
            banner, results = audit_remote(host, port, args.timeout)
        else:
            if args.live:
                text = get_live_config()
                path = "/etc/ssh/sshd_config"
            else:
                text = "\n".join(_read_with_includes(args.config))
                path = args.config
            cfg = parse_sshd_config(text)
            results = audit(cfg)
            if not args.no_file_checks:
                results.extend(audit_files(path, cfg))
    except ValueError as e:
        print(f"sshd-hardening-auditor: ERROR -- {e}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError) as e:
        print(f"sshd-hardening-auditor: ERROR -- {e}", file=sys.stderr)
        return 2

    if args.html:
        with open(args.html, "w") as f:
            f.write(render_html(results))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if banner:
            print(f"Server: {banner}  ({args.remote})\n")
        print(render_text(results))

    if args.fail_on == "never":
        return 0
    gate = SEVERITY_ORDER[args.fail_on.upper()]
    return 1 if any(not r["pass"] and SEVERITY_ORDER[r["severity"]] <= gate for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
