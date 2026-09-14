#!/usr/bin/env python3
"""
sshd-audit — SSH server hardening auditor
==========================================

Audits an sshd_config (and optionally a live server's effective config via
`sshd -T`) against CIS Benchmark / NIST-aligned SSH hardening recommendations.
No third-party dependencies — stdlib only, works anywhere Python 3.8+ runs.

Usage:
    python3 sshd_audit.py [path/to/sshd_config]
    python3 sshd_audit.py --live          # runs `sshd -T` locally (needs sudo)
    python3 sshd_audit.py --json          # machine-readable output
    python3 sshd_audit.py --html report.html

Exit code: 0 if no HIGH-severity findings, 1 otherwise (CI-friendly).

Copyright (c) 2026 Errant Solutions. Licensed for use per LICENSE.txt.
"""
import argparse
import json
import subprocess
import sys
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


def _int_at_least(n):
    def f(v):
        try:
            return v is not None and int(v.strip()) >= n
        except ValueError:
            return False
    return f


WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "3des-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-etm@openssh.com"}

RULES = [
    Rule("PermitRootLogin", "no", "HIGH",
         "Root login over SSH bypasses per-user accountability and audit trails; use sudo/su after a normal-user login instead.",
         check=lambda v: v is not None and v.strip().lower() in ("no", "prohibit-password")),
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
         check=lambda v: v is not None and v.strip() != "0"),
    Rule("LoginGraceTime", "<=60", "LOW",
         "A short grace time limits how long a half-open connection can be held.",
         check=_int_at_most(60)),
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
]


def parse_sshd_config(text: str) -> dict:
    """Parse sshd_config text into {directive_lower: last_value} (last one wins, like sshd itself)."""
    cfg = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, val = parts[0], parts[1].strip()
        cfg[key.lower()] = val
    return cfg


def get_kex_ciphers_macs(cfg: dict):
    findings = []
    for directive, weak_set, label in (
        ("kexalgorithms", WEAK_KEX, "key exchange algorithm"),
        ("ciphers", WEAK_CIPHERS, "cipher"),
        ("macs", WEAK_MACS, "MAC"),
    ):
        val = cfg.get(directive)
        if not val:
            continue
        algs = [a.strip().lstrip("+-^") for a in val.split(",")]
        weak = [a for a in algs if a in weak_set]
        if weak:
            findings.append({
                "key": directive,
                "severity": "HIGH",
                "value": val,
                "expected": f"no legacy {label}s",
                "rationale": f"Legacy/weak {label}(s) still permitted: {', '.join(weak)}.",
            })
    return findings


def audit(cfg: dict) -> list:
    results = []
    for rule in RULES:
        val = cfg.get(rule.key.lower())
        ok = rule.check(val) if rule.check else (val == rule.expected)
        results.append({
            "key": rule.key,
            "value": val if val is not None else "(default)",
            "expected": rule.expected,
            "severity": rule.severity,
            "pass": bool(ok),
            "rationale": rule.rationale,
        })
    results.extend({**f, "value": f["value"], "pass": False} for f in get_kex_ciphers_macs(cfg))
    return results


def render_text(results: list) -> str:
    lines = ["SSH Hardening Audit Report", "=" * 40, ""]
    fails = [r for r in results if not r["pass"]]
    passes = [r for r in results if r["pass"]]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
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
            f'<tr><td>{r["key"]}</td><td>{r["value"]}</td><td>{r["expected"]}</td>'
            f'<td style="color:{color};font-weight:600">{status}</td><td>{r["rationale"]}</td></tr>'
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
    out = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=True)
    return out.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", nargs="?", default="/etc/ssh/sshd_config", help="path to sshd_config")
    ap.add_argument("--live", action="store_true", help="run `sshd -T` instead of reading a file")
    ap.add_argument("--json", action="store_true", help="output JSON instead of text")
    ap.add_argument("--html", metavar="FILE", help="also write an HTML report to FILE")
    args = ap.parse_args()

    if args.live:
        text = get_live_config()
    else:
        with open(args.config) as f:
            text = f.read()

    cfg = parse_sshd_config(text)
    results = audit(cfg)

    if args.html:
        with open(args.html, "w") as f:
            f.write(render_html(results))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render_text(results))

    sys.exit(1 if any(not r["pass"] and r["severity"] == "HIGH" for r in results) else 0)


if __name__ == "__main__":
    main()
