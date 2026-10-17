# SSH Hardening Auditor

A single-file, dependency-free Python script that audits an `sshd_config` (or a
live server's effective config via `sshd -T`) against CIS Benchmark / NIST-aligned
SSH hardening recommendations — catches weak ciphers/KEX/MACs, password auth left
enabled, root login, empty passwords, and more.

By **Errant Solutions** (errant.solutions), makers of [Rustinion](https://rustinion.com)
(device provisioning & monitoring), [/Dev/Out Digital](https://devout.digital) (security
awareness training), [OOPS!](https://oops.codes) (hands-on security labs), and [SSHerpa](https://ssherpa.app) (Android SSH client).

## Why

Every "harden your SSH server" checklist online is a blog post you have to
manually diff against your config by eye. This is a real, runnable, testable tool
instead — one Python file, stdlib only, works on any box with Python 3.8+.

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/sshd-hardening-auditor.git        # latest release branch; puts `sshd-hardening-auditor` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/sshd-hardening-auditor.git@v1.2.1  # a pinned release
brew install canutethegreat/errant-tools/sshd-hardening-auditor   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/sshd-hardening-auditor                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.8+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/sshd_audit.py && python3 sshd_audit.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/sshd-hardening-auditor/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install sshd-hardening-auditor` doesn't work until it's published there.

## Usage

```bash
sshd-hardening-auditor /etc/ssh/sshd_config      # a config file (the default path)
sudo sshd-hardening-auditor --live               # the effective config from `sshd -T`
sshd-hardening-auditor --remote host.example.com # what a running server offers on the wire (port 22)
sshd-hardening-auditor --remote 10.0.0.5:2222 --json
sshd-hardening-auditor --fail-on medium sshd_config   # CI gate: exit 1 on MEDIUM or worse
sshd-hardening-auditor --html report.html sshd_config
```

`--remote` connects, exchanges SSH identification strings and reads the server's
`KEXINIT` (the algorithm lists it offers). It never logs in or sends credentials,
so it works on any server you're allowed to connect to, including appliances
where you can't run `sshd -T`.

## What it checks

- **Authentication**: `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`,
  `HostbasedAuthentication`, `Protocol` (HIGH); `KbdInteractiveAuthentication`
  (`ChallengeResponseAuthentication`), `StrictModes`, `X11Forwarding`, `MaxAuthTries`,
  `PermitUserEnvironment`, `IgnoreRhosts` (MEDIUM); `GSSAPIAuthentication`, `UsePAM`,
  `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` (LOW)
- **CIS session limits and logging**: `LogLevel` (INFO/VERBOSE), `MaxSessions`, `MaxStartups`
  (10:30:60 or stricter), `Banner`, `ClientAliveInterval`, `ClientAliveCountMax`,
  `LoginGraceTime`, `AllowTcpForwarding` (LOW)
- **Algorithms** (configured lists, `sshd -T` output, or what `--remote` sees offered):
  - key exchange: SHA-1 and 1024-bit DH groups (HIGH), NIST `ecdh-sha2-nistp*` (LOW),
    and whether a hybrid **post-quantum** KEX (`sntrup761x25519`, `mlkem768x25519`) is offered (LOW)
  - host keys: `ssh-dss` (HIGH), SHA-1 `ssh-rsa` (MEDIUM), `ecdsa-sha2-nistp*` (LOW)
  - ciphers: every CBC mode, arcfour, 3DES, blowfish, cast128, `none` (HIGH)
  - MACs: MD5 and truncated SHA-1 (HIGH), `hmac-sha1`, `umac-64` (MEDIUM), non-ETM
    (encrypt-and-MAC) variants (LOW)
- **Terrapin** (CVE-2023-48795, `--remote`): chacha20-poly1305 or CBC+EtM offered without
  strict key exchange (MEDIUM); pre-authentication `zlib` compression (LOW)
- **Files** (CIS 5.2.1-5.2.3): `sshd_config` and host private keys owned by root and mode
  0600; RSA host keys under 2048 bits (HIGH) or under 3072 (LOW), DSA host keys (HIGH).
  `--no-file-checks` skips these.

The config is read the way `sshd` itself reads it: `Include` drop-ins
(e.g. `/etc/ssh/sshd_config.d/*.conf`) are expanded in place, the **first**
value of a directive wins, settings inside `Match` blocks don't override the
global ones, and an unset directive is judged on OpenSSH's built-in default
(shown as `<value> (default)`). Times use sshd's format (`90`, `1m30s`, `2h`), and
`LoginGraceTime 0` / `ClientAliveCountMax 0` (which switch the limit off) fail their rules.
One version difference: OpenSSH before 10.1 keeps the *last* of several `MaxStartups` lines;
`--live` always shows what your sshd really uses. An algorithm list written with `+`/`-`/`^` is
relative to OpenSSH's defaults, so only the named algorithms are judged; use
`--live` or `--remote` to judge the full effective list. The test suite
cross-checks file mode against the real `sshd -T` (including 200 random configs in
`tests/test_accuracy.py`), and `--remote` against a real running sshd, on every CI run.

Exit codes (same convention as every Errant Solutions tool):

| Code | Meaning |
|---|---|
| 0 | no failed check at or above `--fail-on` (default `high`) |
| 1 | at least one |
| 2 | the config couldn't be read, `sshd -T` couldn't run, or the remote server couldn't be reached |

Each finding includes the current value, the expected value, and a one-line
rationale — so it doubles as a mini security-training doc for whoever reads the
output.

## CI integration example

```yaml
# .forgejo/workflows/ssh-audit.yml (or any CI)
- name: Audit sshd_config
  run: pipx run --spec git+https://git.canutethegreat.com/CanuteTheGreat/sshd-hardening-auditor.git sshd-hardening-auditor --no-file-checks deploy/sshd_config
```

## License

MIT — see LICENSE. Free to use, modify, and redistribute. If it saves
you time, [pay what you think it's worth here](https://buy.stripe.com/dRmaEXamdbvFbXF4py1VK01) —
or check out [Rustinion](https://rustinion.com) for full fleet-wide config
compliance monitoring.

## Roadmap ideas (not yet built)
- Compare against a specific CIS Benchmark level (1 vs 2) profile flag
- `--fix` mode that writes a hardened config with an explained diff

## Tests

`tests/` runs every option and check end-to-end (including `--live` and `--remote` against a
real OpenSSH server) on Python 3.8 and current Python in Forgejo CI:
`sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).
