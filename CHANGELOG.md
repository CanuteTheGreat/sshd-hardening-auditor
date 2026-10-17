# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.2 - 2026-10-17

- `--remote`: a server whose KEXINIT is cut short or carries a name-list longer than the packet is reported as
  `ERROR -- malformed KEXINIT` (exit 2) instead of crashing with a Python traceback (exit 1).
- Tests: wire-contract suite for `--remote` (fragmented reads, pre-banner lines, every broken-server case,
  both-direction lists, Terrapin CBC+EtM, compression) and exact text/HTML reports.

## 1.2.1 - 2026-10-17

- `ChallengeResponseAuthentication` and `KbdInteractiveAuthentication` are one option inside sshd, so the first of either now wins (the tool always preferred KbdInteractive, disagreeing with `sshd -T` whenever ChallengeResponse came first).
- Times are read in sshd's format (`1m`, `90s`, `1m30s`, `2h`): `LoginGraceTime 1m` used to fail and `ClientAliveInterval 0s` used to pass.
- `LoginGraceTime 0` (no limit at all) and `ClientAliveCountMax 0` (never drops unresponsive clients, OpenSSH 8.2+) now fail their rules instead of passing as "<= limit".
- Tests: accuracy suite (200 random configs whose verdicts must equal those from OpenSSH's own `sshd -T`, Mozilla's Modern guideline, Debian's stock config), mutation testing (nightly), claims ledger.
- Time values with a trailing bare number (`1m30`, `0m45`) are read the way sshd reads them (seconds), instead
  of failing ClientAliveInterval/LoginGraceTime as unparseable. Checked against `sshd -T`.

## 1.2.0 - 2026-10-16

- **`--remote host[:port]`**: reads a running server's KEXINIT over the network (no login) and judges the
  key exchange, host key, cipher and MAC algorithms it actually offers, plus Terrapin (CVE-2023-48795:
  chacha20-poly1305 or CBC+EtM without strict kex) and pre-auth zlib compression.
- Much fuller algorithm policy with per-algorithm severities: SHA-1 KEX/host keys, `ssh-rsa`, `ssh-dss`,
  NIST curves, every CBC cipher, `hmac-sha1`, `umac-64`, non-ETM MACs, and a post-quantum KEX advisory.
- New CIS checks: LogLevel, MaxSessions, MaxStartups, Banner, StrictModes, GSSAPIAuthentication,
  KbdInteractiveAuthentication (and its ChallengeResponseAuthentication alias), AllowUsers/AllowGroups,
  ClientAliveCountMax; sshd_config and host key ownership/permissions; RSA/DSA host key sizes
  (`--no-file-checks` to skip).
- `--fail-on` (default `high`, the previous behaviour).
- JSON results now include passing algorithm entries for every configured or offered algorithm list.
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/sshd-hardening-auditor.git`
  puts a `sshd-hardening-auditor` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Follow sshd's real config semantics, add CI test suite

## 1.0.0 - 2026-09-13

- First public release.
