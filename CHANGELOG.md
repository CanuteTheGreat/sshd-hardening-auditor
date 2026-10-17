# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

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
