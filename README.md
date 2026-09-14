# SSH Hardening Auditor

A single-file, dependency-free Python script that audits an `sshd_config` (or a
live server's effective config via `sshd -T`) against CIS Benchmark / NIST-aligned
SSH hardening recommendations — catches weak ciphers/KEX/MACs, password auth left
enabled, root login, empty passwords, and more.

By **Errant Solutions** (errant.solutions), makers of [Rustinion](https://rustinion.com)
(device provisioning & monitoring), [Big Double D](https://oops.codes) (security
awareness training), and [SSHerpa](https://ssherpa.app) (Android SSH client).

## Why

Every "harden your SSH server" checklist online is a blog post you have to
manually diff against your config by eye. This is a real, runnable, testable tool
instead — one Python file, stdlib only, works on any box with Python 3.8+.

## Usage

```bash
# Audit a config file (defaults to /etc/ssh/sshd_config)
python3 sshd_audit.py /etc/ssh/sshd_config

# Audit the live, effective config (resolves all Match blocks/defaults)
sudo python3 sshd_audit.py --live

# CI-friendly: exits 1 if any HIGH-severity finding exists
python3 sshd_audit.py sshd_config && echo "PASSED"

# Machine-readable output
python3 sshd_audit.py --json sshd_config

# Generate a shareable HTML report
python3 sshd_audit.py --html report.html sshd_config
```

## What it checks

- `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`,
  `HostbasedAuthentication`, `Protocol` (HIGH severity)
- Weak/legacy key-exchange algorithms, ciphers, and MACs (HIGH)
- `X11Forwarding`, `MaxAuthTries`, `PermitUserEnvironment`, `IgnoreRhosts` (MEDIUM)
- `ClientAliveInterval`, `LoginGraceTime`, `AllowTcpForwarding`, `UsePAM` (LOW)

Each finding includes the current value, the expected value, and a one-line
rationale — so it doubles as a mini security-training doc for whoever reads the
output.

## CI integration example

```yaml
# .github/workflows/ssh-audit.yml
- name: Audit sshd_config
  run: python3 sshd_audit.py deploy/sshd_config
```

## License

Free to use, modify, and redistribute for any purpose (MIT-style). If it saves
you time, [pay what you think it's worth here](https://buy.stripe.com/dRmaEXamdbvFbXF4py1VK01) —
or check out [Rustinion](https://rustinion.com) for full fleet-wide config
compliance monitoring.

## Roadmap ideas (not yet built)
- Compare against a specific CIS Benchmark level (1 vs 2) profile flag
- `--fix` mode that writes a hardened config with an explained diff
- Bundled test suite / GitHub Action for one-line CI adoption
