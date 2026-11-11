# Secure Config Auditor

A read-only Linux security configuration auditor written in Python. It checks common filesystem permission risks and SSH configuration without changing the host.

## Features
- Detects world-writable files and directories in selected paths.
- Audits SSH configuration and private-key permissions.
- Checks risky sshd settings when readable.
- Human-readable and JSON output; severity filtering and custom scan roots.
- Python standard library only.

> **Safety:** Read-only. It never changes, deletes, or uploads files. Use only on systems you own or are authorized to audit.

## Requirements
Linux recommended; Python 3.9+.

## Quick start
```bash
git clone https://github.com/VerryHdyt/secure-config-auditor.git
cd secure-config-auditor
python3 -m secure_config_auditor --help
python3 -m secure_config_auditor audit
```

Scan additional paths:
```bash
python3 -m secure_config_auditor audit --paths /etc /opt /var/www
```

JSON report:
```bash
python3 -m secure_config_auditor audit --format json --output report.json
```

## Checks
| ID | Check |
|---|---|
| FS-001 | World-writable files and directories |
| SSH-001 | SSH configuration and host-key permissions |
| SSH-002 | Risky sshd settings (root login, password authentication) |
| SSH-003 | SSH private keys accessible by group or others |

Findings are indicators, not proof of exploitability. Review them against your system policy.

## Tests
```bash
python3 -m unittest discover -s tests -v
```

## License
MIT
