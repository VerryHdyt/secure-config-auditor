"""Audit orchestration."""
from pathlib import Path

from .checks import audit_private_keys, audit_ssh, scan_world_writable
from .models import Finding


def run_audit(paths: list[str] | None = None) -> list[Finding]:
    roots = [Path(p).expanduser() for p in (paths or ["/etc", "/home"])]
    findings = scan_world_writable(roots)
    findings.extend(audit_ssh())
    findings.extend(audit_private_keys([Path.home() / ".ssh"]))
    # Stable ordering makes reports and tests reproducible.
    return sorted(findings, key=lambda item: (item.severity, item.check_id, item.path))
