"""Read-only security checks."""
import os
import stat
from pathlib import Path
from typing import Iterable

from .models import Finding


def _finding(check_id: str, severity: str, title: str, path: Path,
             detail: str, recommendation: str) -> Finding:
    return Finding(check_id, severity, title, str(path), detail, recommendation)


def scan_world_writable(roots: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for root in roots:
        if not root.exists():
            continue
        candidates = [root]
        if root.is_dir():
            try:
                candidates.extend(root.rglob("*"))
            except OSError:
                pass
        for item in candidates:
            try:
                mode = item.lstat().st_mode
            except (OSError, PermissionError):
                continue
            if stat.S_ISREG(mode) or stat.S_ISDIR(mode):
                if mode & stat.S_IWOTH:
                    kind = "directory" if stat.S_ISDIR(mode) else "file"
                    findings.append(_finding(
                        "FS-001", "HIGH", "World-writable " + kind, item,
                        "Other users can write to this " + kind + ".",
                        "Remove world-write permission unless it is explicitly required; validate sticky-bit policy for shared directories."
                    ))
    return findings


def audit_ssh(ssh_dir: Path = Path("/etc/ssh")) -> list[Finding]:
    findings: list[Finding] = []
    if not ssh_dir.exists():
        return findings

    try:
        dir_mode = ssh_dir.stat().st_mode
        if dir_mode & (stat.S_IWGRP | stat.S_IWOTH):
            findings.append(_finding(
                "SSH-001", "HIGH", "SSH directory is writable by non-owner",
                ssh_dir, "The SSH configuration directory has group or other write permission.",
                "Restrict directory writes to the owner and trusted administrators."
            ))
    except OSError:
        pass

    for item in ssh_dir.iterdir():
        try:
            if not item.is_file() or item.is_symlink():
                continue
            mode = item.stat().st_mode
        except OSError:
            continue
        name = item.name.lower()
        if name.startswith("ssh_host_") and name.endswith("_key"):
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                findings.append(_finding(
                    "SSH-001", "HIGH", "SSH host private key permissions", item,
                    "Host private key is accessible by group or other users.",
                    "Restrict the private key to its intended owner (commonly mode 600)."
                ))
        if name in {"sshd_config", "ssh_config"} and mode & stat.S_IWOTH:
            findings.append(_finding(
                "SSH-001", "HIGH", "SSH configuration is world-writable", item,
                "Any local user may modify this SSH configuration file.",
                "Remove world-write permission and review file ownership."
            ))
        if name == "sshd_config":
            findings.extend(audit_sshd_settings(item))
    return findings


def audit_sshd_settings(config: Path) -> list[Finding]:
    findings: list[Finding] = []
    settings: dict[str, str] = {}
    try:
        for raw in config.read_text(errors="replace").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                settings[parts[0].lower()] = parts[1].strip().lower()
    except OSError:
        return findings

    risky = [
        ("permitrootlogin", {"yes"}, "Root SSH login is enabled",
         "Prefer PermitRootLogin prohibit-password or no, according to operational policy."),
        ("passwordauthentication", {"yes"}, "SSH password authentication is enabled",
         "Prefer key-based authentication where practical; confirm recovery access before changing policy."),
    ]
    for key, values, title, recommendation in risky:
        if settings.get(key) in values:
            findings.append(_finding(
                "SSH-002", "MEDIUM", title, config,
                f"{key} is set to {settings[key]}.", recommendation
            ))
    return findings


def audit_private_keys(roots: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            items = root.rglob("id_*")
            for item in items:
                if item.name.endswith(".pub") or not item.is_file():
                    continue
                try:
                    mode = item.stat().st_mode
                except OSError:
                    continue
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    findings.append(_finding(
                        "SSH-003", "HIGH", "Private key permissions are too broad",
                        item, "Potential private-key file is accessible by group or other users.",
                        "Restrict access to the key owner (commonly mode 600) and verify the file is a private key."
                    ))
        except OSError:
            continue
    return findings
