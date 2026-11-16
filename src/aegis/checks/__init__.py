"""Check registry.

Every supported ``check.type`` is registered here exactly once.  Rule loading
validates against this registry, so an unknown type can never reach runtime.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from aegis.checks import accounts, files, logging, network, ssh, system
from aegis.checks.base import CheckContext
from aegis.models import CheckResult, Rule

Validator = Callable[[dict[str, Any]], list[str]]
Runner = Callable[[Rule, CheckContext], CheckResult]


@dataclass(frozen=True)
class CheckSpec:
    name: str
    runner: Runner
    validator: Validator
    description: str


CHECK_SPECS: dict[str, CheckSpec] = {
    "file_exists": CheckSpec(
        "file_exists",
        files.run_file_exists,
        files.validate_file_exists,
        "Assert that a path exists or is absent.",
    ),
    "file_mode": CheckSpec(
        "file_mode",
        files.run_file_mode,
        files.validate_file_mode,
        "Require permission bits to be no broader than an octal mask.",
    ),
    "file_owner": CheckSpec(
        "file_owner",
        files.run_file_owner,
        files.validate_file_owner,
        "Require a file's owner and optional group, resolved inside the rootfs.",
    ),
    "file_content": CheckSpec(
        "file_content",
        files.run_file_content,
        files.validate_file_content,
        "Match a regular expression that must be present or absent.",
    ),
    "sysctl": CheckSpec(
        "sysctl",
        system.run_sysctl,
        system.validate_sysctl,
        "Resolve the effective sysctl value from sysctl.d files and sysctl.conf.",
    ),
    "sshd": CheckSpec(
        "sshd",
        ssh.run_sshd,
        ssh.validate_sshd,
        "Evaluate the first global OpenSSH directive value, expanding Include.",
    ),
    "package": CheckSpec(
        "package",
        system.run_package,
        system.validate_package,
        "Check installation state via dpkg, apk, or an rpm query.",
    ),
    "service": CheckSpec(
        "service",
        system.run_service,
        system.validate_service,
        "Check systemd enablement through unit symlinks.",
    ),
    "account": CheckSpec(
        "account",
        accounts.run_account,
        accounts.validate_account,
        "Audit passwd, shadow, group, and home-directory invariants.",
    ),
    "mount_option": CheckSpec(
        "mount_option",
        network.run_mount_option,
        network.validate_mount_option,
        "Require mount options on an fstab entry.",
    ),
    "firewall": CheckSpec(
        "firewall",
        network.run_firewall,
        network.validate_firewall,
        "Inspect ufw, firewalld, or nftables configuration offline.",
    ),
    "kernel_module": CheckSpec(
        "kernel_module",
        system.run_kernel_module,
        system.validate_kernel_module,
        "Check modprobe blacklist/install directives and explicit module loads.",
    ),
    "login_defs": CheckSpec(
        "login_defs",
        accounts.run_login_defs,
        accounts.validate_login_defs,
        "Constrain a key in /etc/login.defs.",
    ),
    "auditd": CheckSpec(
        "auditd",
        logging.run_auditd,
        logging.validate_auditd,
        "Check auditd installation, enablement, configuration, and boot flags.",
    ),
    "cron_permissions": CheckSpec(
        "cron_permissions",
        accounts.run_cron_permissions,
        accounts.validate_cron_permissions,
        "Inspect cron file permissions or cron/at allow-list restrictions.",
    ),
    "world_writable": CheckSpec(
        "world_writable",
        files.run_world_writable,
        files.validate_world_writable,
        "Bounded scan for world-writable regular files.",
    ),
    "listening_port": CheckSpec(
        "listening_port",
        network.run_listening_port,
        network.validate_listening_port,
        "Parse /proc/net/tcp and tcp6 for listening sockets.",
    ),
    "password_quality": CheckSpec(
        "password_quality",
        accounts.run_password_quality,
        accounts.validate_password_quality,
        "Constrain a key in /etc/security/pwquality.conf.",
    ),
}

CHECK_TYPES: frozenset[str] = frozenset(CHECK_SPECS)


def validate_check(check_type: str, params: dict[str, Any]) -> list[str]:
    spec = CHECK_SPECS.get(check_type)
    if spec is None:
        return [f"unknown check type {check_type!r}"]
    try:
        return spec.validator(params)
    except Exception as exc:  # pragma: no cover - defensive against buggy validators
        return [f"validator crashed: {exc}"]


def run_check(rule: Rule, context: CheckContext) -> CheckResult:
    spec = CHECK_SPECS.get(rule.check_type)
    if spec is None:
        return CheckResult.error(f"unknown check type {rule.check_type!r}")
    return spec.runner(rule, context)


def check_type_descriptions() -> dict[str, str]:
    return {name: spec.description for name, spec in CHECK_SPECS.items()}


__all__ = [
    "CHECK_SPECS",
    "CHECK_TYPES",
    "check_type_descriptions",
    "run_check",
    "validate_check",
]
