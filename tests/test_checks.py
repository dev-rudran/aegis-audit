"""Behavioural tests for every registered check type."""

from __future__ import annotations

import os
import stat

import pytest

from aegis.checks import CHECK_TYPES, run_check, validate_check
from aegis.models import Status
from tests.helpers import context, make_rule, write_file, write_symlink


def evaluate(check_type: str, params: dict, root):
    return run_check(make_rule(check_type, params), context(root))


def test_file_exists_present_absent_and_kind(fresh_root) -> None:
    write_file(fresh_root, "/etc/example", "x")
    present = evaluate("file_exists", {"path": "/etc/example"}, fresh_root)
    assert present.status is Status.PASS
    absent = evaluate("file_exists", {"path": "/etc/missing"}, fresh_root)
    assert absent.status is Status.FAIL
    assert (
        evaluate("file_exists", {"path": "/etc/missing", "state": "absent"}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate("file_exists", {"path": "/etc/example", "kind": "dir"}, fresh_root).status
        is Status.FAIL
    )


def test_file_mode_max_and_exact(fresh_root) -> None:
    write_file(fresh_root, "/etc/secret", "x", mode=0o644)
    assert (
        evaluate("file_mode", {"path": "/etc/secret", "max_mode": "0600"}, fresh_root).status
        is Status.FAIL
    )
    assert (
        evaluate("file_mode", {"path": "/etc/secret", "max_mode": "0640"}, fresh_root).status
        is Status.FAIL
    )
    assert (
        evaluate("file_mode", {"path": "/etc/secret", "max_mode": "0644"}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate(
            "file_mode", {"path": "/etc/secret", "max_mode": "0644", "exact": True}, fresh_root
        ).status
        is Status.PASS
    )
    missing = evaluate("file_mode", {"path": "/etc/absent", "max_mode": "0600"}, fresh_root)
    assert missing.status is Status.NOT_APPLICABLE
    assert (
        evaluate(
            "file_mode", {"path": "/etc/absent", "max_mode": "0600", "missing": "fail"}, fresh_root
        ).status
        is Status.FAIL
    )


def test_file_owner_uses_numeric_or_named_principals(fresh_root) -> None:
    if os.getuid() == 0:
        pytest.skip("fixture files are root-owned when the tests run as root")
    write_file(fresh_root, "/etc/owned", "x")
    uid = os.getuid()
    gid = os.getgid()
    assert (
        evaluate("file_owner", {"path": "/etc/owned", "owner": str(uid)}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate(
            "file_owner", {"path": "/etc/owned", "owner": str(uid), "group": str(gid)}, fresh_root
        ).status
        is Status.PASS
    )
    assert (
        evaluate("file_owner", {"path": "/etc/owned", "owner": str(uid + 1)}, fresh_root).status
        is Status.FAIL
    )
    write_file(fresh_root, "/etc/passwd", f"nobody:x:{uid}:{gid}::/nonexistent:/usr/sbin/nologin\n")
    assert (
        evaluate("file_owner", {"path": "/etc/owned", "owner": "nobody"}, fresh_root).status
        is Status.PASS
    )


def test_file_content_present_and_absent_patterns(fresh_root) -> None:
    write_file(fresh_root, "/etc/issue.net", "Authorized use only\n")
    assert (
        evaluate(
            "file_content", {"path": "/etc/issue.net", "pattern": r"^Authorized"}, fresh_root
        ).status
        is Status.PASS
    )
    assert (
        evaluate(
            "file_content",
            {"path": "/etc/issue.net", "pattern": "authorized", "ignore_case": True},
            fresh_root,
        ).status
        is Status.PASS
    )
    assert (
        evaluate(
            "file_content",
            {"path": "/etc/issue.net", "pattern": "welcome", "state": "absent"},
            fresh_root,
        ).status
        is Status.PASS
    )
    assert (
        evaluate(
            "file_content",
            {"path": "/etc/issue.net", "pattern": "Authorized", "state": "absent"},
            fresh_root,
        ).status
        is Status.FAIL
    )


def test_sysctl_scans_drop_ins_then_final_file(fresh_root) -> None:
    write_file(fresh_root, "/etc/sysctl.d/10-base.conf", "net.ipv4.ip_forward = 1\n")
    write_file(fresh_root, "/etc/sysctl.d/20-override.conf", "net.ipv4.ip_forward = 0\n")
    write_file(fresh_root, "/etc/sysctl.conf", "net/ipv4/ip_forward=1\n")
    fail = evaluate("sysctl", {"key": "net.ipv4.ip_forward", "value": ["0"]}, fresh_root)
    assert fail.status is Status.FAIL
    assert fail.evidence["actual"] == "1"
    assert fail.evidence["source"] == "/etc/sysctl.conf"
    assert (
        evaluate("sysctl", {"key": "net.ipv4.ip_forward", "value": ["1", "2"]}, fresh_root).status
        is Status.PASS
    )
    missing = evaluate(
        "sysctl",
        {"key": "kernel.randomize_va_space", "value": ["2"], "missing": "not_applicable"},
        fresh_root,
    )
    assert missing.status is Status.NOT_APPLICABLE


def test_sshd_first_directive_wins_and_includes_are_followed(fresh_root) -> None:
    write_file(
        fresh_root,
        "/etc/ssh/sshd_config",
        "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User backup\n"
        "    PermitRootLogin no\n",
    )
    write_file(fresh_root, "/etc/ssh/sshd_config.d/50-hardening.conf", "PermitRootLogin no\n")
    first = evaluate("sshd", {"key": "PermitRootLogin", "value": "no"}, fresh_root)
    assert first.status is Status.FAIL
    assert first.evidence["actual"] == "yes"
    assert first.evidence["directive_count"] == 2
    defaulted = evaluate(
        "sshd", {"key": "X11Forwarding", "value": "no", "default": "no"}, fresh_root
    )
    assert defaulted.status is Status.PASS
    assert defaulted.evidence["defaulted"] is True
    missing = evaluate(
        "sshd",
        {"key": "Banner", "value": "/etc/issue.net", "missing": "not_applicable"},
        fresh_root,
    )
    assert missing.status is Status.NOT_APPLICABLE


def test_package_check_supports_dpkg_and_name_alternatives(fresh_root) -> None:
    write_file(
        fresh_root,
        "/var/lib/dpkg/status",
        "Package: openssh-server\nStatus: install ok installed\nVersion: 1:9.6p1\n"
        "Architecture: amd64\n\n"
        "Package: telnetd\nStatus: deinstall ok config-files\nVersion: 0.17\n"
        "Architecture: amd64\n",
    )
    installed = evaluate(
        "package", {"name": ["openssh-server", "ssh"], "state": "installed"}, fresh_root
    )
    assert installed.status is Status.PASS
    assert installed.evidence["installed"] == ["openssh-server"]
    assert (
        evaluate("package", {"name": "telnetd", "state": "removed"}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate("package", {"name": "telnetd", "state": "installed"}, fresh_root).status
        is Status.FAIL
    )


def test_service_state_uses_enablement_symlinks(fresh_root) -> None:
    write_symlink(
        fresh_root,
        "/etc/systemd/system/multi-user.target.wants/ssh.service",
        "/lib/systemd/system/ssh.service",
    )
    assert (
        evaluate("service", {"name": "ssh", "state": "enabled"}, fresh_root).status is Status.PASS
    )
    assert (
        evaluate("service", {"name": "ssh.service", "state": "disabled"}, fresh_root).status
        is Status.FAIL
    )
    write_symlink(fresh_root, "/etc/systemd/system/ssh.service", "/dev/null")
    masked = evaluate("service", {"name": "ssh", "state": "enabled"}, fresh_root)
    assert masked.status is Status.FAIL
    assert "masked" in masked.message


def test_account_empty_password_and_uid_zero(fresh_root) -> None:
    write_file(
        fresh_root,
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\ntoor::0:0:toor:/root:/bin/bash\n",
    )
    empty = evaluate("account", {"kind": "empty_password"}, fresh_root)
    assert empty.status is Status.FAIL
    assert "toor" in empty.message
    uid_zero = evaluate("account", {"kind": "uid_zero_unique"}, fresh_root)
    assert uid_zero.status is Status.FAIL
    assert uid_zero.evidence["uid_zero_accounts"] == ["root", "toor"]


def test_account_root_shell_validation(fresh_root) -> None:
    write_file(fresh_root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    write_file(fresh_root, "/etc/shells", "/bin/sh\n/bin/bash\n")
    assert evaluate("account", {"kind": "root_shell_valid"}, fresh_root).status is Status.PASS
    write_file(fresh_root, "/etc/passwd", "root:x:0:0:root:/root:/usr/sbin/nologin\n")
    assert evaluate("account", {"kind": "root_shell_valid"}, fresh_root).status is Status.FAIL
    write_file(fresh_root, "/etc/passwd", "root:x:0:0:root:/root:/bin/zsh\n")
    assert evaluate("account", {"kind": "root_shell_valid"}, fresh_root).status is Status.FAIL


def test_mount_option_against_fstab(fresh_root) -> None:
    write_file(
        fresh_root,
        "/etc/fstab",
        "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0\n",
    )
    assert (
        evaluate(
            "mount_option",
            {"mountpoint": "/dev/shm", "options": ["nodev", "nosuid", "noexec"]},
            fresh_root,
        ).status
        is Status.PASS
    )
    assert (
        evaluate(
            "mount_option", {"mountpoint": "/dev/shm", "options": ["nodev", "ro"]}, fresh_root
        ).status
        is Status.FAIL
    )
    assert (
        evaluate(
            "mount_option", {"mountpoint": "/var/tmp", "options": ["nodev"]}, fresh_root
        ).status
        is Status.NOT_APPLICABLE
    )
    assert (
        evaluate(
            "mount_option",
            {"mountpoint": "/var/tmp", "options": ["nodev"], "missing": "fail"},
            fresh_root,
        ).status
        is Status.FAIL
    )


def test_firewall_ufw_settings(fresh_root) -> None:
    write_file(fresh_root, "/usr/sbin/ufw", "")
    write_file(fresh_root, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
    write_file(fresh_root, "/etc/default/ufw", 'DEFAULT_INPUT_POLICY="DROP"\n')
    assert (
        evaluate("firewall", {"engine": "ufw", "setting": "installed"}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate("firewall", {"engine": "ufw", "setting": "enabled"}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate("firewall", {"engine": "ufw", "setting": "default_incoming"}, fresh_root).status
        is Status.PASS
    )
    write_file(fresh_root, "/etc/default/ufw", "DEFAULT_INPUT_POLICY=ACCEPT\n")
    assert (
        evaluate("firewall", {"engine": "ufw", "setting": "default_incoming"}, fresh_root).status
        is Status.FAIL
    )


def test_kernel_module_blacklist_and_explicit_load(fresh_root) -> None:
    write_file(fresh_root, "/etc/modprobe.d/99-aegis.conf", "install cramfs /bin/false\n")
    assert (
        evaluate("kernel_module", {"module": "cramfs", "state": "disabled"}, fresh_root).status
        is Status.PASS
    )
    write_file(fresh_root, "/etc/modules-load.d/cramfs.conf", "cramfs\n")
    loaded = evaluate("kernel_module", {"module": "cramfs", "state": "disabled"}, fresh_root)
    assert loaded.status is Status.FAIL
    assert "explicitly loaded" in loaded.message
    assert (
        evaluate("kernel_module", {"module": "sctp", "state": "disabled"}, fresh_root).status
        is Status.FAIL
    )


def test_login_defs_numeric_limits(fresh_root) -> None:
    write_file(fresh_root, "/etc/login.defs", "PASS_MAX_DAYS 99999\nPASS_MIN_LEN 8\n")
    assert (
        evaluate("login_defs", {"key": "PASS_MAX_DAYS", "max": 90}, fresh_root).status
        is Status.FAIL
    )
    assert (
        evaluate("login_defs", {"key": "PASS_MAX_DAYS", "max": 100000}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate("login_defs", {"key": "PASS_MIN_LEN", "min": 14}, fresh_root).status is Status.FAIL
    )
    missing = evaluate(
        "login_defs", {"key": "UMASK", "exact": "027", "missing": "not_applicable"}, fresh_root
    )
    assert missing.status is Status.NOT_APPLICABLE


def test_auditd_config_values(fresh_root) -> None:
    write_file(
        fresh_root,
        "/etc/audit/auditd.conf",
        "max_log_file = 8\nmax_log_file_action = keep_logs\nspace_left_action = email\n",
    )
    assert (
        evaluate(
            "auditd",
            {"kind": "config", "key": "max_log_file_action", "exact": "keep_logs"},
            fresh_root,
        ).status
        is Status.PASS
    )
    assert (
        evaluate(
            "auditd",
            {"kind": "config", "key": "max_log_file_action", "exact": "rotate"},
            fresh_root,
        ).status
        is Status.FAIL
    )
    assert (
        evaluate("auditd", {"kind": "config", "key": "max_log_file", "min": 8}, fresh_root).status
        is Status.PASS
    )
    assert (
        evaluate(
            "auditd",
            {"kind": "config", "key": "space_left_action", "allowed": ["email", "exec"]},
            fresh_root,
        ).status
        is Status.PASS
    )


def test_cron_permissions_and_restrictions(fresh_root) -> None:
    write_file(fresh_root, "/etc/cron.d/job", "* * * * * root true\n", mode=0o644)
    custom = {"kind": "permissions", "path": "/etc/cron.d/job", "max_mode": "0600"}
    assert evaluate("cron_permissions", custom, fresh_root).status is Status.FAIL
    (fresh_root / "etc/cron.d/job").chmod(0o600)
    assert evaluate("cron_permissions", custom, fresh_root).status is Status.PASS
    restricted = evaluate("cron_permissions", {"kind": "restricted"}, fresh_root)
    assert restricted.status is Status.FAIL
    write_file(fresh_root, "/etc/cron.allow", "root\n")
    write_file(fresh_root, "/etc/at.allow", "root\n")
    assert evaluate("cron_permissions", {"kind": "restricted"}, fresh_root).status is Status.PASS


def test_world_writable_scan(fresh_root) -> None:
    write_file(fresh_root, "/tmp/safe", "x", mode=0o644)
    write_file(fresh_root, "/tmp/unsafe", "x", mode=0o666)
    result = evaluate("world_writable", {"root": "/tmp"}, fresh_root)
    assert result.status is Status.FAIL
    assert result.evidence["world_writable_count"] == 1
    (fresh_root / "tmp/unsafe").chmod(stat.S_IRUSR | stat.S_IWUSR)
    passed = evaluate("world_writable", {"root": "/tmp"}, fresh_root)
    assert passed.status is Status.PASS
    assert passed.evidence["scanned"] == 2


def test_listening_port_denied_and_allowed(fresh_root) -> None:
    write_file(
        fresh_root,
        "/proc/net/tcp",
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000\n"
        "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000\n",
    )
    assert (
        evaluate("listening_port", {"mode": "denied", "ports": [22]}, fresh_root).status
        is Status.FAIL
    )
    assert (
        evaluate("listening_port", {"mode": "allowed", "ports": [22, 8080]}, fresh_root).status
        is Status.PASS
    )
    loopback_ignored = evaluate(
        "listening_port",
        {"mode": "denied", "ports": [8080], "ignore_loopback": True},
        fresh_root,
    )
    assert loopback_ignored.status is Status.PASS
    write_file(fresh_root, "/proc/net/tcp", "header\n")
    assert (
        evaluate("listening_port", {"mode": "allowed", "ports": [22]}, fresh_root).status
        is Status.PASS
    )


def test_password_quality_minimum_length(fresh_root) -> None:
    write_file(fresh_root, "/etc/security/pwquality.conf", "minlen = 14\ndcredit = -1\n")
    assert (
        evaluate("password_quality", {"key": "minlen", "min": 14}, fresh_root).status is Status.PASS
    )
    assert (
        evaluate("password_quality", {"key": "minlen", "min": 16}, fresh_root).status is Status.FAIL
    )
    assert (
        evaluate("password_quality", {"key": "dcredit", "max": -1}, fresh_root).status
        is Status.PASS
    )


def test_all_required_check_types_are_registered() -> None:
    required = {
        "file_exists",
        "file_mode",
        "file_owner",
        "file_content",
        "sysctl",
        "sshd",
        "package",
        "service",
        "account",
        "mount_option",
        "firewall",
        "kernel_module",
        "login_defs",
        "auditd",
        "cron_permissions",
        "world_writable",
        "listening_port",
        "password_quality",
    }
    assert required <= CHECK_TYPES


def test_parameter_validation_is_actionable() -> None:
    assert "unknown check type" in validate_check("missing", {})[0]
    errors = validate_check("file_exists", {"path": "/etc/x", "bogus": 1})
    assert any("unknown parameter" in error for error in errors)
    assert any("missing required parameter" in error for error in validate_check("sysctl", {}))
    assert any(
        "must be one of" in error
        for error in validate_check("service", {"name": "ssh", "state": "maybe"})
    )
