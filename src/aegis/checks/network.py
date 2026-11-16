"""Network-facing checks: fstab options, host firewall, listening sockets."""

from __future__ import annotations

import re
from typing import Any

from aegis.checks.base import CheckContext, ParamReader, service_unit_state
from aegis.models import CheckResult, Rule
from aegis.util.shell import parse_fstab, parse_proc_net_tcp
from aegis.util.text import parse_assignments, parse_bool

ALLOWED_MOUNT_OPTION = {"mountpoint", "options", "missing", "fstype", "fstab"}
ALLOWED_FIREWALL = {"engine", "setting"}
ALLOWED_LISTENING = {"mode", "ports", "ignore_loopback"}

ENGINES = ("ufw", "firewalld", "nftables", "any")
SETTINGS = ("installed", "enabled", "default_incoming", "policy")


def validate_mount_option(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_MOUNT_OPTION)
    reader.str("mountpoint", required=True)
    reader.list("options", required=True, item_type=str)
    reader.str("missing", default="not_applicable", choices=("not_applicable", "fail"))
    reader.str("fstype")
    reader.str("fstab", default="/etc/fstab")
    return reader.finish()


def run_mount_option(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_MOUNT_OPTION)
    mountpoint = reader.str("mountpoint", required=True)
    required = reader.list("options", required=True, item_type=str)
    missing = reader.str("missing", default="not_applicable", choices=("not_applicable", "fail"))
    fstype = reader.str("fstype")
    fstab_path = reader.str("fstab", default="/etc/fstab")
    if mountpoint is None or fstab_path is None or missing is None or not required:
        return CheckResult.error("invalid rule parameters")
    display = ctx.fs.display(fstab_path)
    text = ctx.fs.read_text(fstab_path)
    if text is None:
        if missing == "fail":
            return CheckResult.failed(f"{display} is missing", path=display)
        return CheckResult.not_applicable(f"{display} is missing", path=display)
    entries = parse_fstab(text)
    matching = [entry for entry in entries if entry.mountpoint == mountpoint]
    if fstype:
        matching = [entry for entry in matching if entry.fstype == fstype]
    if not matching:
        message = f"mount point {mountpoint} is not present in {display}"
        if missing == "fail":
            return CheckResult.failed(message, path=display, mountpoint=mountpoint)
        return CheckResult.not_applicable(message, path=display, mountpoint=mountpoint)
    problems: list[str] = []
    for entry in matching:
        absent = [option for option in required if option not in entry.options]
        if absent:
            problems.append(
                f"line {entry.line} ({entry.device} {entry.fstype}) lacks {', '.join(absent)}"
            )
    evidence = {
        "mountpoint": mountpoint,
        "required_options": required,
        "entries": [
            {"line": entry.line, "device": entry.device, "options": list(entry.options)}
            for entry in matching
        ],
    }
    if problems:
        return CheckResult.failed(
            f"{mountpoint} mount options are incomplete: {'; '.join(problems)}",
            path=display,
            **evidence,
        )
    return CheckResult.passed(
        f"{mountpoint} has required mount options: {', '.join(required)}",
        path=display,
        **evidence,
    )


def validate_firewall(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_FIREWALL)
    engine = reader.str("engine", required=True, choices=ENGINES)
    setting = reader.str("setting", default="enabled", choices=SETTINGS)
    if engine == "nftables" and setting == "enabled":
        pass
    elif engine in ("ufw", "firewalld") and setting == "policy":
        reader.errors.append("setting 'policy' only applies to the nftables engine")
    return reader.finish()


def _ufw_installed(ctx: CheckContext) -> tuple[bool, str]:
    if ctx.fs.exists("/usr/sbin/ufw") or ctx.fs.exists("/etc/ufw"):
        return True, "ufw files are present"
    return False, "ufw is not installed"


def _ufw_enabled(ctx: CheckContext) -> tuple[bool, str]:
    text = ctx.fs.read_text("/etc/ufw/ufw.conf")
    if text is None:
        return False, "/etc/ufw/ufw.conf is missing"
    config = parse_assignments(text)
    value = config.get("enabled")
    return parse_bool(value) is True, f"ENABLED={value!r} in /etc/ufw/ufw.conf"


def _ufw_default_incoming(ctx: CheckContext) -> tuple[bool, str]:
    text = ctx.fs.read_text("/etc/default/ufw")
    if text is None:
        return False, "/etc/default/ufw is missing"
    config = parse_assignments(text)
    value = (config.get("default_input_policy") or "").strip().upper()
    return value in ("DROP", "REJECT"), f"DEFAULT_INPUT_POLICY={value!r} in /etc/default/ufw"


def _firewalld_installed(ctx: CheckContext) -> tuple[bool, str]:
    if ctx.fs.exists("/usr/sbin/firewalld") or ctx.fs.exists("/etc/firewalld"):
        return True, "firewalld files are present"
    return False, "firewalld is not installed"


def _firewalld_enabled(ctx: CheckContext) -> tuple[bool, str]:
    enabled, detail = service_unit_state(ctx, "firewalld")
    return enabled, detail


def _firewalld_default_incoming(ctx: CheckContext) -> tuple[bool, str]:
    text = ctx.fs.read_text("/etc/firewalld/firewalld.conf")
    if text is None:
        return False, "/etc/firewalld/firewalld.conf is missing"
    config = parse_assignments(text)
    zone = (config.get("defaultzone") or "").strip().lower()
    # A dedicated zone with a DROP target is also acceptable; inspect zone XML.
    for zone_file in ctx.fs.glob("/etc/firewalld/zones/*.xml"):
        content = ctx.fs.read_text(zone_file.relative_to(ctx.fs.root).as_posix(), default="") or ""
        if re.search(r"<target>\s*(?:DROP|REJECT)\s*</target>", content, re.IGNORECASE):
            return True, f"zone {zone_file.name} uses a DROP/REJECT target"
    return zone in ("drop", "block"), f"DefaultZone={zone!r} in firewalld.conf"


def _nftables_installed(ctx: CheckContext) -> tuple[bool, str]:
    if ctx.fs.exists("/usr/sbin/nft") or ctx.fs.exists("/etc/nftables.conf"):
        return True, "nftables files are present"
    return False, "nftables is not installed"


def _nftables_enabled(ctx: CheckContext) -> tuple[bool, str]:
    enabled, detail = service_unit_state(ctx, "nftables")
    if enabled:
        return True, detail
    content = ctx.fs.read_text("/etc/nftables.conf")
    if content is not None and "table" in content:
        return True, "/etc/nftables.conf defines a ruleset"
    return False, detail


def _nftables_input_policy(ctx: CheckContext) -> tuple[bool, str]:
    content = ctx.fs.read_text("/etc/nftables.conf")
    if content is None:
        return False, "/etc/nftables.conf is missing"
    has_input = re.search(r"hook\s+input", content, re.IGNORECASE) is not None
    has_drop = re.search(
        r"hook\s+input[^{}]*\{[^{}]*?policy\s+(?:drop|reject)", content, re.IGNORECASE | re.DOTALL
    )
    if has_drop is None:
        # Accept a policy declared inside an input chain block over multiple lines.
        has_drop = re.search(
            r"chain\s+\w+\s*\{[^{}]*hook\s+input[^{}]*policy\s+(?:drop|reject)",
            content,
            re.IGNORECASE | re.DOTALL,
        )
    return (
        bool(has_input and has_drop),
        "input hook with drop policy"
        if has_input and has_drop
        else "no input chain with a drop/reject policy",
    )


def run_firewall(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_FIREWALL)
    engine = reader.str("engine", required=True, choices=ENGINES)
    setting = reader.str("setting", default="enabled", choices=SETTINGS)
    if engine is None or setting is None:
        return CheckResult.error("invalid rule parameters")

    checks = {
        "ufw": {
            "installed": _ufw_installed,
            "enabled": _ufw_enabled,
            "default_incoming": _ufw_default_incoming,
        },
        "firewalld": {
            "installed": _firewalld_installed,
            "enabled": _firewalld_enabled,
            "default_incoming": _firewalld_default_incoming,
        },
        "nftables": {
            "installed": _nftables_installed,
            "enabled": _nftables_enabled,
            "policy": _nftables_input_policy,
            "default_incoming": _nftables_input_policy,
        },
    }
    if engine == "any":
        detected: list[str] = []
        if setting == "installed":
            for name, func in (
                ("ufw", _ufw_installed),
                ("firewalld", _firewalld_installed),
                ("nftables", _nftables_installed),
            ):
                ok, detail = func(ctx)
                if ok:
                    detected.append(f"{name}: {detail}")
        elif setting == "enabled":
            for name, func in (
                ("ufw", _ufw_enabled),
                ("firewalld", _firewalld_enabled),
                ("nftables", _nftables_enabled),
            ):
                ok, detail = func(ctx)
                if ok:
                    detected.append(f"{name}: {detail}")
        else:
            for name, func in (
                ("ufw", _ufw_default_incoming),
                ("firewalld", _firewalld_default_incoming),
                ("nftables", _nftables_input_policy),
            ):
                ok, detail = func(ctx)
                if ok:
                    detected.append(f"{name}: {detail}")
        if detected:
            return CheckResult.passed(
                f"at least one host firewall satisfies {setting}: {'; '.join(detected)}",
                path="/etc",
                engines=detected,
            )
        return CheckResult.failed(
            f"no supported host firewall satisfies {setting}", path="/etc", engines=[]
        )

    func = checks[engine].get(setting)
    if func is None:
        return CheckResult.error(f"unsupported firewall setting {setting!r} for {engine}")
    ok, detail = func(ctx)
    if ok:
        return CheckResult.passed(f"{engine} {setting}: {detail}", path="/etc", engine=engine)
    return CheckResult.failed(
        f"{engine} {setting} check failed: {detail}", path="/etc", engine=engine
    )


def validate_listening_port(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_LISTENING)
    reader.str("mode", required=True, choices=("allowed", "denied"))
    ports = reader.list("ports", required=True, item_type=int)
    if any(port < 1 or port > 65535 for port in ports):
        reader.errors.append("ports must be between 1 and 65535")
    reader.bool("ignore_loopback", default=False)
    return reader.finish()


def run_listening_port(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_LISTENING)
    mode = reader.str("mode", required=True, choices=("allowed", "denied"))
    ports = set(reader.list("ports", required=True, item_type=int))
    ignore_loopback = reader.bool("ignore_loopback", default=False)
    if mode is None or not ports:
        return CheckResult.error("invalid rule parameters")
    sockets = []
    found_table = False
    for table, family in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")):
        text = ctx.fs.read_text(table)
        if text is None:
            continue
        found_table = True
        sockets.extend(parse_proc_net_tcp(text, family))
    if not found_table:
        return CheckResult.not_applicable(
            "no /proc/net/tcp or /proc/net/tcp6 in the audit root; "
            "live sockets cannot be inspected",
            path="/proc/net",
        )
    listening = [socket for socket in sockets if socket.listening]
    if ignore_loopback:
        listening = [
            socket
            for socket in listening
            if socket.address not in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
        ]
    rendered = [f"{socket.address}:{socket.port}" for socket in listening]
    if mode == "denied":
        violations = [socket for socket in listening if socket.port in ports]
        evidence = {
            "listening": rendered,
            "denied_ports": sorted(ports),
            "violations": [f"{socket.address}:{socket.port}" for socket in violations],
        }
        if violations:
            detail = ", ".join(evidence["violations"][:10])
            return CheckResult.failed(
                f"forbidden listening ports detected: {detail}", path="/proc/net/tcp", **evidence
            )
        return CheckResult.passed(
            f"none of the denied ports {sorted(ports)} are listening",
            path="/proc/net/tcp",
            **evidence,
        )
    unexpected = [socket for socket in listening if socket.port not in ports]
    evidence = {
        "listening": rendered,
        "allowed_ports": sorted(ports),
        "unexpected": [f"{socket.address}:{socket.port}" for socket in unexpected],
    }
    if unexpected:
        detail = ", ".join(evidence["unexpected"][:10])
        return CheckResult.failed(
            f"unexpected listening ports detected: {detail}", path="/proc/net/tcp", **evidence
        )
    return CheckResult.passed(
        f"all listening ports are in the allowed set {sorted(ports)}",
        path="/proc/net/tcp",
        **evidence,
    )
