"""Checks for sysctl values, kernel modules, systemd services, and packages."""

from __future__ import annotations

import shutil

# The rpm query below uses a fixed argv and never invokes a shell.
import subprocess  # nosec B404
from typing import Any

from aegis.checks.base import CheckContext, ParamReader, service_unit_state
from aegis.models import CheckResult, Rule
from aegis.util.shell import (
    PackageDatabase,
    parse_apk_installed,
    parse_dpkg_status,
)
from aegis.util.text import split_assignment, unquote

ALLOWED_SYSCTL = {"key", "value", "files", "missing"}
ALLOWED_KERNEL_MODULE = {"module", "state", "search_dirs"}
ALLOWED_SERVICE = {"name", "state"}
ALLOWED_PACKAGE = {"name", "state"}

SYSCTL_DIRS_LOW_TO_HIGH = (
    "/usr/lib/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/run/sysctl.d",
    "/etc/sysctl.d",
)
SYSCTL_FINAL_FILE = "/etc/sysctl.conf"


def _normalize_sysctl_key(key: str) -> str:
    return key.strip().lower().replace("/", ".")


def validate_sysctl(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_SYSCTL)
    reader.str("key", required=True)
    value = params.get("value")
    if value is None:
        reader.errors.append("missing required parameter 'value'")
    elif not isinstance(value, (str, list)):
        reader.errors.append("parameter 'value' must be a string or list of strings")
    elif isinstance(value, list) and (
        not value or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        reader.errors.append("parameter 'value' must not contain empty values")
    reader.list("files", default=(), item_type=str)
    reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    return reader.finish()


def _sysctl_assignments(ctx: CheckContext, files: list[str]) -> list[tuple[str, str, str, int]]:
    assignments: list[tuple[str, str, str, int]] = []
    ordered: list[str] = []
    if files:
        ordered = list(files)
    else:
        for directory in SYSCTL_DIRS_LOW_TO_HIGH:
            for path in sorted(ctx.fs.glob(f"{directory}/*.conf")):
                ordered.append(path.relative_to(ctx.fs.root).as_posix())
        ordered.append(SYSCTL_FINAL_FILE)
    for relative in ordered:
        display = ctx.fs.display(relative)
        try:
            text = ctx.fs.read_text(relative)
        except (OSError, ValueError):
            continue
        if text is None:
            continue
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            item = split_assignment(line)
            if item is None:
                continue
            key, value = item
            value = unquote(value)
            if "#" in value:
                value = value.split("#", 1)[0].strip()
            assignments.append((_normalize_sysctl_key(key), value, display, lineno))
    return assignments


def run_sysctl(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_SYSCTL)
    key = reader.str("key", required=True)
    raw_value = rule.params.get("value")
    if isinstance(raw_value, str):
        expected = [raw_value]
    elif isinstance(raw_value, list):
        expected = [str(item) for item in raw_value]
    else:
        expected = []
    files = reader.list("files", default=(), item_type=str)
    missing = reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    if key is None or not expected:
        return CheckResult.error("invalid rule parameters")
    normalized_key = _normalize_sysctl_key(key)
    assignments = _sysctl_assignments(ctx, files)
    matching = [item for item in assignments if item[0] == normalized_key]
    if not matching:
        message = f"sysctl {key} is not configured in any scanned sysctl file"
        if missing == "not_applicable":
            return CheckResult.not_applicable(message, path="/etc")
        return CheckResult.failed(message, path="/etc/sysctl.conf", key=key, expected=expected)
    _, actual, source, lineno = matching[-1]
    accepted = {" ".join(item.strip().lower().split()) for item in expected}
    compliant = " ".join(actual.strip().lower().split()) in accepted
    evidence = {
        "key": key,
        "actual": actual,
        "expected": expected,
        "source": source,
        "line": lineno,
        "assignments_seen": len(matching),
    }
    if compliant:
        return CheckResult.passed(
            f"sysctl {key} is {actual!r} (set in {source}:{lineno})",
            path=source,
            **evidence,
        )
    return CheckResult.failed(
        f"sysctl {key} is {actual!r}, expected {' or '.join(repr(item) for item in expected)}"
        f" (effective value from {source}:{lineno})",
        path=source,
        **evidence,
    )


def validate_kernel_module(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_KERNEL_MODULE)
    reader.str("module", required=True)
    reader.str("state", default="disabled", choices=("disabled", "enabled"))
    reader.list("search_dirs", default=(), item_type=str)
    return reader.finish()


def _module_directives(
    ctx: CheckContext, search_dirs: list[str]
) -> tuple[list[tuple[str, str, str, str, int]], list[tuple[str, int, str]]]:
    directories = search_dirs or [
        "/etc/modprobe.d",
        "/run/modprobe.d",
        "/usr/lib/modprobe.d",
        "/lib/modprobe.d",
    ]
    directives: list[tuple[str, str, str, str, int]] = []
    for directory in directories:
        for path in sorted(ctx.fs.glob(f"{directory}/*.conf")):
            relative = path.relative_to(ctx.fs.root).as_posix()
            display = ctx.fs.display(relative)
            text = ctx.fs.read_text(relative, default="") or ""
            for lineno, raw in enumerate(text.splitlines(), start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                fields = line.split()
                if len(fields) >= 2 and fields[0] in ("install", "blacklist"):
                    command = " ".join(fields[2:]) if len(fields) > 2 else ""
                    directives.append((fields[0], fields[1], command, display, lineno))
    loads: list[tuple[str, int, str]] = []
    for directory in ("/etc/modules-load.d", "/run/modules-load.d", "/usr/lib/modules-load.d"):
        for path in sorted(ctx.fs.glob(f"{directory}/*.conf")):
            relative = path.relative_to(ctx.fs.root).as_posix()
            display = ctx.fs.display(relative)
            text = ctx.fs.read_text(relative, default="") or ""
            for lineno, raw in enumerate(text.splitlines(), start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                name = line.split()[0]
                loads.append((name, lineno, display))
    modules_file = ctx.fs.read_text("/etc/modules", default="") or ""
    for lineno, raw in enumerate(modules_file.splitlines(), start=1):
        line = raw.strip()
        if line and not line.startswith("#"):
            loads.append((line.split()[0], lineno, "/etc/modules"))
    return directives, loads


def run_kernel_module(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_KERNEL_MODULE)
    module = reader.str("module", required=True)
    state = reader.str("state", default="disabled", choices=("disabled", "enabled"))
    search_dirs = reader.list("search_dirs", default=(), item_type=str)
    if module is None or state is None:
        return CheckResult.error("invalid rule parameters")
    normalized = module.replace("-", "_")
    directives, loads = _module_directives(ctx, search_dirs)
    relevant = [item for item in directives if item[1].replace("-", "_") == normalized]
    blacklisted = [item for item in relevant if item[0] == "blacklist"]
    install_false = [
        item
        for item in relevant
        if item[0] == "install"
        and any(token in item[2] for token in ("/bin/false", "/usr/bin/false"))
    ]
    explicitly_loaded = [item for item in loads if item[0].replace("-", "_") == normalized]

    disabled = bool(blacklisted) or bool(install_false)
    evidence = {
        "module": module,
        "blacklist": [f"{item[3]}:{item[4]}" for item in blacklisted],
        "install_false": [f"{item[3]}:{item[4]}" for item in install_false],
        "explicitly_loaded": [f"{source}:{lineno}" for _, lineno, source in explicitly_loaded],
    }
    if state == "disabled":
        if disabled and not explicitly_loaded:
            where = evidence["install_false"] or evidence["blacklist"]
            return CheckResult.passed(
                f"kernel module {module} is disabled ({', '.join(where)})",
                path=where[0].split(":", 1)[0],
                **evidence,
            )
        if explicitly_loaded:
            return CheckResult.failed(
                f"kernel module {module} is explicitly loaded by "
                f"{explicitly_loaded[0][2]}:{explicitly_loaded[0][1]}",
                path=explicitly_loaded[0][2],
                **evidence,
            )
        return CheckResult.failed(
            f"kernel module {module} is not disabled in modprobe.d",
            path="/etc/modprobe.d",
            **evidence,
        )
    if explicitly_loaded and not disabled:
        return CheckResult.passed(
            f"kernel module {module} is loaded at boot",
            path=explicitly_loaded[0][2],
            **evidence,
        )
    return CheckResult.failed(
        f"kernel module {module} is not scheduled to load",
        path="/etc/modules-load.d",
        **evidence,
    )


def validate_service(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_SERVICE)
    reader.str("name", required=True)
    reader.str("state", required=True, choices=("enabled", "disabled"))
    return reader.finish()


def run_service(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_SERVICE)
    name = reader.str("name", required=True)
    state = reader.str("state", required=True, choices=("enabled", "disabled"))
    if name is None or state is None:
        return CheckResult.error("invalid rule parameters")
    enabled, detail = service_unit_state(ctx, name)
    unit = name if "." in name else f"{name}.service"
    if state == "enabled":
        if enabled:
            return CheckResult.passed(f"{unit} is enabled ({detail})", path=detail, unit=unit)
        return CheckResult.failed(f"{unit} is not enabled ({detail})", unit=unit)
    if enabled:
        return CheckResult.failed(f"{unit} must be disabled but is enabled ({detail})", unit=unit)
    return CheckResult.passed(f"{unit} is disabled ({detail})", unit=unit)


def validate_package(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_PACKAGE)
    name = params.get("name")
    if isinstance(name, list):
        if not name or not all(isinstance(item, str) and item.strip() for item in name):
            reader.errors.append("parameter 'name' must not contain empty values")
    else:
        reader.str("name", required=True)
    reader.str("state", required=True, choices=("installed", "removed"))
    return reader.finish()


def _load_package_db(ctx: CheckContext) -> PackageDatabase:
    cached = ctx.cache.get("package_database")
    if isinstance(cached, PackageDatabase):
        return cached
    dpkg_status = "/var/lib/dpkg/status"
    text = ctx.fs.read_text(dpkg_status, default=None)
    if text is not None:
        db = parse_dpkg_status(text)
        ctx.cache["package_database"] = db
        return db
    apk_status = "/lib/apk/db/installed"
    text = ctx.fs.read_text(apk_status, default=None)
    if text is not None:
        db = parse_apk_installed(text)
        ctx.cache["package_database"] = db
        return db
    rpm_dir = "/var/lib/rpm"
    if ctx.fs.exists(rpm_dir):
        db = _query_rpm(ctx)
        ctx.cache["package_database"] = db
        return db
    db = PackageDatabase(source="none", available=False)
    ctx.cache["package_database"] = db
    return db


def _query_rpm(ctx: CheckContext) -> PackageDatabase:
    rpm_binary = shutil.which("rpm")
    if rpm_binary is None:
        return PackageDatabase(source="rpm", available=False)
    command = [
        rpm_binary,
        "--root",
        str(ctx.fs.root),
        "-qa",
        "--qf",
        "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
    ]
    try:
        # Fixed argv, no shell, bounded output, explicit timeout.
        completed = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return PackageDatabase(source="rpm", available=False)
    if completed.returncode != 0:
        return PackageDatabase(source="rpm", available=False)
    db = PackageDatabase(source="rpm")
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        if not fields or not fields[0]:
            continue
        db.packages[fields[0]] = _rpm_record(fields)
    return db


def _rpm_record(fields: list[str]):
    from aegis.util.shell import PackageRecord

    version = fields[1] if len(fields) > 1 else ""
    arch = fields[2] if len(fields) > 2 else ""
    return PackageRecord(name=fields[0], version=version, status="installed", architecture=arch)


def run_package(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_PACKAGE)
    raw_name = rule.params.get("name")
    if isinstance(raw_name, list):
        names = [str(item).strip() for item in raw_name if str(item).strip()]
    elif isinstance(raw_name, str) and raw_name.strip():
        names = [raw_name.strip()]
    else:
        names = []
    state = reader.str("state", required=True, choices=("installed", "removed"))
    if not names or state is None:
        return CheckResult.error("invalid rule parameters")
    db = _load_package_db(ctx)
    if not db.available:
        return CheckResult.not_applicable(
            f"no supported package database found (dpkg, apk, or rpm) under {ctx.fs.root}",
            path="/var/lib",
            database=db.source,
        )
    installed = [name for name in names if db.is_installed(name)]
    versions = {
        name: (db.packages[name].version if name in db.packages else None) for name in names
    }
    evidence = {
        "package": names,
        "database": db.source,
        "installed": installed,
        "version": versions,
    }
    if state == "removed":
        if installed:
            detail = ", ".join(
                f"{name} ({versions.get(name) or 'unknown version'})" for name in installed
            )
            return CheckResult.failed(
                f"package(s) installed that must be removed: {detail}",
                path="/var/lib/dpkg/status" if db.source == "dpkg" else f"/var/lib/{db.source}",
                **evidence,
            )
        return CheckResult.passed(
            f"none of {', '.join(names)} are installed", path="/var/lib", **evidence
        )
    if installed:
        return CheckResult.passed(
            f"package {installed[0]} is installed "
            f"({versions.get(installed[0]) or 'unknown version'})",
            path="/var/lib",
            **evidence,
        )
    return CheckResult.failed(
        f"none of {', '.join(names)} are installed", path="/var/lib", **evidence
    )


__all__ = [
    "run_kernel_module",
    "run_package",
    "run_service",
    "run_sysctl",
    "validate_kernel_module",
    "validate_package",
    "validate_service",
    "validate_sysctl",
]
