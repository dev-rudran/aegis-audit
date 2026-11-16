"""auditd installation, service, configuration, and kernel command line checks."""

from __future__ import annotations

from typing import Any

from aegis.checks.base import CheckContext, ParamReader, evaluate_scalar, service_unit_state
from aegis.models import CheckResult, Rule
from aegis.util.text import parse_assignments

ALLOWED_AUDITD = {
    "kind",
    "key",
    "path",
    "exact",
    "allowed",
    "min",
    "max",
    "missing",
    "state",
}
AUDITD_KINDS = ("config", "service", "installed", "grub")


def validate_auditd(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_AUDITD)
    kind = reader.str("kind", default="config", choices=AUDITD_KINDS)
    reader.str("key")
    reader.str("path", default="/etc/audit/auditd.conf")
    reader.str("exact")
    reader.list("allowed", default=(), item_type=str)
    reader.int("min")
    reader.int("max")
    reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    reader.str("state", default="enabled", choices=("enabled", "disabled"))
    if kind == "config":
        if "key" not in params:
            reader.errors.append("key is required when kind is 'config'")
        if not any(key in params for key in ("exact", "allowed", "min", "max")):
            reader.errors.append("one of exact, allowed, min, or max is required for kind 'config'")
    return reader.finish()


def run_auditd(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_AUDITD)
    kind = reader.str("kind", default="config", choices=AUDITD_KINDS)
    key = reader.str("key")
    path = reader.str("path", default="/etc/audit/auditd.conf") or "/etc/audit/auditd.conf"
    exact = reader.str("exact")
    allowed = reader.list("allowed", default=(), item_type=str)
    minimum = reader.int("min")
    maximum = reader.int("max")
    missing = reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    state = reader.str("state", default="enabled", choices=("enabled", "disabled"))
    if kind is None or missing is None or state is None:
        return CheckResult.error("invalid rule parameters")

    if kind == "installed":
        if ctx.fs.exists("/usr/sbin/auditd") or ctx.fs.exists("/etc/audit"):
            return CheckResult.passed("auditd is installed", path="/usr/sbin/auditd")
        return CheckResult.failed("auditd is not installed", path="/usr/sbin/auditd")

    if kind == "service":
        enabled, detail = service_unit_state(ctx, "auditd")
        if state == "enabled":
            if enabled:
                return CheckResult.passed(f"auditd is enabled ({detail})", path=detail)
            return CheckResult.failed(
                f"auditd is not enabled ({detail})", path="/etc/systemd/system"
            )
        if enabled:
            return CheckResult.failed(f"auditd is enabled but must be disabled ({detail})")
        return CheckResult.passed(f"auditd is disabled ({detail})")

    if kind == "grub":
        locations = ["/etc/default/grub"]
        for path_obj in sorted(ctx.fs.glob("/etc/default/grub.d/*.cfg")):
            locations.append(path_obj.relative_to(ctx.fs.root).as_posix())
        configured = False
        source = None
        for location in locations:
            text = ctx.fs.read_text(location)
            if text is None:
                continue
            config = parse_assignments(text, key_lower=False)
            value = config.get("GRUB_CMDLINE_LINUX", "")
            tokens = value.split()
            if "audit=1" in tokens or "audit=1" in text.replace('"', " ").split():
                configured = True
                source = ctx.fs.display(location)
                break
        if configured:
            return CheckResult.passed(f"kernel audit is enabled at boot ({source})", path=source)
        return CheckResult.failed(
            "kernel command line does not set audit=1", path="/etc/default/grub"
        )

    if key is None:
        return CheckResult.error("key is required for auditd config checks")
    display = ctx.fs.display(path)
    text = ctx.fs.read_text(path)
    if text is None:
        if missing == "not_applicable":
            return CheckResult.not_applicable(f"{display} is missing", path=display)
        return CheckResult.failed(f"{display} is missing", path=display)
    config = parse_assignments(text)
    actual = config.get(key.lower())
    evidence = {
        "key": key,
        "actual": actual,
        "exact": exact,
        "allowed": allowed,
        "min": minimum,
        "max": maximum,
        "source": display,
    }
    if actual is None:
        if missing == "not_applicable":
            return CheckResult.not_applicable(f"{key} is not set in {display}", path=display)
        return CheckResult.failed(f"{key} is not set in {display}", path=display, **evidence)
    compliant, requirement = evaluate_scalar(
        actual, allowed=allowed or None, exact=exact, minimum=minimum, maximum=maximum
    )
    if compliant:
        return CheckResult.passed(
            f"auditd {key}={actual} is compliant ({requirement})", path=display, **evidence
        )
    return CheckResult.failed(
        f"auditd {key}={actual} violates requirement {requirement}", path=display, **evidence
    )
