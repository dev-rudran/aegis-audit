"""Account, authentication policy, and cron permission checks."""

from __future__ import annotations

import stat as stat_module
from datetime import date, datetime, timezone
from typing import Any

from aegis.checks.base import CheckContext, ParamReader, evaluate_scalar
from aegis.models import CheckResult, Rule
from aegis.util.fs import format_mode, parse_mode
from aegis.util.shell import (
    GroupAccount,
    ShadowEntry,
    UserAccount,
    is_system_uid,
    parse_group,
    parse_passwd,
    parse_shadow,
)
from aegis.util.text import parse_assignments

ALLOWED_ACCOUNT = {"kind", "max_days", "max_mode"}
ALLOWED_LOGIN_DEFS = {"key", "path", "exact", "allowed", "min", "max", "requires_bits", "missing"}
ALLOWED_PASSWORD_QUALITY = ALLOWED_LOGIN_DEFS
ALLOWED_CRON = {"kind", "path", "max_mode"}

ACCOUNT_KINDS = (
    "uid_zero_unique",
    "empty_password",
    "shadowed_passwords",
    "root_shell_valid",
    "system_accounts_locked",
    "system_accounts_nologin",
    "duplicate_uid",
    "duplicate_gid",
    "duplicate_user",
    "duplicate_group",
    "home_exists",
    "home_permissions",
    "home_owner",
    "group_membership",
    "password_expiry",
    "inactive_lock",
    "last_change_past",
)

NOLOGIN_SHELLS = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/bin/sync",
    "/usr/bin/sync",
    "/bin/true",
    "/usr/bin/true",
}

CRON_PATHS: tuple[tuple[str, int], ...] = (
    ("/etc/crontab", 0o600),
    ("/etc/cron.d", 0o700),
    ("/etc/cron.hourly", 0o700),
    ("/etc/cron.daily", 0o700),
    ("/etc/cron.weekly", 0o700),
    ("/etc/cron.monthly", 0o700),
)


def validate_account(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_ACCOUNT)
    reader.str("kind", required=True, choices=ACCOUNT_KINDS)
    reader.int("max_days", default=365, minimum=1, maximum=99999)
    reader.mode("max_mode", default="0750")
    return reader.finish()


def _users(ctx: CheckContext) -> list[UserAccount] | None:
    text = ctx.fs.read_text("/etc/passwd")
    if text is None:
        return None
    return parse_passwd(text)


def _shadow(ctx: CheckContext) -> list[ShadowEntry] | None:
    text = ctx.fs.read_text("/etc/shadow")
    if text is None:
        return None
    return parse_shadow(text)


def _groups(ctx: CheckContext) -> list[GroupAccount] | None:
    text = ctx.fs.read_text("/etc/group")
    if text is None:
        return None
    return parse_group(text)


def _login_users(users: list[UserAccount]) -> list[UserAccount]:
    return [
        account
        for account in users
        if (account.uid == 0 or account.uid >= 1000) and account.shell not in NOLOGIN_SHELLS
    ]


def _duplicates(values: list[Any]) -> dict[Any, int]:
    counts: dict[Any, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return {value: count for value, count in counts.items() if count > 1}


def _result_failures(
    failures: list[str], message: str, *, path: str, **evidence: Any
) -> CheckResult:
    detail = ", ".join(failures[:10])
    if len(failures) > 10:
        detail += f" (+{len(failures) - 10} more)"
    return CheckResult.failed(f"{message}: {detail}", path=path, failures=failures[:50], **evidence)


def run_account(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_ACCOUNT)
    kind = reader.str("kind", required=True, choices=ACCOUNT_KINDS)
    max_days = reader.int("max_days", default=365, minimum=1, maximum=99999)
    max_mode = reader.mode("max_mode", default="0750")
    if kind is None or max_days is None or max_mode is None:
        return CheckResult.error("invalid rule parameters")
    users = _users(ctx)
    if users is None:
        return CheckResult.not_applicable("/etc/passwd is missing", path="/etc/passwd")
    shadow_entries = _shadow(ctx)
    groups = _groups(ctx)
    shadow_by_name = {entry.name: entry for entry in shadow_entries or []}

    if kind == "uid_zero_unique":
        roots = [account for account in users if account.uid == 0]
        names = [account.name for account in roots]
        if names == ["root"]:
            return CheckResult.passed("root is the only UID 0 account", path="/etc/passwd")
        if "root" not in names:
            return CheckResult.failed(
                "no account named root has UID 0", path="/etc/passwd", uid_zero_accounts=names
            )
        return CheckResult.failed(
            f"multiple UID 0 accounts exist: {', '.join(names)}",
            path="/etc/passwd",
            uid_zero_accounts=names,
        )

    if kind == "empty_password":
        empty: list[str] = []
        for account in users:
            # Compare against an empty field; this is not a credential literal.
            if account.password == "":  # nosec B105
                empty.append(account.name)
                continue
            shadow = shadow_by_name.get(account.name)
            if shadow is not None and shadow.password == "":  # nosec B105
                empty.append(account.name)
        if empty:
            return _result_failures(
                empty, "accounts with empty password fields", path="/etc/shadow"
            )
        return CheckResult.passed("no accounts have empty password fields", path="/etc/shadow")

    if kind == "shadowed_passwords":
        unshadowed = [account.name for account in users if account.password not in ("x", "X")]
        if unshadowed:
            return _result_failures(
                unshadowed, "accounts not using shadowed passwords", path="/etc/passwd"
            )
        return CheckResult.passed("all accounts use shadowed passwords", path="/etc/passwd")

    if kind == "root_shell_valid":
        root = next((account for account in users if account.name == "root"), None)
        if root is None:
            return CheckResult.failed(
                "root account is missing from /etc/passwd", path="/etc/passwd"
            )
        if not root.shell.startswith("/"):
            return CheckResult.failed(
                f"root shell {root.shell!r} is not an absolute path", path="/etc/passwd"
            )
        if root.shell in NOLOGIN_SHELLS:
            return CheckResult.failed(
                f"root shell {root.shell!r} is not a usable login shell", path="/etc/passwd"
            )
        shells_text = ctx.fs.read_text("/etc/shells", default="") or ""
        listed = {
            line.strip()
            for line in shells_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        if listed and root.shell not in listed:
            return CheckResult.failed(
                f"root shell {root.shell!r} is not listed in /etc/shells",
                path="/etc/passwd",
                # Report evidence only; no subprocess is involved.
                shell=root.shell,  # nosec B604
            )
        return CheckResult.passed(
            f"root has a valid login shell ({root.shell})",
            path="/etc/passwd",
            shell=root.shell,  # nosec B604
        )

    if kind in ("system_accounts_locked", "system_accounts_nologin"):
        candidates = [account for account in users if is_system_uid(account.uid)]
        failures: list[str] = []
        for account in candidates:
            if kind == "system_accounts_nologin":
                if account.shell not in NOLOGIN_SHELLS:
                    failures.append(f"{account.name} ({account.shell})")
                continue
            shadow = shadow_by_name.get(account.name)
            if shadow is None:
                failures.append(f"{account.name} (no shadow entry)")
            elif not shadow.password.startswith(("!", "*")):
                failures.append(account.name)
        if failures:
            label = (
                "system accounts with login shells"
                if kind == "system_accounts_nologin"
                else "system accounts with unlocked passwords"
            )
            return _result_failures(failures, label, path="/etc/passwd")
        label = (
            "all system accounts use nologin/false shells"
            if kind == "system_accounts_nologin"
            else "all system accounts are locked"
        )
        return CheckResult.passed(label, path="/etc/passwd")

    if kind == "duplicate_uid":
        duplicates = _duplicates([account.uid for account in users])
        if duplicates:
            detail = [f"UID {uid} used {count} times" for uid, count in duplicates.items()]
            return _result_failures(detail, "duplicate UIDs", path="/etc/passwd")
        return CheckResult.passed("UIDs are unique", path="/etc/passwd")

    if kind == "duplicate_user":
        duplicates = _duplicates([account.name for account in users])
        if duplicates:
            return _result_failures(list(duplicates), "duplicate user names", path="/etc/passwd")
        return CheckResult.passed("user names are unique", path="/etc/passwd")

    if groups is None:
        return CheckResult.not_applicable("/etc/group is missing", path="/etc/group")

    if kind == "duplicate_gid":
        duplicates = _duplicates([group.gid for group in groups])
        if duplicates:
            detail = [f"GID {gid} used {count} times" for gid, count in duplicates.items()]
            return _result_failures(detail, "duplicate GIDs", path="/etc/group")
        return CheckResult.passed("GIDs are unique", path="/etc/group")

    if kind == "duplicate_group":
        duplicates = _duplicates([group.name for group in groups])
        if duplicates:
            return _result_failures(list(duplicates), "duplicate group names", path="/etc/group")
        return CheckResult.passed("group names are unique", path="/etc/group")

    if kind == "group_membership":
        gids = {group.gid for group in groups}
        orphans = [
            f"{account.name} (gid {account.gid})" for account in users if account.gid not in gids
        ]
        if orphans:
            return _result_failures(
                orphans, "users with missing primary groups", path="/etc/passwd"
            )
        return CheckResult.passed("all primary GIDs exist in /etc/group", path="/etc/group")

    if kind in ("home_exists", "home_permissions", "home_owner"):
        failures: list[str] = []
        checked = 0
        for account in _login_users(users):
            home = account.home
            if not home or len(home) <= 1:
                failures.append(f"{account.name} (invalid home {home!r})")
                continue
            try:
                exists = ctx.fs.exists(home)
            except ValueError as exc:
                failures.append(f"{account.name} ({exc})")
                continue
            if not exists:
                failures.append(f"{account.name} ({home} missing)")
                continue
            checked += 1
            if kind == "home_exists":
                continue
            try:
                info = ctx.fs.stat(home)
            except (OSError, ValueError) as exc:
                failures.append(f"{account.name} ({exc})")
                continue
            if kind == "home_permissions":
                mode = stat_module.S_IMODE(info.st_mode)
                if mode & ~max_mode:
                    failures.append(
                        f"{account.name} ({format_mode(mode)} > {format_mode(max_mode)})"
                    )
            elif kind == "home_owner" and (
                info.st_uid != account.uid or info.st_gid != account.gid
            ):
                failures.append(
                    f"{account.name} (owned {info.st_uid}:{info.st_gid}, "
                    f"expected {account.uid}:{account.gid})"
                )
        if kind == "home_exists" and not failures:
            return CheckResult.passed(
                f"all {checked} login user home directories exist", path="/home", checked=checked
            )
        if failures:
            return _result_failures(failures, f"home directory {kind} failures", path="/home")
        return CheckResult.passed(
            f"home directory {kind} checks passed for {checked} accounts",
            path="/home",
            checked=checked,
        )

    if shadow_entries is None:
        return CheckResult.not_applicable("/etc/shadow is missing", path="/etc/shadow")

    if kind == "password_expiry":
        failures: list[str] = []
        for account in _login_users(users):
            shadow = shadow_by_name.get(account.name)
            if shadow is None:
                failures.append(f"{account.name} (no shadow entry)")
                continue
            if shadow.max_days is None or shadow.max_days > max_days:
                failures.append(f"{account.name} (PASS_MAX_DAYS={shadow.max_days})")
            elif shadow.warn_days is None or shadow.warn_days < 7:
                failures.append(f"{account.name} (PASS_WARN_AGE={shadow.warn_days})")
            elif shadow.min_days is None or shadow.min_days < 1:
                failures.append(f"{account.name} (PASS_MIN_DAYS={shadow.min_days})")
        if failures:
            return _result_failures(
                failures, f"password aging requirements (max {max_days} days)", path="/etc/shadow"
            )
        return CheckResult.passed(
            f"password aging is configured for all login users (max {max_days} days)",
            path="/etc/shadow",
        )

    if kind == "inactive_lock":
        failures = []
        for account in _login_users(users):
            shadow = shadow_by_name.get(account.name)
            if shadow is None:
                failures.append(f"{account.name} (no shadow entry)")
            elif (
                shadow.inactive_days is None
                or shadow.inactive_days <= 0
                or shadow.inactive_days > max_days
            ):
                failures.append(f"{account.name} (inactive={shadow.inactive_days})")
        if failures:
            return _result_failures(
                failures, f"inactive account lockout (max {max_days} days)", path="/etc/shadow"
            )
        return CheckResult.passed(
            f"inactive lock is set to {max_days} days or less for all login users",
            path="/etc/shadow",
        )

    if kind == "last_change_past":
        today = datetime.now(timezone.utc).date()
        epoch = date(1970, 1, 1)
        failures = []
        for account in _login_users(users):
            shadow = shadow_by_name.get(account.name)
            if shadow is None or shadow.last_change is None:
                failures.append(f"{account.name} (no last-change data)")
                continue
            if shadow.last_change == 0:
                continue
            try:
                changed = epoch.fromordinal(epoch.toordinal() + shadow.last_change)
            except (ValueError, OverflowError):
                failures.append(f"{account.name} (invalid last-change value)")
                continue
            if changed > today:
                failures.append(
                    f"{account.name} (last change {changed.isoformat()} is in the future)"
                )
        if failures:
            return _result_failures(
                failures, "password change dates in the future", path="/etc/shadow"
            )
        return CheckResult.passed("all password change dates are in the past", path="/etc/shadow")

    return CheckResult.error(f"unsupported account kind: {kind}")


def validate_login_defs(params: dict[str, Any]) -> list[str]:
    return _validate_key_constraint(params, ALLOWED_LOGIN_DEFS, default_path="/etc/login.defs")


def validate_password_quality(params: dict[str, Any]) -> list[str]:
    return _validate_key_constraint(
        params, ALLOWED_PASSWORD_QUALITY, default_path="/etc/security/pwquality.conf"
    )


def _validate_key_constraint(
    params: dict[str, Any], allowed: set[str], *, default_path: str
) -> list[str]:
    reader = ParamReader(params, allowed)
    reader.str("key", required=True)
    reader.str("path", default=default_path)
    reader.str("exact")
    reader.list("allowed", default=(), item_type=str)
    reader.int("min")
    reader.int("max")
    reader.mode("requires_bits")
    reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    if not any(key in params for key in ("exact", "allowed", "min", "max", "requires_bits")):
        reader.errors.append(
            "at least one of exact, allowed, min, max, or requires_bits is required"
        )
    return reader.finish()


def _run_key_constraint(
    rule: Rule,
    ctx: CheckContext,
    *,
    allowed: set[str],
    default_path: str,
    label: str,
) -> CheckResult:
    reader = ParamReader(rule.params, allowed)
    key = reader.str("key", required=True)
    path = reader.str("path", default=default_path) or default_path
    exact = reader.str("exact")
    allowed_values = reader.list("allowed", default=(), item_type=str)
    minimum = reader.int("min")
    maximum = reader.int("max")
    required_bits = reader.mode("requires_bits")
    missing = reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    if key is None or missing is None:
        return CheckResult.error("invalid rule parameters")
    display = ctx.fs.display(path)
    text = ctx.fs.read_text(path)
    if text is None:
        if missing == "not_applicable":
            return CheckResult.not_applicable(f"{display} is missing", path=display)
        return CheckResult.failed(f"{display} is missing; {key} is not configured", path=display)

    assignments = parse_assignments(text)
    actual = assignments.get(key.lower())
    evidence: dict[str, Any] = {
        "key": key,
        "actual": actual,
        "exact": exact,
        "allowed": allowed_values,
        "min": minimum,
        "max": maximum,
        "requires_bits": format_mode(required_bits) if required_bits is not None else None,
        "source": display,
    }
    if actual is None:
        if missing == "not_applicable":
            return CheckResult.not_applicable(f"{key} is not set in {display}", path=display)
        return CheckResult.failed(f"{key} is not configured in {display}", path=display, **evidence)

    if required_bits is not None:
        parsed = parse_mode(actual) if _looks_octal(actual) else None
        compliant = parsed is not None and (parsed & required_bits) == required_bits
        requirement = f"must include bits {format_mode(required_bits)}"
        if compliant:
            return CheckResult.passed(
                f"{key}={actual} satisfies {requirement} in {display}", path=display, **evidence
            )
        return CheckResult.failed(
            f"{key}={actual} does not satisfy {requirement} in {display}",
            path=display,
            **evidence,
        )

    compliant, requirement = evaluate_scalar(
        actual, allowed=allowed_values or None, exact=exact, minimum=minimum, maximum=maximum
    )
    if compliant:
        return CheckResult.passed(
            f"{label} {key}={actual} is compliant ({requirement})", path=display, **evidence
        )
    return CheckResult.failed(
        f"{label} {key}={actual} violates requirement {requirement}", path=display, **evidence
    )


def _looks_octal(value: str) -> bool:
    text = value.strip().lower().removeprefix("0o")
    return bool(text) and all(char in "01234567" for char in text)


def run_login_defs(rule: Rule, ctx: CheckContext) -> CheckResult:
    return _run_key_constraint(
        rule,
        ctx,
        allowed=ALLOWED_LOGIN_DEFS,
        default_path="/etc/login.defs",
        label="login.defs",
    )


def run_password_quality(rule: Rule, ctx: CheckContext) -> CheckResult:
    return _run_key_constraint(
        rule,
        ctx,
        allowed=ALLOWED_PASSWORD_QUALITY,
        default_path="/etc/security/pwquality.conf",
        label="pwquality",
    )


def validate_cron_permissions(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_CRON)
    kind = reader.str("kind", default="permissions", choices=("permissions", "restricted"))
    reader.str("path")
    reader.mode("max_mode")
    if kind == "permissions" and "path" in params and "max_mode" not in params:
        reader.errors.append("max_mode is required when path is set")
    return reader.finish()


def run_cron_permissions(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_CRON)
    kind = reader.str("kind", default="permissions", choices=("permissions", "restricted"))
    custom_path = reader.str("path")
    max_mode = reader.mode("max_mode")
    if kind is None:
        return CheckResult.error("invalid rule parameters")
    if kind == "restricted":
        problems = _check_cron_restrictions(ctx)
        if problems:
            return CheckResult.failed(
                "cron/at use is not restricted: " + "; ".join(problems),
                path="/etc/cron.allow",
                problems=problems,
            )
        return CheckResult.passed(
            "cron and at are restricted to explicit allow lists", path="/etc/cron.allow"
        )

    targets: list[tuple[str, int]]
    if custom_path:
        if max_mode is None:
            return CheckResult.error("max_mode is required with a custom path")
        targets = [(custom_path, max_mode)]
    else:
        targets = list(CRON_PATHS)
    violations: list[dict[str, Any]] = []
    checked = 0
    for path, allowed_mode in targets:
        display = ctx.fs.display(path)
        try:
            info = ctx.fs.stat(path)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            return CheckResult.error(str(exc), path=display)
        checked += 1
        actual = stat_module.S_IMODE(info.st_mode)
        if actual & ~allowed_mode:
            violations.append(
                {
                    "path": display,
                    "mode": format_mode(actual),
                    "allowed_mode": format_mode(allowed_mode),
                    "uid": info.st_uid,
                }
            )
    if not checked:
        return CheckResult.not_applicable("no cron configuration files exist", path="/etc")
    if violations:
        detail = ", ".join(f"{item['path']} ({item['mode']})" for item in violations[:5])
        return CheckResult.failed(
            f"cron permissions are too permissive: {detail}",
            path=violations[0]["path"],
            violations=violations,
        )
    return CheckResult.passed(
        f"cron configuration permissions are restrictive ({checked} paths checked)",
        path="/etc",
        checked=checked,
    )


def _check_cron_restrictions(ctx: CheckContext) -> list[str]:
    problems: list[str] = []
    cron_allow = ctx.fs.exists("/etc/cron.allow")
    cron_deny = ctx.fs.exists("/etc/cron.deny")
    at_allow = ctx.fs.exists("/etc/at.allow")
    at_deny = ctx.fs.exists("/etc/at.deny")
    if not cron_allow:
        problems.append("/etc/cron.allow does not exist")
    if cron_deny:
        problems.append("/etc/cron.deny exists")
    if not at_allow:
        problems.append("/etc/at.allow does not exist")
    if at_deny:
        problems.append("/etc/at.deny exists")
    return problems


def _shadow_str(entry: ShadowEntry) -> str:
    return f"{entry.name}:{entry.password}"


__all__ = [
    "run_account",
    "run_cron_permissions",
    "run_login_defs",
    "run_password_quality",
    "validate_account",
    "validate_cron_permissions",
    "validate_login_defs",
    "validate_password_quality",
]
