#!/usr/bin/env python3
"""Regenerate docs/RULES.md from the bundled rule pack.

The rule pack is the source of truth: this script never invents or edits rule
content, it only renders the YAML that ships in ``src/aegis/rules``.  Run it via
``make docs`` after changing a rule.
"""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "src" / "aegis" / "rules"
OUTPUT = ROOT / "docs" / "RULES.md"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
CATEGORY_ORDER = [
    "SSH",
    "Kernel",
    "Filesystem",
    "Accounts",
    "Logging",
    "Firewall",
    "Packages",
    "Services",
    "Crypto",
]

FIX_TYPES = {
    "file_mode": "Set the mode of an existing file (chmod equivalent, never executed as a shell).",
    "file_content": "Append a line or replace a matching line in a text file.",
    "sshd_set": "Set or replace a single keyword in sshd_config, preserving the rest of the file.",
    "sysctl_set": "Set or replace a key in a sysctl file, preserving comments and formatting.",
}


def load_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.extend(document["rules"])
    return rules


def cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def inline_params(params: dict) -> str:
    rendered = yaml.safe_dump(params, default_flow_style=True, sort_keys=True)
    return rendered.strip().removesuffix("...").strip()


def fix_label(remediation: dict) -> str:
    if remediation.get("safe") and remediation.get("fix"):
        return "`{}`".format(remediation["fix"]["type"])
    return "manual"


def render(rules: list[dict]) -> str:
    rules.sort(key=lambda rule: rule["id"])
    by_category: dict[str, list[dict]] = defaultdict(list)
    for rule in rules:
        by_category[rule["category"]].append(rule)

    severity_counts = Counter(rule["severity"] for rule in rules)
    automated = sum(1 for rule in rules if rule["remediation"].get("safe"))

    lines: list[str] = []
    add = lines.append

    add("# Rule reference")
    add("")
    add(
        f"aegis ships {len(rules)} rules covering the controls that most often decide whether a "
        "Linux host survives an audit. Every rule is plain YAML in `src/aegis/rules/`; "
        "this page is generated from that pack, so edit the YAML and run `make docs` "
        "instead of editing this file."
    )
    add("")
    add("| Property | Value |")
    add("| --- | --- |")
    add(f"| Rules | {len(rules)} |")
    add(f"| Categories | {len(by_category)} |")
    add(f"| Rules with an automated safe fix | {automated} |")
    add(f"| Manual controls | {len(rules) - automated} |")
    add(
        "| Severity mix | {} |".format(
            ", ".join(
                f"{severity_counts[key]} {key}"
                for key in ("critical", "high", "medium", "low")
                if severity_counts[key]
            )
        )
    )
    add("")

    add("## Scoring model")
    add("")
    add(
        "Each evaluated rule contributes its severity weight to the denominator. A "
        "passing rule contributes the same weight to the numerator, so the score is "
        "`100 * passed_weight / evaluated_weight` and not a raw pass rate. Not "
        "applicable rules and suppressed baseline entries are removed from both sides, "
        "which keeps image audits comparable across hosts that legitimately differ."
    )
    add("")
    add("| Severity | Weight | Grade impact |")
    add("| --- | --- | --- |")
    add("| critical | 10 | A single failure costs 10 points of the weighted total |")
    add("| high | 5 | Two failures cost roughly one critical |")
    add("| medium | 2 | Hardening depth and defence in depth |")
    add("| low | 1 | Hygiene and logging quality |")
    add("| info | 0 | Context only, never affects the gate |")
    add("")
    add("| Grade | Minimum score |")
    add("| --- | --- |")
    for grade, floor in (("A", 90), ("B", 80), ("C", 70), ("D", 60), ("F", 0)):
        add(f"| {grade} | {floor} |")
    add("")

    add("## Coverage summary")
    add("")
    add("| Category | Rules | Critical | High | Medium | Low | Automated fixes |")
    add("| --- | --- | --- | --- | --- | --- | --- |")
    ordered = [name for name in CATEGORY_ORDER if name in by_category]
    ordered += [name for name in sorted(by_category) if name not in ordered]
    for category in ordered:
        entries = by_category[category]
        counts = Counter(entry["severity"] for entry in entries)
        fixes = sum(1 for entry in entries if entry["remediation"].get("safe"))
        add(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                category,
                len(entries),
                counts["critical"],
                counts["high"],
                counts["medium"],
                counts["low"],
                fixes,
            )
        )
    add("")

    add("## Rule catalogue")
    add("")
    for category in ordered:
        add(f"### {category}")
        add("")
        add("| ID | Severity | Title | CIS reference | Check | Fix |")
        add("| --- | --- | --- | --- | --- | --- |")
        entries = sorted(
            by_category[category],
            key=lambda rule: (SEVERITY_ORDER.get(rule["severity"], 9), rule["id"]),
        )
        for rule in entries:
            add(
                "| [{id}](#{anchor}) | {severity} | {title} | {cis} | `{check}` | {fix} |".format(
                    id=rule["id"],
                    anchor=rule["id"].lower(),
                    severity=rule["severity"],
                    title=cell(rule["title"]),
                    cis=cell(rule["cis"]),
                    check=rule["check"]["type"],
                    fix=fix_label(rule["remediation"]),
                )
            )
        add("")

    add("## Remediation types")
    add("")
    add(
        "`--remediate` prints the plan and writes nothing. `--apply` executes only the "
        "structured fixes below, never a shell command, and writes a `.aegis.bak` "
        "backup next to each modified file before an atomic replace. Anything labelled "
        "manual requires human judgement, a service restart, or a package operation, "
        "so aegis prints the command and leaves it to you."
    )
    add("")
    add("| Fix type | Behaviour |")
    add("| --- | --- |")
    for fix_type, description in FIX_TYPES.items():
        add(f"| `{fix_type}` | {description} |")
    add("")

    add("## Rule details")
    add("")
    for rule in rules:
        remediation = rule["remediation"]
        add("### {}".format(rule["id"]))
        add("")
        add("**{}**".format(rule["title"]))
        add("")
        add(
            "`{}` | severity `{}` | category {} | {}".format(
                rule["id"], rule["severity"], rule["category"], rule["cis"]
            )
        )
        add("")
        add(cell(rule["description"]))
        add("")
        add("| Field | Value |")
        add("| --- | --- |")
        add("| Check | `{}` |".format(rule["check"]["type"]))
        add("| Parameters | `{}` |".format(cell(inline_params(rule["check"]["params"]))))
        add("| Tags | {} |".format(", ".join(f"`{tag}`" for tag in rule["tags"])))
        add("| Automated fix | {} |".format("yes" if remediation.get("safe") else "no"))
        if remediation.get("fix"):
            add("| Fix type | `{}` |".format(remediation["fix"]["type"]))
        add("")
        add("Remediation: {}".format(cell(remediation["text"])))
        if remediation.get("command"):
            add("")
            add("```sh")
            add(remediation["command"])
            add("```")
        add("")

    add("## Check types")
    add("")
    add(
        "Checks are read-only and operate through the audit root. Absolute symlinks "
        "inside the root are resolved relative to that root, never to the host, so an "
        "image can be audited safely from a build server."
    )
    add("")
    add("| Check | What it inspects |")
    add("| --- | --- |")
    checks = {
        "file_exists": "Presence and expected type of a path.",
        "file_mode": "Maximum permission bits (and optionally ownership) of a file.",
        "file_owner": "Owning user and group of a path.",
        "file_content": "Required or forbidden patterns in a text file, with line reporting.",
        "sysctl": "Effective sysctl value across the scanned sysctl configuration files.",
        "sshd": "Effective sshd_config keyword, including first-match and Match section handling.",
        "package": "Installed package state through distro package databases.",
        "service": "systemd unit enablement and mask state from unit symlinks.",
        "account": "passwd, shadow and group invariants for local accounts.",
        "mount_option": "Required mount options for a mount point in fstab and mountinfo.",
        "firewall": "UFW, firewalld and nftables configuration state.",
        "kernel_module": "Whether a module is disabled through modprobe.d.",
        "login_defs": "login.defs policy values with numeric or set comparisons.",
        "auditd": "auditd.conf settings and audit daemon availability.",
        "cron_permissions": "Modes of crontab, cron directories and at configuration.",
        "world_writable": "World-writable files below a path, with bounded traversal.",
        "listening_port": "Listening sockets from procfs, including socket ownership.",
        "password_quality": "pwquality.conf enforcement, length and complexity settings.",
    }
    for name, description in checks.items():
        add(f"| `{name}` | {description} |")
    add("")
    add(
        "The bundled pack exercises {} of these {} checks. `file_owner` is implemented "
        "and unit-tested but not used by the default pack, because ownership of a "
        "fixture tree cannot be changed without root; the check is available to custom "
        "rule packs.".format(len({rule["check"]["type"] for rule in rules}), len(checks))
    )
    add("")
    return "\n".join(lines)


def main() -> int:
    rules = load_rules()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(render(rules), encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(rules)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
