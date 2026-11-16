# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and the project adheres to Semantic Versioning.

## [0.1.0] - 2026-11-16

First public release.

### Added

- Audit engine with weighted severity scoring, letter grades, per-category
  breakdowns, and top-risk summaries.
- 81-rule CIS-aligned pack across SSH, kernel and sysctl, filesystem
  permissions, accounts and authentication, logging and auditd, firewall,
  package hygiene, services, and cryptography.
- 18 read-only check types: `file_exists`, `file_mode`, `file_owner`,
  `file_content`, `sysctl`, `sshd`, `package`, `service`, `account`,
  `mount_option`, `firewall`, `kernel_module`, `login_defs`, `auditd`,
  `cron_permissions`, `world_writable`, `listening_port`, and
  `password_quality`.
- `--root` filesystem confinement with chroot-style symlink resolution, so images
  and extracted container filesystems can be audited without touching the host.
- Time-bound baseline exceptions with expiry validation and stale-entry
  reporting.
- Safe remediation engine: dry-run by default, `--apply` writes with
  `.aegis.bak` backups and atomic replacement, structured fixes only, and
  before/after diffs. Shell commands in rules are never executed.
- Report formats: console, JSON, Markdown, self-contained HTML, and SARIF 2.1.0.
  Format inference from the output file extension.
- Drift reporting with `aegis diff`, including newly failing, newly fixed, still
  failing, per-severity counts, and score delta.
- CI gates with `--fail-on` and `--min-score`, plus stable exit codes.
- Rule tooling: `aegis rules list`, `aegis rules show`, `aegis rules validate`,
  and `aegis explain`.
- Hardened and vulnerable fixture root filesystems used by the test suite.

### Known limitations

- Checks inspect persisted configuration inside the audit root rather than live
  kernel or firewall state.
- Ownership checks are implemented but unused by the bundled pack, because
  fixture ownership cannot be changed without root.
- Package, service, and firewall checks understand the common Debian/Ubuntu and
  RHEL-family layouts; unusual layouts produce findings that need manual review.

[0.1.0]: https://github.com/dev-rudran/aegis-audit/releases/tag/v0.1.0
