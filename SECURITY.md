# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

aegis is pre-1.0. Security fixes land on `main` and are released as patch
versions of the current minor line.

## Reporting a vulnerability

Report suspected vulnerabilities privately to **rudraking2404@gmail.com** with
the subject prefix `aegis security`. Include the affected version, the command
or rule involved, and a minimal reproduction. Do not open a public issue before
a fix is available.

You can expect an acknowledgement within five working days, an assessment within
ten, and a coordinated disclosure date once a fix is ready. Credit is given in
the release notes unless you ask to remain anonymous.

Please do not test against hosts you do not own or have written permission to
audit.

## Threat model

aegis runs on a trusted management host and reads untrusted filesystem content:
configuration files, package metadata, account databases, and directory trees
from an image or a running system.

The design assumes:

- The operator invoking aegis is trusted. aegis does not sandbox itself from the
  user running it.
- Audited files are hostile input. Every read goes through `RootFS`, which
  confines paths to the audit root, resolves symlinks with chroot semantics,
  rejects traversal, caps file reads at 4 MiB, and bounds directory walks.
- Rule packs are trusted code-adjacent configuration. A custom pack can select
  checks and parameters but cannot introduce executable code; unknown check
  types are rejected at load time.
- State files are untrusted. JSON reports, baselines, and manifests are parsed
  with type validation and without `eval`, `pickle`, or YAML object
  construction.

aegis does not make network connections, does not execute shell commands from
rule packs, and does not require elevated privileges for auditing.

## Remediation risk

`--apply` writes to the audited root. It is limited to rules declaring
`remediation.safe: true` and a structured fix of a known type. Every write is
preceded by a `.aegis.bak` backup and performed through an atomic replace.
Backups are not automatically removed.

Even a safe fix changes host configuration. Run `--remediate` first, review the
plan, and keep console access available. On a live host, restart or reload the
affected service yourself; aegis does not restart services or run package
operations.

## Known limitations

- Checks reason about persisted configuration under the audit root, not live
  kernel state. See `docs/architecture.md` for which checks are affected.
- Ownership checks resolve UIDs and GIDs against the audit root's own account
  databases. A deliberately inconsistent image can therefore appear compliant
  within its own namespace.
- The tool cannot detect a compromised auditor host or tampered aegis
  installation. Verify release artifacts and install from a pinned source.
