# Improvement backlog

Captured 2026-11-23. Priorities: **P1** correctness/security, **P2** capability,
**P3** polish. Keep the existing suite green and add tests for every change.

## P1

- **Strict typing.** Add `src/aegis/py.typed`, a `[tool.mypy]` section with
  `strict = true`, and a CI step. Definition of done: `mypy src` is clean.
- **Python 3.14 in CI.** Add `"3.14"` to the matrix. The suite already passes
  locally on 3.14.
- **`--write-baseline PATH`.** Generate a baseline file from the current report
  instead of asking users to hand-write rule ids. Must include rule id, a short
  reason placeholder and a default 90-day expiry, and must refuse to overwrite
  without `--force`.
- **SARIF `partialFingerprints`.** Add stable fingerprints (rule id + root
  relative path, no timestamps) so GitHub code scanning deduplicates across
  runs. Test that two audits of the same root produce identical fingerprints.

## P2

- **Parallel checks.** Run independent checks with a bounded thread pool and add
  `--jobs N` (default: CPU count). DoD: same report as serial mode, plus a
  benchmark note in `docs/architecture.md`.
- **`--format junit`.** Emit JUnit XML for CI test reporters.
- **Distribution profiles.** Detect Debian/RHEL layout and mark rules that do not
  apply as `not_applicable` rather than failed, behind `--profile auto`.
- **Container image.** Add a small `Dockerfile` publishing the CLI, with a
  documented `docker run --rm -v /:/host:ro aegis audit --root /host` recipe.
- **PyPI release.** Publish wheels via OIDC trusted publishing from the release
  workflow (no long-lived tokens) and switch README install lines to `pip install aegis-audit`.

## P3

- Shell completions (argcomplete) for `audit`, `rules` and `explain`.
- `docs/COMPARISON.md` explaining scope differences from Lynis and OpenSCAP.
- Parser fuzz tests for `sshd_config`, `fstab` and `sysctl` inputs.
- Add `CODE_OF_CONDUCT.md`.
