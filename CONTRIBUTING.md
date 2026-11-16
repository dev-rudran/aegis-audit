# Contributing

Thanks for improving aegis. The project favours small, tested changes that keep
the audit path read-only and the rule pack declarative.

## Development setup

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the full local gate before opening a pull request:

```sh
make check
```

This runs `ruff check`, `ruff format --check`, `bandit -r src`, and `pytest`.
Formatting is non-negotiable in CI; apply it with `make format`.

## Project layout

```
src/aegis/          package code
  checks/           read-only check implementations and registry
  report/           five report renderers
  rules/            bundled YAML rule pack
  util/             filesystem confinement and parsers
tests/              unit, integration, CLI, and fixture tests
docs/               rule reference, architecture, banner
scripts/            documentation generator
```

## Adding a rule

1. Pick the matching file in `src/aegis/rules/` and append a rule using the next
   free `AEGIS-NNNN` identifier.
2. Use an existing check type when possible. Run `aegis rules validate` to catch
   parameter mistakes.
3. Set a real severity. Critical is reserved for controls that directly enable
   remote compromise or credential theft.
4. Write remediation text that a competent administrator can follow. Add
   `safe: true` with a structured `fix` only when the change is deterministic and
   reversible from the backup. Everything else stays manual.
5. Add or extend a test that asserts the rule fails on the vulnerable fixture and
   passes on the hardened one. Update `tests/fixtures/manifest.json` if the
   fixture tree needs new modes or symlinks.
6. Regenerate the reference with `make docs`.

Identifiers are never reused, even after a rule is removed.

## Adding a check type

1. Implement `run_<type>` and `validate_<type>` in the appropriate module under
   `src/aegis/checks/`.
2. Register a `CheckSpec` in `src/aegis/checks/__init__.py`.
3. Validate parameters through `ParamReader` and return findings rather than
   raising for host conditions.
4. Add unit tests for the happy path, missing files, malformed input, and at
   least one boundary condition.
5. Document the check in `docs/RULES.md` by extending the generator's check
   table in `scripts/generate_rule_docs.py`, then run `make docs`.

## Testing expectations

- New behaviour needs a test that fails without the change.
- Filesystem tests use the fixture builder or `tmp_path`; never read the real
  `/etc` or `/proc`.
- Remediation tests must prove idempotence and that unsafe rules are never
  applied.
- CLI tests assert exit codes and stable output fragments, not timestamps.
- Keep the suite fast: it should stay under ten seconds on a laptop.

## Style

- Python 3.10 or newer, `from __future__ import annotations` at the top of every
  module.
- Line length 100, double quotes, typed public functions.
- No new runtime dependencies beyond PyYAML without prior discussion.
- Error messages start with a lowercase object name and explain the fix, for
  example `rule AEGIS-0001: check.type must be a string`.
- Comments explain why; the code explains what.

## Commits and pull requests

- Keep commits focused and describe the behaviour change in the imperative mood.
- Reference the affected rule or module in the subject when it helps, for
  example `rules: tighten SSH MaxAuthTries guidance`.
- Include the commands you ran in the pull request description.
- Do not include generated reports, virtual environments, or editor state.
- By contributing you agree that your work is licensed under the MIT license.

## Reporting bugs

Include the aegis version (`aegis version`), the command you ran, the expected
and actual result, and, when the issue is rule-specific, the output of
`aegis explain AEGIS-NNNN`. Redact hostnames and paths that you consider
sensitive.

Security issues follow `SECURITY.md` and must not be filed publicly.
