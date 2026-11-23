# Five-minute quickstart

## 1. Install

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e .
```

## 2. Audit something safe

The repository ships two fixture root filesystems, so you can try the tool
without touching the host:

```console
$ aegis audit --root tests/fixtures/rootfs-hardened
Result: 0 failing, 0 error(s), 0 not applicable. Score 100.00 (A). Gate: PASS

$ aegis audit --root tests/fixtures/rootfs-vulnerable --fail-on high
Result: 78 failing, 0 error(s), 0 not applicable. Score 3.83 (F). Gate: FAIL
```

## 3. Understand a finding

```console
$ aegis explain AEGIS-0002
```

## 4. Produce a report for CI

```console
$ aegis audit --root tests/fixtures/rootfs-vulnerable --format sarif -o aegis.sarif
$ aegis audit --root tests/fixtures/rootfs-vulnerable --format html -o aegis.html
```

Upload the SARIF file with `github/codeql-action/upload-sarif` (see the README)
or open the HTML report locally.

## 5. Plan and apply fixes

```console
$ cp -r tests/fixtures/rootfs-vulnerable /tmp/demo-root
$ aegis audit --root /tmp/demo-root --remediate   # dry run
$ aegis audit --root /tmp/demo-root --apply       # writes backups + re-audits
```

`--apply` only touches rules marked safe. Everything else is reported with an
advisory command for a human to review.
