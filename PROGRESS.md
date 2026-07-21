# PROGRESS.md — ossys

Dated log of what happened, what changed, what worked, what did not.

---

## 2026-07-21 — Bootstrap + Phase 0 security audit

**Worked on:** Lifecycle-file bootstrap and the Phase 0 audit gating the architecture and
automation upgrade.

### What changed

- Created `STATUS.md`, `PROGRESS.md`, `DECISIONS.md`, `CLAUDE_MEMORY.md` (bootstrap-on-demand;
  `README.md` and `CLAUDE.md` already present).
- Created `SECURITY_AUDIT.md` — the Phase 0 deliverable.
- **No source code touched.** Execution rule 2 gates fixes on approval.

### What was examined

Full tree read: `src/ossys/{__init__,cli,system,tasks}.py` (276 LOC), `tests/` (101 LOC),
`scripts/menu.sh`, `.github/workflows/ci.yml`, `pyproject.toml`, `.pre-commit-config.yaml`.
Grep sweep for `shell=True`, `os.system`, `os.popen`, `eval(`, `exec(`, `subprocess.*`,
`extractall`.

### What worked

- Baseline test run is green: `uv run python -m pytest -q` → `16 passed in 0.06s`. Confirms
  the zero-regression gate has a valid starting point.
- The prior hardening pass holds up under scrutiny. Zero shell-injection findings: both
  subprocess sites pass argv lists, `_USERNAME_RE` is anchored *and* length-bounded, and
  `tests/test_system.py` asserts on exact argv lists so a regression to string-building
  would break the suite rather than pass quietly. The README's central claim is accurate.
- Reading the tests alongside the source paid off — `test_archive_missing_file_raises`
  turned out to pass *over* a real bug (`OSSYS-SEC-014`): it asserts the exception but never
  asserts the partial `.tgz` is absent.

### What did not work / what surprised

- **`uv run ossys` is broken on this workstation**: `error: uv trampoline failed to
  canonicalize script path`. Cause is the spaces in `.../GitHub Main/...`. Worked around
  with `uv run python -m pytest`; no live CLI smoke-testing was possible. Logged as
  `SECURITY_AUDIT.md` §5; the fix (a `python -m ossys` entrypoint) is deferred to Phase 5.
- **Zip-slip, the brief's headline archive risk, does not exist in this tree.** There is no
  extraction code at all — `tasks.py` only creates archives. Recorded as INFO
  (`OSSYS-SEC-017`) with pre-emptive controls required before any `unarchive` command lands,
  rather than dropped from the report.
- The audit's centre of gravity landed somewhere other than expected. The *command*
  boundary is hardened thoroughly; the *filesystem* boundary is not hardened at all. Both
  HIGH findings are unvalidated output paths (`--out` → arbitrary write, symlink-following),
  not subprocess issues.

### Findings tally

2 HIGH · 7 MED · 8 LOW · 1 INFO — 18 total. See `SECURITY_AUDIT.md`.

### Next

Awaiting approval of the phase plan. First Phase 1 commit will be the shared validator
module (`src/ossys/validate.py`) plus tests — every other Phase 1 fix depends on it.

---

## 2026-07-21 (later) — Phases 1–3: dual automation paths, checkup, endpoint config

**Worked on:** The user asked for two ways to run ossys automatically — one privileged, one
not — plus a checkup gate and per-endpoint customisation. Delivering that required the
Phase 1 validator and the Phase 2 exit taxonomy first, so those landed as part of it.

### What changed

New modules: `exits.py` (taxonomy + error hierarchy), `validate.py` (shared allowlists),
`privilege.py` (ROOT/SUDO/USER detection and execution), `config.py` (TOML per-endpoint
profiles), `preflight.py` (the checkup), `output.py` (JSON/human emitter), `__main__.py`.
Rewrote `cli.py` (global flags, single exception boundary), `system.py` and `tasks.py`.

New deploy surface: `deploy/systemd/ossys-{system,user}.{service,timer}`,
`deploy/cron/ossys-{root,user}.cron`, `deploy/ossys.toml.example`,
`deploy/install-endpoint.sh`, `scripts/ossys-run.sh`.

Tests grew from 16 to 88 (87 passed, 1 skipped). Coverage 84%, gate set at 80%.

### What worked

- **Two paths from one detection function.** `detect_mode()` returns ROOT / SUDO / USER with
  the *reason* attached, and `PrivilegeReport` carries it into `ossys check`. Debugging "why
  did host 47 pick USER" across a fleet is otherwise guesswork.
- **`sudo -n true` as the elevation test.** Not a heuristic — `-n` makes sudo fail rather than
  prompt, so it answers exactly the right question ("can this run unattended?") and cannot
  hang while asking it. It closed OSSYS-SEC-006 more cleanly than a timeout alone.
- **Config discovery differing by privilege level.** `/etc/ossys/` for root, `~/.config/ossys/`
  for user. Both paths coexist on one endpoint and the timer needs no knowledge of which is
  active.
- **Writing the CLI tests against `main()` rather than Typer's CliRunner.** This caught two
  real bugs that unit tests on the app object would have missed entirely — see below.

### What did not work / what surprised

- **`import click` in `main()` was a latent crash.** Typer 0.26.2 dropped its public click
  dependency and vendored it as `typer._click`; `click` is not installed in this project at
  all. The entrypoint would have raised `ModuleNotFoundError` on every invocation. Found by
  inspection while chasing a mypy `import-not-found`, not by tests — the suite had no
  coverage of `main()` at that point. Replaced with a probe across
  `typer._click.exceptions` / `click.exceptions` and public `typer.Exit` / `typer.Abort`.
- **`app(standalone_mode=False)` returns exit codes instead of raising them.** Reading
  `typer/core.py::_main` confirmed it: `typer.Exit` is caught and its code *returned*, while
  `ClickException` and `Abort` are re-raised. `main()` discarded the return value, so every
  deliberate exit — including `check --strict` failures — silently collapsed to 0. The
  `except typer.Exit` branch was dead code. Caught by `test_check_strict_fails_on_warnings`.
- **`find_config` read the explicit path back out of the discovery chain** (`chain[0]`), so an
  empty or reordered chain raised `IndexError` and got mapped to exit 30 instead of 50.
  Caught by `test_config_error_exits_50`. Now resolves the named path directly.
- **mypy strict rejects the standard monkeypatch idiom.** `monkeypatch.setattr(privilege.shutil,
  "which", ...)` trips `no_implicit_reexport`. A per-module override does not help — the rule
  is evaluated against the module being *read from*, not the reader. Switched the tests to
  monkeypatch's string-target form, which keeps `src` and `tests` both fully strict.
- **Ruff `S311` fires on the dice RNG.** Suppressed per-file rather than switching to
  `secrets`: using a CSPRNG there would imply a guarantee ossys does not make. The module
  docstring already says the rolls are demo output.

### Findings closed

All 2 HIGH and 7 MED from `SECURITY_AUDIT.md`, plus 7 of 8 LOW. Still open:
OSSYS-SEC-018 (pre-commit mypy deps) and OSSYS-SEC-017 (zip-slip, INFO — no extraction code
exists yet, and the pre-emptive `safe_extract()` is deliberately deferred until one does).

### Next

Webhook-on-failure — the config keys are parsed and validated but nothing posts yet. Then
Phase 4 plugin auto-registration.
