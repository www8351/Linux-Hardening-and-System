# STATUS.md — ossys

**Last updated:** 2026-07-21
**Branch:** `main` · **Baseline before this session:** `15d27d8`
**Tests:** `87 passed, 1 skipped` · **Coverage:** 84% (gate: ≥80%) · **mypy strict:** clean · **ruff (incl. `S`):** clean
**Current phase:** Phases 1–3 landed. Phase 4 (plugins) and 5 (packaging/Docker) open.

---

## Where the project stands

`ossys` is now an automatable admin framework rather than a set of hardened scripts. It runs
on **two automation paths** from one build:

| | Privileged | Unprivileged |
|---|---|---|
| Privilege | root (euid 0) or passwordless `sudo -n` | never elevates |
| Scheduler | `ossys-system.timer` / `/etc/cron.d/ossys` | `systemctl --user` timer / user crontab |
| Config | `/etc/ossys/ossys.toml` | `~/.config/ossys/ossys.toml` |
| Privileged commands | run | refuse cleanly with exit 20 |

Both are gated by `ossys check`, a read-only endpoint checkup, and both branch on the same
exit-code taxonomy.

## Done

- [x] Lifecycle files bootstrapped
- [x] `SECURITY_AUDIT.md` — 18 findings (2 HIGH, 7 MED, 8 LOW, 1 INFO)
- [x] **Phase 1** — `ossys/validate.py` shared allowlist layer; all 2 HIGH + 7 MED findings fixed
- [x] **Phase 2** — `ossys/exits.py` taxonomy (`0/10/20/30/40/50/60`), global `--json`, single CLI exception boundary
- [x] **Phase 3** — `--dry-run`, TOML per-endpoint config with hostname-glob profiles, idempotent `useradd`, systemd units (both paths), cron files (both paths), `ossys-run.sh` preflight wrapper, `install-endpoint.sh`, GHA hardening
- [x] `ossys check` endpoint checkup, human + `--json`, `--strict` deployment gate
- [x] `python -m ossys` entrypoint (works around the uv trampoline bug)
- [x] Coverage gate at 80% wired into CI; `S` (flake8-bandit) ruleset enabled

## Findings status

| Finding | Status |
|---|---|
| OSSYS-SEC-001/002 (HIGH, arbitrary write + symlink) | Fixed — `validate_output_path`, atomic writes |
| OSSYS-SEC-003/004 (archive dirs, basename collision) | Fixed — `validate_archive_members` |
| OSSYS-SEC-005 (PATH re-resolution) | Fixed — resolved absolute paths executed |
| OSSYS-SEC-006 (no timeout / sudo hang) | Fixed — `timeout=` + `stdin=DEVNULL` + `sudo -n` |
| OSSYS-SEC-007 (partial state) | Fixed — `require_tools` preflight before first mutation |
| OSSYS-SEC-008/012/013 (bounds, sides, newline) | Fixed |
| OSSYS-SEC-009 (no exit taxonomy) | Fixed — `ossys/exits.py` + `main()` boundary |
| OSSYS-SEC-010 (env inheritance) | Fixed — `safe_env()` |
| OSSYS-SEC-011 (no platform guard) | Fixed — `_require_linux()` |
| OSSYS-SEC-014 (partial `.tgz`) | Fixed — temp file + `os.replace` |
| OSSYS-SEC-015 (menu.sh stdout) | Fixed — banner to stderr, only when argv is empty |
| OSSYS-SEC-016 (CI gaps) | Fixed — `--frozen`, coverage gate, `S` rules, `pip-audit` job |
| OSSYS-SEC-017 (zip-slip, INFO) | **Still open by design** — no extraction exists; `safe_extract()` required before any lands |
| OSSYS-SEC-018 (pre-commit mypy) | **Open** — hook still lacks `additional_dependencies` |

## Open

- [ ] **OSSYS-SEC-018** — add `additional_dependencies: [typer, pytest]` to the pre-commit mypy hook and pin revs to `uv.lock`
- [ ] **Phase 3 remainder** — webhook-on-failure hook (config keys `webhook.url` / `webhook.on_failure` exist and are parsed, but nothing posts yet)
- [ ] **Phase 4** — plugin/subcommand auto-registration via entry points
- [ ] **Phase 5** — verify `pipx install .`; optional Dockerfile for sandboxed destructive commands
- [ ] **Phase 6** — MCP tool server wrapper

## Next best action

Wire the webhook-on-failure hook into `main()`'s exception boundary — the config surface is
already parsed and validated, so this is the smallest remaining piece of Phase 3.

## Blockers / waiting on

Nothing blocking. Two decisions were taken unilaterally and should be confirmed:

- **D-005 resolved as option (c)** — configurable `allowed_roots`, defaulting to CWD. This is
  a **breaking change**: `ossys details -o /etc/foo` now exits 10 instead of writing. Widening
  is an explicit config edit.
- **D-002 confirmed** — the request for a sudo automation path establishes that ossys does run
  elevated, so the HIGH ratings on OSSYS-SEC-001/002 stand.

## Needs review

- `deploy/*` units and cron files carry **example** ExecStart/command lines (archiving
  `/var/log/syslog`, `~/.bashrc`). They are illustrative — real workloads must be edited in
  before enabling any timer.
- `deploy/install-endpoint.sh` has not been executed on a real Linux host; it is
  shellcheck-clean and CI lints it, but end-to-end install is untested.
- The `sudo -n true` probe runs on every privileged invocation via `build_argv`. Fine for a
  scheduled job; worth caching if a future command issues many calls in one run.

## Known environment issue

`uv run ossys` and `uv run mypy` fail locally: `error: uv trampoline failed to canonicalize
script path` (spaces in the repo path). Use `uv run python -m ossys` / `uv run python -m mypy`
/ `uv run python -m pytest`. The `python -m ossys` entrypoint added this session makes this a
local-tooling annoyance rather than a functional limitation.
