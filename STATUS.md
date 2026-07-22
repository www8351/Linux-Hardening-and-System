# STATUS.md — ossys

**Last updated:** 2026-07-21
**Branch:** `main` · **Baseline before this session:** `15d27d8`
**Tests:** `181 passed, 1 skipped` · **Coverage:** 87% (gate: ≥80%) · **mypy strict:** clean · **ruff (incl. `S`):** clean · **pre-commit:** 10/10 hooks pass
**Current phase:** Phases 1–5 complete. Only Phase 6 (MCP, stretch) remains.

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
- [x] **Phase 3 complete** — failure webhook (`ossys/notify.py`), off by default, https-only,
      token from env, detail egress opt-in, never alters the exit code
- [x] **Phase 4** — entry-point plugin auto-registration (`ossys/plugins.py`), allow-list,
      kill switch, shadow refusal, failure isolation, `ossys plugins` inventory
- [x] `examples/ossys-plugin-demo/` — working plugin template; CI asserts the full contract
      (mount, invoke, exit 40 propagation, validator reuse, allow-list unmount)
- [x] **Phase 5** — `py.typed` marker, full distribution metadata, explicit hatch build
      targets, `tests/test_packaging.py`, Dockerfile + `.dockerignore`, Docker CI job
- [x] **`pipx install .` verified** — wheel built, installed into a clean space-free venv,
      console script resolves and propagates the exit taxonomy (0 / 10 / 2)
- [x] **OSSYS-SEC-018 closed** — pre-commit now matches CI (mypy deps, pinned revs,
      shellcheck, hygiene hooks)

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
| OSSYS-SEC-018 (pre-commit mypy) | Fixed — deps added, revs pinned to `uv.lock`, shellcheck added |

## Open

- [ ] **Phase 6 (stretch)** — wrap ossys as an MCP tool server so Claude Code / Desktop can
      call operations as tool calls instead of shelling out
- [ ] **Docker image is unbuilt locally** — see "Needs review"

## Next best action

Push, and read the CI result — the Docker job is the only verification the image has ever
had. If it is green, Phase 5 is genuinely done and Phase 6 is the remaining work.

All 18 findings from `SECURITY_AUDIT.md` are now closed except OSSYS-SEC-017 (zip-slip),
which stays open by design: no extraction code exists, and `safe_extract()` is the gate on
any future `ossys unarchive`.

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
- **Plugin allow-list defaults to empty (allow all).** Correct for a workstation, deliberately
  wrong-by-default for a privileged fleet host — `deploy/ossys.toml.example` pins it under
  `[profile.server.plugins]`, but an operator copying only `[defaults]` would not get that.
  Worth deciding whether privileged profiles should default to deny.
- **Plugins are not sandboxed** and the docs say so explicitly. A loaded plugin runs with full
  process privilege; the allow-list decides what loads, not what it may then do.
- `examples/ossys-plugin-demo/pyproject.toml` declares `ossys` as a dependency for realism.
  There may be an unrelated `ossys` on PyPI — installs use `--no-deps` for that reason, in CI
  and in the README.
- **The Docker image has never been built.** The daemon is not running on this machine. What
  *was* verified locally is the builder stage's logic: the exact COPY set and the same
  `python -m build --wheel --no-isolation` invocation, run against a clean directory,
  producing a correct wheel with `py.typed` and the console-script entry point. The 15 shell
  blocks in the workflow are `bash -n` clean. Everything else about the image — base image,
  apt layer, non-root user, ENTRYPOINT — is unproven until the CI Docker job runs.
- The Docker CI job runs `useradd` **for real** as root inside a throwaway container. That is
  deliberate (it is the only non-mocked exercise of the privileged path) but it is worth a
  second pair of eyes on the isolation assumption before it is trusted.
- `Dockerfile` pins the base image by tag, not digest. For a production image, pin by digest
  so a rebuild cannot silently pick up a new base; noted inline.

## Known environment issue

`uv run ossys` and `uv run mypy` fail locally: `error: uv trampoline failed to canonicalize
script path` (spaces in the repo path). Use `uv run python -m ossys` / `uv run python -m mypy`
/ `uv run python -m pytest`. The `python -m ossys` entrypoint added this session makes this a
local-tooling annoyance rather than a functional limitation.
