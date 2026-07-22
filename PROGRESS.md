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

---

## 2026-07-21 (later still) — Phase 3 completed, Phase 4 landed

**Worked on:** The two remaining planned items — the failure webhook, then plugin
auto-registration.

### What changed

`src/ossys/notify.py` (failure webhook) and `src/ossys/plugins.py` (entry-point discovery),
plus config keys, preflight rows, an `ossys plugins` inventory command, CLI wiring,
`examples/ossys-plugin-demo/` as a working template, and a CI step asserting the whole plugin
contract end to end.

Tests: 87 → 172 passed, 1 skipped. Coverage 84% → 87%. `plugins.py` at 100%.

### What worked

- **Designing the webhook entirely as negative guarantees.** Disabled by default, never
  raises, never changes the exit code, never sends on dry-run, never sends on exit 0 or 40,
  never leaks stderr unless asked, never opens a non-http scheme. Writing the tests as
  assertions about what does *not* happen made the module fall out almost mechanically.
- **Validating the webhook URL at config load rather than at send time.** The first real
  failure is the worst moment to discover alerting is broken. Rejecting unknown keys in the
  `[*.webhook]` table covers the same class from the other side — a misspelled `on_failuer`
  would otherwise leave alerting armed while the operator thinks it is off.
- **Making `ossys check` refuse to send a test POST.** The checkup stays read-only and
  schedulable. It still catches the important case: a `token_env` naming an unset variable is
  a *failure*, because the alert would be delivered unauthenticated and silently dropped.
- **Gating the plugin allow-list at the import, not the mount.** The obvious implementation —
  load everything, filter afterwards — would let a blocked package run module-level code in a
  root process. Getting this the right way round was the single most important decision in
  Phase 4.
- **The demo plugin proved the contract for real.** Installing it and running `ossys demo
  hello` end to end verified mounting, exit 40 propagating through a plugin, validator reuse
  producing exit 10 with a JSON envelope, and the allow-list making the subcommand vanish
  (exit 2). All five assertions now run in CI.

### What did not work / what surprised

- **Backticks in a `git commit -m "..."` heredoc ran as command substitution.** The message
  for the webhook commit lost the word "detail" — bash executed `` `detail` `` and reported
  "command not found". Caught by re-reading the committed message, and amended from a file.
  Commit bodies now go through `-F`, never `-m` with backticks.
- **Plugin registration is a genuine ordering problem.** Typer cannot dispatch to a subcommand
  that is not on the app yet, but the allow-list governing registration lives in the config
  file selected by `--config`. Resolved with a deliberately-not-a-parser argv pre-scan in
  `main()`, with the callback doing the authoritative load moments later. If the pre-load
  fails, discovery is skipped entirely rather than falling back to permissive defaults.
- **Ruff B023 caught a closure capturing loop variables** in `discover()`. Safe as written
  (called within the same iteration) but exactly the shape that breaks the moment anyone
  defers the call. Rebound explicitly via default arguments.
- **mypy strict rejected `PluginRecord.status -> str`** where preflight wanted a `Literal`.
  Declared `PluginStatus` in `plugins.py` rather than importing from `preflight`, keeping the
  dependency one-way (preflight imports plugins, never the reverse).

### Findings status

Unchanged: OSSYS-SEC-018 (pre-commit mypy deps) and OSSYS-SEC-017 (zip-slip, INFO — still no
extraction code, so the pre-emptive `safe_extract()` remains deferred by design).

### Next

Phase 5: verify `pipx install .` on a clean machine, and the optional Dockerfile.

---

## 2026-07-22 — Phase 5: packaging, container sandbox, gate parity

**Worked on:** Phase 5 (testing & packaging), plus closing the last open audit finding.

### What changed

`src/ossys/py.typed`; full distribution metadata and explicit hatch build targets in
`pyproject.toml`; `tests/test_packaging.py`; `Dockerfile` and `.dockerignore`; a `docker` CI
job; a rewritten `.pre-commit-config.yaml`.

Tests 172 → 181 passed, 1 skipped. Coverage steady at 87%.

### What worked

- **`pipx install .` finally verified rather than assumed.** Built both artefacts, installed
  the wheel into a clean venv at a *space-free* path, and confirmed the console script
  resolves and propagates the taxonomy (0 success, 10 validation, 2 usage). This retires a
  claim carried as "unverified" for three sessions. The old `uv trampoline failed to
  canonicalize script path` was purely the spaces in this checkout's path — not a packaging
  defect. The shim was always fine.
- **`py.typed` turned out to be the substantive part of Phase 5.** The package is checked
  under `mypy --strict`, but without the PEP 561 marker none of that reached consumers: a
  plugin author importing `ossys.validate` got bare `Any`. That matters more here than in a
  typical library, because Phase 4 actively instructs plugin authors to import those modules
  rather than reimplement the checks — so the missing marker was quietly undermining the
  plugin contract.
- **Explicit sdist include list.** Ships src, tests, deploy, examples, scripts, README,
  LICENSE and SECURITY_AUDIT.md; excludes the working notes. Someone auditing the tarball
  should see what the code does and how it is verified — the tests carry the security
  contract, so they belong — not a session-by-session progress log.
- **Putting the privileged path in CI, for real.** The Docker job runs `useradd` as root
  inside a throwaway container and then re-runs it to prove exit 40 against genuine system
  state rather than a stubbed pwd lookup. Every unit test of that path mocks `subprocess` by
  design; this is the one place the real thing executes, and the container is what makes
  that safe.
- **Simulating the Dockerfile builder stage locally.** Could not build the image, but copying
  the exact COPY set into a clean directory and running the same
  `python -m build --wheel --no-isolation` proved the COPY list sufficient and the wheel
  correct. Partial verification beats none.

### What did not work / what surprised

- **`[project.urls]` silently swallowed `dependencies`.** Inserting the table immediately
  after `requires-python` put the following `dependencies = [...]` array *inside* it. The
  build failed with `URL 'dependencies' of field 'project.urls' must be a string` — a good
  error, but only because hatchling type-checks URLs. TOML table ordering is positional;
  headers must go after the key-values they are not meant to capture.
- **`python -m build` re-downloads the backend by default.** The Dockerfile installed
  `hatchling` and then ignored it, because `build` creates an isolated env unless told not
  to. Added `--no-isolation`: one fewer network fetch per image build, and the backend
  version is the one actually pinned.
- **The first shellcheck pre-commit hook required a Docker daemon.**
  `koalaman/shellcheck-precommit` runs shellcheck in a container, so `pre-commit run` failed
  outright on this machine (Docker installed, not started). Switched to `shellcheck-py`,
  which ships the binary as a wheel. A local gate that depends on Docker Desktop being up is
  a gate developers disable — worth remembering for any future hook choice.
- **The pre-commit revs had drifted badly**: pinned at ruff 0.6.9 / mypy 1.11.2 against
  0.15.14 / 2.1.0 actually installed. Combined with the missing `additional_dependencies`
  (OSSYS-SEC-018), the local gate was weaker than CI in three separate ways.
- **Could not build the container image.** Docker CLI present, daemon down. The image is
  committed unbuilt and flagged as such in `STATUS.md`; the CI Docker job is its first real
  verification.
- **Bash heredocs bit me a second time this project** — after the backtick incident in a
  commit message, an inline heredoc carrying prose with quotes failed to parse. Long prose
  now goes through written files, never inline shell.

### Findings status

17 of 18 findings closed. OSSYS-SEC-018 fixed this session. Only OSSYS-SEC-017 (zip-slip)
remains open by design — no extraction code exists, and `safe_extract()` is the gate on any
future `ossys unarchive`.

### Next

Phase 6 (stretch): MCP tool server wrapper. Before that, confirm the CI Docker job is green —
the image has no other verification.

---

## 2026-07-22 (later) — Phase 6: MCP tool server

**Worked on:** The stretch goal — wrapping ossys as an MCP server so Claude Code / Desktop
can call operations as tool calls instead of shelling out.

### What changed

`src/ossys/mcp_server.py`, `tests/test_mcp_server.py` (24 tests), MCP config keys, an `mcp`
check row in the preflight, an `mcp` optional extra plus the `ossys-mcp` console script, an
MCP contract step in CI, and config/README documentation.

Tests 181 → 205 passed, 1 skipped. Coverage 82% (down from 87%: the new module is large and
its `main()` serving loop is not unit-testable, but still above the 80% gate).

### What worked

- **Treating this as the sharpest surface in the project and designing backwards from that.**
  An MCP server hands tool invocation to a model, with model-chosen arguments, in response to
  text that may have come from anywhere. So: read-only by default, writes need a config
  entry, `useradd` needs a *second independent* switch, and none of it is reachable via a CLI
  flag or environment variable — only a file that can be reviewed and diffed.
- **Separating tool bodies from registration.** The handlers are plain functions returning
  plain dicts with no MCP types in them, so they are testable without the optional dependency
  and the registration layer stays a thin adapter rather than somewhere logic hides.
- **Verifying with a real stdio handshake**, not just the in-process object graph: spawned
  the actual server process, completed the protocol handshake, listed tools, called them.
  That is the wiring an MCP client uses, and nothing else proves it.
- **The gating is structural, not cosmetic.** An unexposed tool is not registered at all, so
  `call_tool("ossys_useradd", ...)` fails with "Unknown tool". An advertised-but-refusing tool
  would still tell the model the capability exists.

### What did not work / what surprised

- **A real security defect in the first version of `_bind`.** I used
  `functools.update_wrapper` to carry the docstring across a `functools.partial`. That sets
  `__wrapped__`, which makes `inspect.signature` follow through to the *unbound* function —
  re-exposing `settings` as a required tool argument in every generated schema. `settings`
  carries `allowed_roots` and the privilege mode. Caught by printing the schemas rather than
  assuming, fixed by computing the trimmed signature explicitly and never setting
  `__wrapped__`, and pinned by a regression test that asserts no tool schema contains it.
  Worth remembering: `update_wrapper` and `partial` do not compose the way they look like
  they do.
- **A first-match string replace corrupted the example config.** My insertion anchor
  `[profile.server.plugins]` matched inside a *comment* ("see [profile.server.plugins]
  below") before the real table header, splicing a block mid-sentence and producing
  `Cannot overwrite a value`. Caught because `ossys check` exited 50 against the example.
  Fixed by anchoring on the exact line rather than a substring. Second time this session that
  a naive replace has bitten; anchors need to be line-exact in files that quote their own
  structure.
- **Coverage dropped 87% → 82%.** Expected — `main()`'s serving loop and the SDK-import
  failure path are not unit-testable — but it is the first time this project has moved
  *toward* the gate rather than away from it.

### CI has never run — worth stating plainly

While checking the Docker job result from the previous session, found that this repository
has produced **zero GitHub Actions runs in its entire history**, across every push. The
workflow is registered and reported active, the repo is public, Actions are enabled, and
`ci.yml` has been on the default branch throughout. No run has ever started.

That means everything described as "CI verifies this" — the container image, the plugin
integration contract, the coverage gate, the new MCP contract step — is unverified. Added a
`workflow_dispatch` trigger so it can at least be started manually, but the underlying cause
is unresolved and sits outside the repository.

### Next

Nothing planned. All six phases are complete. The open items are the CI mystery, the unbuilt
container image, and OSSYS-SEC-017 (zip-slip), which stays open by design until an extraction
command exists.
