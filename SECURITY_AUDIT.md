# SECURITY_AUDIT.md — ossys Phase 0

**Audit date:** 2026-07-21
**Commit audited:** `15d27d8` (branch `main`)
**Scope:** `src/ossys/{__init__,cli,system,tasks}.py`, `scripts/menu.sh`, `.github/workflows/ci.yml`, `pyproject.toml`, `.pre-commit-config.yaml`
**Tree size:** 276 LOC source / 101 LOC tests
**Baseline test state:** `uv run python -m pytest -q` → `16 passed` (green before audit)
**Status:** Findings only. **No fixes applied.** Remediation gated on approval.

---

## 1. Method

Every external-process call, filesystem write, and archive operation in the tree was
enumerated by grep + manual read, then rated on exploitability *in the deployment model
this tool actually targets*: a non-interactive CLI invoked from cron / systemd / CI,
frequently **under `sudo`** (the `useradd` command requires it).

That last point drives the severity ranking. An arbitrary-file-write primitive in a
user-level script is an annoyance; the same primitive in a binary routinely run as root
is a privilege-escalation chain. Findings are rated accordingly.

Grep sweep results (clean):

```
shell=True        → 0 occurrences (source)
os.system         → 0 occurrences (source)
os.popen          → 0 occurrences
eval( / exec(     → 0 occurrences
subprocess.Popen  → 0 occurrences
tar.extractall    → 0 occurrences
```

Only prose mentions of `os.system` remain, inside docstrings describing the *removed*
legacy behaviour. The core claim in the README — "user input never reaches a shell" —
holds. The gaps are elsewhere.

---

## 2. Operation inventory

### 2.1 External process calls (2 sites, both in `system.py`)

| # | Location | Call | Shell? | Args validated? |
|---|----------|------|--------|-----------------|
| P1 | `system.py:82` | `subprocess.run([*prefix, "useradd", username], check=True)` | No | Yes — `validate_username` |
| P2 | `system.py:87` | `subprocess.run([*prefix, "usermod", "-aG", "sudo", username], check=True)` | No | Yes — same |

Both are argv lists. Neither spawns a shell. Injection via the `username` argument is
**not** exploitable. The residual issues are resolution, timeout, and ordering — see
`OSSYS-SEC-005/006/007`.

### 2.2 Filesystem writes (2 sites, both in `tasks.py`)

| # | Location | Call | Path validated? |
|---|----------|------|-----------------|
| F1 | `tasks.py:75` | `Path(path).write_text(...)` | **No** |
| F2 | `tasks.py:90` | `tarfile.open(archive, "w:gz")` | **No** |

Both destination paths originate from CLI options (`--out`) and reach the filesystem
with zero normalisation, containment check, or symlink handling.

### 2.3 Archive operations (1 site)

| # | Location | Call | Notes |
|---|----------|------|-------|
| A1 | `tasks.py:96` | `tar.add(p, arcname=p.name)` | Creation only. **No extraction path exists in the tree.** |

---

## 3. Findings

Severity: **HIGH** = exploitable primitive with privilege impact · **MED** = correctness
or availability failure reachable from normal automated use · **LOW** = hardening gap /
defence-in-depth · **INFO** = no defect today, constrains future work.

### OSSYS-SEC-001 — HIGH — Arbitrary file write via unvalidated `--out` in `save_details`

**Location:** `src/ossys/tasks.py:68-79`, reached from `src/ossys/cli.py:55-64`

`save_details` accepts `path: str | Path` and calls `Path(path).write_text(...)` with no
containment check. The CLI exposes this directly as `--out`.

```bash
sudo ossys details --name x --age 1 --phone 1 --out /etc/cron.d/ossys
```

The written content is attacker-influenced (`name`, `age`, `phone` are free-form strings,
and `OSSYS-SEC-013` shows newlines survive), so this is not merely a clobber primitive —
it is a *controlled-content* write to an arbitrary path. Under `sudo`, `/etc/cron.d/`,
`~/.ssh/authorized_keys`, and `/etc/sudoers.d/` are all reachable, and the second and
third lines of the output format are close enough to free text to be weaponised.

**Compounding: symlink following.** `write_text` opens with `"w"`, which follows symlinks.
An unprivileged attacker who can create `details.txt` in the working directory (the CLI
default) as a symlink to a root-owned file turns the *default invocation* into a
privileged overwrite. No `O_NOFOLLOW`, no `O_EXCL`, no `lstat` pre-check.

**Fix direction (Phase 1):** shared `validate_output_path()` — resolve, reject symlinked
targets and symlinked parents, require containment under an explicit allowed root
(CWD by default, overridable by config), and write via `O_NOFOLLOW | O_CREAT` to a temp
file followed by `os.replace` for atomicity.

---

### OSSYS-SEC-002 — HIGH — Same arbitrary-write / symlink-clobber in `archive_files`

**Location:** `src/ossys/tasks.py:82-97`, reached from `src/ossys/cli.py:67-74`

`tarfile.open(archive, "w:gz")` on an unvalidated `archive_path`. Identical exposure to
`OSSYS-SEC-001` minus the content control — this is a destructive clobber, not a
content-injection primitive.

```bash
sudo ossys archive a.txt -o /etc/shadow      # truncates and replaces with a tarball
```

`tarfile.open` in write mode follows symlinks on the destination for the same reason.

**Fix direction:** route through the same `validate_output_path()` as `OSSYS-SEC-001`.
One validator, both call sites — this is precisely the shared allowlist layer Phase 1
calls for.

---

### OSSYS-SEC-003 — MED — `tar.add` silently recurses into directories

**Location:** `src/ossys/tasks.py:91-96`

The guard is `if not p.exists()`. A directory satisfies `exists()`, and `tarfile.add`
defaults to `recursive=True`. So:

```bash
ossys archive /etc -o out.tgz      # archives the entire tree, no warning
```

Consequences: unbounded runtime and disk consumption in an automated context, and silent
capture of unintended, potentially secret-bearing files into an artifact that may be
shipped off-host. Recursion also drags in whatever symlinks live under the tree, stored
as links whose targets are resolved at *extraction* time — which is how this finding
becomes an extraction-side problem later (see `OSSYS-SEC-017`).

**Fix direction:** `p.is_file()` rather than `p.exists()`; require an explicit
`--recursive` opt-in for directory members; enforce member-count and total-byte caps.

---

### OSSYS-SEC-004 — MED — `arcname=p.name` collapses distinct paths to one member

**Location:** `src/ossys/tasks.py:96`

Flattening to basename is correct for not leaking host paths, but it is applied without a
collision check:

```bash
ossys archive /var/log/app/config.yml /home/user/config.yml -o out.tgz
```

Both are stored as `config.yml`. `tarfile` appends both members without complaint; the
majority of extractors then silently overwrite the first with the second. Result: a
backup that appears to contain two files and restores only one, with no error at create
time or restore time. For a tool whose stated purpose includes backups, silent data loss
is the failure mode that matters most.

**Fix direction:** track seen `arcname`s; on collision either fail loudly (exit code 10)
or disambiguate deterministically. Add a test asserting a two-same-basename archive is
rejected.

---

### OSSYS-SEC-005 — MED — `_require()` result discarded; PATH re-resolved by subprocess

**Location:** `src/ossys/system.py:41-51`, `81-87`

`_require()` does the right thing — `shutil.which(tool)` and raise if absent — then
**returns a path the callers throw away**:

```python
_require("useradd")
subprocess.run([*prefix, "useradd", username], check=True)   # resolves "useradd" AGAIN
```

Two defects follow. First, the resolution is performed twice against a mutable `PATH`,
so the binary verified is not necessarily the binary executed — a genuine TOCTOU window,
narrow but real. Second, and more practically: on a host where `PATH` is attacker-
influenced (a compromised service account's cron environment is the classic case), a
planted `useradd` earlier in `PATH` is executed **under `sudo`**. The existence check
provides the false comfort of validation without the guarantee.

Related: `sudo` itself is never passed through `_require`, so a missing `sudo` surfaces
as a raw `FileNotFoundError` rather than the module's own `SystemError_`.

**Fix direction:** use the return value — `subprocess.run([*prefix, _require("useradd"), ...])`
— and resolve `sudo` the same way. Update `test_add_user_uses_list_args_no_shell`, which
currently asserts on the bare tool names and will need to assert on resolved paths.

---

### OSSYS-SEC-006 — MED — No `timeout=` on any subprocess call

**Location:** `src/ossys/system.py:82`, `87`

`subprocess.run(...)` with no `timeout`. If `sudo` blocks on a password prompt — which it
will whenever the cached credential has expired and no `NOPASSWD` rule applies — the
process waits **forever** on a TTY that does not exist. Under cron this produces a hung
job holding a lock; under systemd it hangs the unit until `TimeoutStopSec`. This directly
contradicts the project's stated non-interactive guarantee: the code is non-interactive by
*intent*, but nothing enforces it at runtime.

**Fix direction:** `timeout=` on every call (config-tunable), `stdin=subprocess.DEVNULL`
to force `sudo` to fail fast rather than prompt, and map `TimeoutExpired` onto the Phase 2
external-command-failure exit code (`30`).

---

### OSSYS-SEC-007 — MED — Preflight ordering leaves partial state on missing `usermod`

**Location:** `src/ossys/system.py:81-87`

```python
_require("useradd")
subprocess.run([...useradd...])       # ← account created here
if sudo_group:
    _require("usermod")               # ← only checked now; may raise
    subprocess.run([...usermod...])
```

`_require("usermod")` executes *after* the account already exists. On a host lacking
`usermod`, `add_user("alice", sudo_group=True)` creates `alice`, raises `SystemError_`,
and returns a non-zero exit — leaving a caller that reasonably reads failure as "nothing
happened" with a real account on the box. The docstring for `_require` explicitly claims
this class of partial state is what it prevents; the call ordering defeats it.

**Fix direction:** resolve every tool the requested operation will need before the first
mutating call.

---

### OSSYS-SEC-008 — MED — Unbounded allocation in `count_to` / `roll_cubes`

**Location:** `src/ossys/tasks.py:29-37`, `53-65`

Both validate only the lower bound:

```python
ossys count 10000000000        # list(range(1, 10**10)) → OOM
ossys cubes 100000000          # 10**8 CubeRoll objects → OOM
```

`count_to` materialises the full list rather than yielding. Local DoS only, but it is
reachable from any wrapper that forwards an unsanitised integer, and OOM-killing a
scheduled job is a real availability event.

**Fix direction:** upper bounds in the shared validator layer; make `count_to` a generator
(the CLI already iterates it lazily at `cli.py:37`, so this is source-compatible).

---

### OSSYS-SEC-009 — MED — No exception boundary in the CLI; undifferentiated exit codes

**Location:** `src/ossys/cli.py` (all commands)

No command wraps its delegate. `ValueError` from validators, `SystemError_`, `FileNotFoundError`,
and `CalledProcessError` all escape to Typer's default handler, producing a **Python
traceback on stderr and exit code 1** for every distinct failure mode.

Two problems. Operationally, a calling script cannot distinguish "bad username" from
"permission denied" from "useradd not installed" — every branch is `1`. That is the exact
gap Phase 2's exit-code taxonomy exists to close, and it is the single largest obstacle to
ossys being automatable. Informationally, tracebacks disclose absolute filesystem paths
and module layout on stderr, which in a CI log or a mailed cron report is gratuitous.

**Fix direction:** central exception handler mapping exception class → taxonomy code
(`10` validation, `20` permission, `30` external command, `40` no-op), human-readable
message on stderr, traceback only under `--debug`.

---

### OSSYS-SEC-010 — LOW — Full parent environment inherited into `sudo`-elevated children

**Location:** `src/ossys/system.py:65-87`

`subprocess.run` inherits `os.environ` wholesale. `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`,
and `IFS` all cross into a process that may be running as root. `sudo`'s own `env_reset`
defaults mitigate much of this on a correctly configured host — which is why this is LOW,
not MED — but the code should not be relying on the target host's `sudoers` hygiene for a
control it can enforce itself.

**Fix direction:** pass an explicit minimal `env=` (`PATH`, `LANG`, `LC_ALL` only).

---

### OSSYS-SEC-011 — LOW — No platform guard on Linux-only operations

**Location:** `src/ossys/system.py:65`, `src/ossys/cli.py:77-86`

`add_user` is documented "Linux only" and enforced nowhere. On Windows/macOS the failure
is an indirect `SystemError_: required tool not found: useradd`, which reads as a broken
installation rather than an unsupported platform. Confirmed live during this audit — see
§5.

**Fix direction:** explicit `sys.platform` check raising a distinct, clearly-worded error.

---

### OSSYS-SEC-012 — LOW — `sides` parameter unvalidated in `roll_cubes`

**Location:** `src/ossys/tasks.py:53-65`

`rounds` is bounds-checked; `sides` is not. `sides=0` or a negative value produces a raw
`ValueError` from `random.randint` internals ("empty range"), attributed to stdlib rather
than to the caller's bad input. Not currently CLI-reachable (`cli.py:42-52` does not expose
`--sides`), so this is a latent defect that becomes real the moment the flag is added.

**Fix direction:** validate `sides >= 2` alongside `rounds`.

---

### OSSYS-SEC-013 — LOW — Newline injection permits record forgery in `save_details`

**Location:** `src/ossys/tasks.py:75-78`

Field values are interpolated into a line-oriented format with no escaping:

```bash
ossys details --name $'Alice\nYour Age is: 99' --age 30 --phone 555
```

yields a file containing two `Your Age is:` lines. Harmless standalone; it matters as the
content-control half of `OSSYS-SEC-001`, and it matters if anything downstream ever parses
these files as records.

**Fix direction:** reject control characters in field values, or switch the output format
to JSON — which Phase 2 wants anyway.

---

### OSSYS-SEC-014 — LOW — Partial `.tgz` left on disk when a member is missing

**Location:** `src/ossys/tasks.py:90-97`

`tarfile.open(...)` creates and begins writing the destination immediately. The
`FileNotFoundError` for a missing member is raised **inside** the `with` block, after
earlier members have already been written. The context manager closes the file cleanly and
a truncated, valid-looking `.tgz` remains on disk. A backup job that failed leaves behind
an artifact indistinguishable from one that succeeded.

`test_archive_missing_file_raises` (`tests/test_tasks.py:48-50`) asserts the exception and
does **not** assert the absence of the output file — the test passes over the bug.

**Fix direction:** validate every member up front, before opening the destination; write to
a temp file and `os.replace` into place on success. Extend the existing test to assert
`not out.exists()`.

---

### OSSYS-SEC-015 — LOW — `menu.sh` writes a banner to stdout before `exec`

**Location:** `scripts/menu.sh:31-35`

```bash
echo "Examples:"
...
exec "${OSSYS[@]}" "$@"
```

Four lines of human-facing help are emitted on **stdout**, ahead of the command's real
output. Any caller doing `count=$(./scripts/menu.sh count 200)` gets the banner glued to
its data. This defeats Phase 2's `--json` work at the wrapper layer before it starts —
a JSON consumer piping through `menu.sh` receives unparseable output.

**Fix direction:** redirect the banner to stderr (`>&2`), or emit it only when no arguments
are supplied.

---

### OSSYS-SEC-016 — LOW — Supply-chain and coverage gaps in CI

**Location:** `.github/workflows/ci.yml`

- `uv sync --all-extras --dev` without `--frozen` / `--locked` — CI may silently resolve
  dependencies that differ from `uv.lock`, so the lockfile is not actually enforced.
- No dependency vulnerability scan (`pip-audit` / `uv pip audit`).
- No static security linter (`bandit`, or ruff's `S` ruleset — note `pyproject.toml:32`
  selects `E,F,I,UP,B,SIM,RUF` but **not** `S`, the flake8-bandit rules, which are exactly
  the ones that would flag `shell=True` and friends automatically on every commit).
- No coverage measurement or gate, despite Phase 5 requiring ≥80%.
- `mypy src` in CI vs. `files = ["src", "tests"]` in `pyproject.toml` — tests are type-checked
  locally but not in CI.

**Fix direction:** `--frozen`; add `S` to the ruff selection; add `pip-audit` and
`pytest-cov --cov-fail-under=80`; align the mypy invocation with the config.

---

### OSSYS-SEC-017 — INFO — Zip-slip is absent today and must stay that way by construction

**Location:** whole tree (`grep extractall` → no matches)

The brief calls out zip-slip in archive extraction. **There is no extraction code in ossys
at present** — `tasks.py` creates archives and never reads them. The vulnerability is
therefore not present.

Recording it as INFO rather than omitting it, because the moment an `ossys unarchive`
command is written it becomes an immediate HIGH: a member named `../../etc/cron.d/x`, or a
symlink member pointing outside the destination, is an arbitrary write as whatever user the
extraction runs as. `OSSYS-SEC-003` makes it likelier still that ossys-produced archives
contain symlink members.

**Fix direction (pre-emptive, Phase 1):** land a `safe_extract()` helper *with its tests*
before any extraction command exists — resolve each member against the destination root,
reject absolute paths, `..` traversal, symlink and hardlink members, and device/FIFO
members; enforce member-count and decompressed-size caps against zip-bombs. On Python 3.12+
set `tar.extraction_filter = tarfile.data_filter`; ship the explicit checks regardless,
since `requires-python = ">=3.10"` covers versions where that filter is unavailable.

---

### OSSYS-SEC-018 — LOW — pre-commit mypy hook lacks type dependencies

**Location:** `.pre-commit-config.yaml:8-11`

The `mirrors-mypy` hook declares no `additional_dependencies`, so it runs in an isolated
env without `typer`. It cannot see those types and will silently diverge from the CI mypy
run — the local gate is weaker than the remote one, which is the wrong way round.

**Fix direction:** `additional_dependencies: [typer, pytest]`, and pin the hook revs to
match the versions resolved in `uv.lock`.

---

## 4. Summary

| ID | Sev | Area | One-line |
|----|-----|------|----------|
| OSSYS-SEC-001 | **HIGH** | file write | `save_details` writes any path, follows symlinks, content attacker-controlled |
| OSSYS-SEC-002 | **HIGH** | file write | `archive_files` clobbers any path, follows symlinks |
| OSSYS-SEC-003 | MED | archive | `tar.add` recurses into directories silently |
| OSSYS-SEC-004 | MED | archive | basename collision → silent data loss on restore |
| OSSYS-SEC-005 | MED | subprocess | `_require()` result discarded; PATH re-resolved under `sudo` |
| OSSYS-SEC-006 | MED | subprocess | no `timeout=`; `sudo` prompt hangs forever in cron |
| OSSYS-SEC-007 | MED | subprocess | `usermod` preflight after `useradd` → partial state |
| OSSYS-SEC-008 | MED | input | unbounded `n` / `rounds` → OOM |
| OSSYS-SEC-009 | MED | CLI | no exception boundary; every failure exits `1` + traceback |
| OSSYS-SEC-010 | LOW | subprocess | full env inherited into elevated child |
| OSSYS-SEC-011 | LOW | portability | no platform guard on Linux-only ops |
| OSSYS-SEC-012 | LOW | input | `sides` unvalidated |
| OSSYS-SEC-013 | LOW | file write | newline injection → record forgery |
| OSSYS-SEC-014 | LOW | archive | partial `.tgz` survives a failed run |
| OSSYS-SEC-015 | LOW | wrapper | `menu.sh` banner pollutes stdout |
| OSSYS-SEC-016 | LOW | CI | unpinned sync, no `S` ruleset, no audit, no coverage gate |
| OSSYS-SEC-017 | INFO | archive | no extraction today; zip-slip controls required before any lands |
| OSSYS-SEC-018 | LOW | tooling | pre-commit mypy weaker than CI mypy |

**Totals:** 2 HIGH · 7 MED · 8 LOW · 1 INFO.

### What the existing hardening got right

Worth stating plainly, because the remediation must not regress it:

- No `shell=True`, no `os.system`, no `os.popen`, no `eval`/`exec` anywhere in the tree.
- Both subprocess call sites pass argv **lists**; the injection class the rewrite targeted
  is genuinely closed.
- `_USERNAME_RE` is anchored end-to-end **and** length-bounded — no `re.match`-prefix
  bypass, no embedded-newline bypass.
- Privilege escalation to the `sudo` group is opt-in, not default.
- `tests/test_system.py` asserts on the **exact argv lists**, so a regression to string
  building breaks the suite rather than passing quietly.

The theme of this audit is that the *command* boundary was hardened thoroughly and the
*filesystem* boundary was not hardened at all.

---

## 5. Environment note (not a code defect)

`uv run ossys` fails on the audit workstation:

```
error: uv trampoline failed to canonicalize script path
```

The console-script trampoline cannot handle the spaces in
`C:\Users\www83\Downloads\AI\GitHub Main\...`. `uv run python -m pytest -q` works and
returns `16 passed`. Windows is not a supported target for the privileged commands
(`OSSYS-SEC-011`), but this blocks local CLI smoke-testing on this machine. Phase 5 should
add a `python -m ossys` entrypoint, which sidesteps the trampoline entirely.
