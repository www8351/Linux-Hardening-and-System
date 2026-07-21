# DECISIONS.md — ossys

Decision log. Why things were decided, what was rejected, and whether the door is closed.

---

## D-001 — Phase 0 produces findings only; no fixes in the same pass

**Date:** 2026-07-21 · **Status:** Final

Audit and remediation are separated. `SECURITY_AUDIT.md` is written and approved before any
fix commit lands.

**Why:** An audit that fixes as it goes cannot be reviewed — the reviewer sees the patch,
not the exposure, and cannot check the severity reasoning that justified the patch. It also
makes "zero regressions, tests green before commit" unverifiable, because there is no clean
baseline to compare against. The baseline here is `15d27d8` / `16 passed`.

**Rejected:** Fix-as-you-find. Faster, but conflates two review questions and destroys the
before/after signal.

---

## D-002 — Severity rated against a `sudo`-invoked deployment model

**Date:** 2026-07-21 · **Status:** Final (confirmed same day)

`OSSYS-SEC-001` and `OSSYS-SEC-002` (unvalidated output paths) are rated HIGH on the
assumption that ossys is genuinely run elevated in production.

**Confirmed:** the follow-up request asked for a privileged automation path alongside an
unprivileged one, which settles the open question — ossys does run elevated on the target
endpoints. The HIGH ratings stand, and Phase 1 led with the filesystem fixes accordingly.

**Why:** The tool ships a `useradd` command, which cannot work without root. Once *any*
invocation runs under `sudo`, an arbitrary-file-write primitive with attacker-influenced
content is a privilege-escalation chain, not a nuisance.

---

## D-003 — Zip-slip recorded as INFO, not omitted

**Date:** 2026-07-21 · **Status:** Final

No extraction code exists in the tree, so zip-slip is not a present vulnerability. It is
logged as `OSSYS-SEC-017` (INFO) with mandatory pre-emptive controls rather than dropped.

**Why:** Silently omitting it would read to a future maintainer as "audited, clean" — the
most dangerous kind of gap. Recording it as INFO makes the constraint explicit: the
`safe_extract()` helper and its tests land *before* any extraction command, not after.

**Rejected:** Omit (creates a false clean signal). Also rejected: rate it HIGH now
(inflates the report with a non-existent vulnerability and devalues the two real HIGHs).

**Still open by design.** No extraction command has been written, so no `safe_extract()`
exists yet. This remains the gate on any future `ossys unarchive`.

---

## D-004 — One shared validator module, not per-function checks

**Date:** 2026-07-21 · **Status:** Final — implemented

`src/ossys/validate.py` holds every allowlist: usernames, output paths, integer bounds,
archive members, text fields. `validate_username` moved out of `system.py`.

**Why:** The audit found validation applied unevenly — usernames were rigorously checked
while output paths were not checked at all. Ad-hoc per-function validation is exactly how
that asymmetry arose, and it will recur as Phase 4 adds plugin domains. A single module is
also the only way a "no unvalidated value reaches the system" rule becomes greppable and
enforceable.

**Rejected:** Pydantic models for validation. Adds a runtime dependency to a stdlib-only
tool for logic that is a handful of regexes and bounds checks. Reconsider only if the
TOML config layer grows complex enough to need real schema validation.

**Compatibility:** `system.py` re-exports `validate_username`, so existing importers and
`tests/test_system.py` keep working.

---

## D-005 — Output-path containment is a breaking change; resolved as configurable roots

**Date:** 2026-07-21 · **Status:** Final — resolved as option 3

Fixing `OSSYS-SEC-001/002` means `--out` can no longer write anywhere on the filesystem.

**Options considered:**
1. Contain to CWD by default; escape hatch via config. Safest; breaks `ossys details -o /tmp/x.txt`.
2. Allow any path but refuse symlinks and symlinked parents. Least disruptive; leaves the
   arbitrary-write primitive intact under `sudo`.
3. Contain to a configurable allowed-roots list, defaulting to `[CWD]`.

**Resolved: option 3.** `Settings.allowed_roots` defaults to `["."]` and is widened per
endpoint in `ossys.toml`. Chosen because the same request that settled D-002 also asked for
per-endpoint customisation, and an allowed-roots list is exactly that: policy that travels
with the machine rather than with the command line. Option 2 was rejected outright — it
would have left the primitive that made both findings HIGH fully intact.

**This is a breaking change.** `ossys details -o /etc/foo` now exits 10 instead of writing.
Widening the boundary is an explicit, auditable edit to a config file. Belongs in the
changelog.

---

## D-006 — Non-interactivity enforced at runtime, not merely intended

**Date:** 2026-07-21 · **Status:** Final — implemented

Every `subprocess.run` carries `timeout=` and `stdin=subprocess.DEVNULL`, and `sudo` is
always invoked with `-n`.

**Why:** `OSSYS-SEC-006`. The project guaranteed non-interactive operation, but nothing
enforced it — a `sudo` password prompt on an expired credential blocks forever on a TTY that
does not exist, hanging cron jobs and systemd units. Design intent that the runtime does not
enforce is not a guarantee. `-n` and the timeout are independent controls: `-n` makes sudo
specifically fail instead of prompting, the timeout bounds *any* child regardless of binary.

---

## D-007 — Ruff `S` (flake8-bandit) rules enabled rather than adding bandit

**Date:** 2026-07-21 · **Status:** Final — implemented

`pyproject.toml` now selects `E,F,I,UP,B,SIM,RUF,S`.

**Why:** The `S` ruleset flags `shell=True`, `subprocess` without validation, and unsafe
`tarfile` use automatically on every commit — turning this audit's core findings into a
permanent regression gate. Ruff is already in the toolchain and pre-commit hooks.

**Rejected:** Adding `bandit` as a separate CI step. Duplicate coverage, extra dependency,
slower CI, and a second config to keep in sync.

---

## D-008 — Three privilege modes, resolved once, with the reason attached

**Date:** 2026-07-21 · **Status:** Final

`ossys.privilege.detect_mode()` returns ROOT (euid 0), SUDO (passwordless `sudo -n` works) or
USER (no elevation route), wrapped in a `PrivilegeReport` that carries *why* it chose that.

**Why three and not two:** ROOT and SUDO differ in what they prepend to argv, and USER is not
a degraded privileged mode — it is a first-class deployment target (the `systemctl --user`
path) where privileged commands should refuse cleanly rather than fail halfway.

**Why the reason field:** across a fleet, "host 47 picked USER" is not actionable. "sudo not
installed" versus "`sudo -n` requires a password" are different remediations. `ossys check`
surfaces it.

**Why `sudo -n true` and not parsing `sudoers`:** it is a real credential test rather than a
prediction, and `-n` guarantees the probe itself cannot hang waiting for a password.

**Rejected:** inferring privilege from `os.getuid() == 0` alone. That conflates "cannot
elevate" with "not currently elevated", and would have sent every service account down the
USER path even where passwordless sudo was configured for exactly this purpose.

---

## D-009 — A forced privilege mode fails loudly rather than degrading

**Date:** 2026-07-21 · **Status:** Final

`mode = "root"` in config on a non-root host raises `PermissionDenied`. It does not fall back
to SUDO or USER.

**Why:** silent degradation changes what a scheduled unit *does* without the unit file
changing. An operator who pinned `mode = "sudo"` wants to know the credential expired, not to
discover weeks later that the job has been quietly no-opping. Pinning the mode in the unit
file (rather than leaving it `auto`) also means a later-granted sudo rule cannot silently
promote an unprivileged timer to a privileged one.

---

## D-010 — Idempotency modelled as an exception carrying exit code 40

**Date:** 2026-07-21 · **Status:** Final

`AlreadyDone` short-circuits the operation but is reported as a **success** outcome
(`Exit.NOOP = 40`), distinct from `Exit.OK`.

**Why an exception:** it must abort the remaining steps, which is what exceptions are for.
**Why a distinct code:** a scheduler needs to tell "created the user" from "user already
existed" without parsing text, and re-running is the normal case for a timer. Collapsing it
into 0 loses real signal; treating it as an error makes the command non-automatable.

Callers branching on failure must treat 0 and 40 alike — documented in the taxonomy, handled
in `ossys-run.sh`, and set as `SuccessExitStatus=40` in both systemd units.

**Rejected:** a `--force` / `--if-not-exists` flag. That pushes the decision to every call
site; idempotency should be the default for a tool designed to be re-run on a schedule.

---

## D-011 — Exit-code taxonomy extended beyond the five codes in the brief

**Date:** 2026-07-21 · **Status:** Final

The brief specified `0/10/20/30/40`. Added `50` (config) and `60` (preflight).

**Why:** both are operationally distinct and common. A malformed `ossys.toml` is not a
validation error in the caller's *input* — the caller passed nothing wrong — and a failed
checkup is not an external-command failure. Folding either into `30` would make the two most
likely fleet-deployment failures indistinguishable from "useradd returned non-zero", which is
precisely the ambiguity the taxonomy exists to remove.

Values are spaced by ten so sub-cases can be slotted in later. Codes are treated as stable
API: new failure classes take a new number and never recycle an old one.

---

## D-012 — Usage errors keep Click's exit code 2, outside the ossys taxonomy

**Date:** 2026-07-21 · **Status:** Final

An unknown flag or missing argument exits 2 with Click's own message, not a remapped ossys
code.

**Why:** the taxonomy describes *operational outcomes* on a host. "You typed the command
wrong" is not one — it is a caller bug, it happens before any work starts, and 2 is the
long-standing Unix convention for it. Remapping it to 10 (validation) would blur the line
between "this endpoint rejected your input" and "this invocation was never valid".

---

## D-013 — Deploy assets shipped as real units, not documentation snippets

**Date:** 2026-07-21 · **Status:** Final

`deploy/` contains installable systemd units, cron files, a config example and an installer,
rather than a README section showing what to write.

**Why:** the brief asked for reference automation, not just docs. It also lets the hardening
live in version control and be reviewed — `ProtectSystem=strict` plus
`ReadWritePaths=/var/lib/ossys` in the root unit means a path-traversal bug in ossys cannot
write outside the archive directory even if the in-process containment check were bypassed.
That is defence in depth for OSSYS-SEC-001/002 that a docs snippet would not provide.

**Caveat recorded:** the `ExecStart` lines are illustrative examples and must be edited before
any timer is enabled. Noted in `STATUS.md` under "Needs review".

---

## D-014 — CLI tests drive `main()`, not Typer's `CliRunner`

**Date:** 2026-07-21 · **Status:** Final

**Why:** `main()` *is* the exception boundary, and the thing every console-script, systemd and
cron invocation actually calls. Testing the Typer app object leaves the entrypoint uncovered.

This is not theoretical. Writing these tests immediately caught two real defects that
app-level tests could not have: `main()` discarded the value returned by
`app(standalone_mode=False)`, silently collapsing every deliberate `typer.Exit` — including
`check --strict` failures — to 0; and `find_config` raised `IndexError` (mapped to exit 30)
instead of `ConfigError` (50) when handed an explicit missing path. A third defect, an
`import click` that would have crashed the entrypoint outright under Typer 0.26, was found by
inspection while the suite still had no `main()` coverage at all.

---

## D-015 — `no_implicit_reexport` worked around in tests, not disabled

**Date:** 2026-07-21 · **Status:** Final

Tests use monkeypatch's string-target form
(`monkeypatch.setattr("ossys.privilege.shutil.which", ...)`) rather than attribute access on
the imported module.

**Why:** mypy strict flags `privilege.shutil` as reaching a non-exported attribute. A
per-module override does not fix it — the rule is evaluated against the module being *read
from*, not the reader — so the alternatives were relaxing `implicit_reexport` for `ossys.*`
(which weakens `src`) or disabling `attr-defined` for tests (a genuinely useful check). The
string form sidesteps the issue and keeps both trees fully strict.

---

## D-016 — Ruff `S311` suppressed for the dice RNG rather than switching to `secrets`

**Date:** 2026-07-21 · **Status:** Final

**Why:** `roll_cubes` is demo/utility output, documented as such in the module header. Using a
CSPRNG there would imply a security guarantee ossys does not make, and would break the
injectable-`random.Random` seam the tests rely on for determinism. Suppressed per-file so the
`S` ruleset stays enabled everywhere else — including on the subprocess call sites, which is
the reason it was turned on (D-007).
