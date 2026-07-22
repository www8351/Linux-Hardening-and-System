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

---

## D-017 — Webhook does not block private or link-local destinations

**Date:** 2026-07-21 · **Status:** Final

`validate_webhook_url` enforces a scheme allow-list and rejects embedded credentials, but
does **not** filter the destination address.

**Why:** the intended deployment is a fleet of endpoints reporting to an *internal*
collector — `https://ossys-collector.prod.internal/hook`, a 10.x address, a `.local` name.
SSRF-style private-range filtering would break the normal case while protecting against a
threat that does not exist here: the URL is operator-set in a root-owned config file, not
attacker-supplied. Blocking it would push operators toward `allow_http` or a public relay,
both strictly worse.

**Reconsider if:** ossys ever accepts a webhook URL from a non-operator source — a CLI flag,
an environment variable, an API. At that point the URL becomes untrusted input and the
filtering calculus inverts.

---

## D-018 — Webhook is a side channel that cannot affect the outcome

**Date:** 2026-07-21 · **Status:** Final

Every failure inside `notify.py` — DNS, refused connection, TLS handshake, timeout, non-2xx
— is caught and returned as a `WebhookResult`. Delivery problems produce a stderr warning
and nothing else. The local failure report is emitted *before* the POST is attempted.

**Why:** the caller is already on an error path. If a dead collector could raise, a
validation error (exit 10) would surface as a network error, and the operator would debug
the wrong thing. Emitting locally first also means a slow collector cannot delay or suppress
the operator-visible output.

**Rejected:** retries with backoff. On a scheduled tool, retrying multiplies the delay
between the failure and the operator seeing it, and the next timer tick will re-report
anyway. One attempt with a hard timeout.

---

## D-019 — Webhook secrets come from the environment, detail egress is opt-in

**Date:** 2026-07-21 · **Status:** Final

`token_env` names an environment variable rather than holding a token, and
`include_detail` defaults to **false**.

**Why the env var:** `ossys.toml` is installed 0644 and readable by every local user. A
config file is the wrong place for a bearer token. The systemd unit gains
`EnvironmentFile=-/etc/ossys/webhook.env` (0600 root:root) for it. URLs with embedded
credentials are rejected for the same reason.

**Why detail is opt-in:** `detail` usually carries an external command's stderr — usernames,
paths, host layout. Shipping that off-host by default is exactly the quiet data egress a
hardening tool should not do. When enabled it is truncated at 2000 characters.

---

## D-020 — Webhook URL validated at config load, not at send time

**Date:** 2026-07-21 · **Status:** Final

A bad URL fails the config with exit 50 and shows up in `ossys check`. Unknown keys in the
`[*.webhook]` table are rejected outright.

**Why:** the first real failure is the worst possible moment to discover that alerting is
broken. Validating eagerly moves that discovery to deployment. Rejecting unknown keys covers
the same class from the other side: a misspelled `on_failuer = false` would otherwise leave
alerting armed while the operator believes it is off.

`ossys check` deliberately does **not** send a test POST — the checkup is read-only and
schedulable, and one that fires an alert every run is worse than none. A `token_env` naming
an unset variable is a *failure*, not a warning, because the alert would be delivered
unauthenticated and silently dropped by the collector.

---

## D-021 — Plugins load via entry points, gated by an allow-list

**Date:** 2026-07-21 · **Status:** Final

Phase 4. Packages declare an entry point in the `ossys.plugins` group; ossys discovers and
mounts them. `[*.plugins] allowlist` pins which may load; `enabled = false` disables
discovery entirely.

**Why entry points:** it is the only mechanism that satisfies "new domains snap in without
touching core" without ossys maintaining a registry of known plugins — which would defeat
the point.

**Why the allow-list:** discovery imports third-party code into a process that, on the
privileged path, runs as root. Empty (allow all) is right for a workstation and wrong for a
fleet host, where any package landing in the venv — including as a transitive dependency —
could otherwise mount a root-run subcommand. The allow-list gates the **import**, not just
the mount, so a blocked package never executes module-level code.

**Rejected:** requiring explicit opt-in for every plugin (breaks the "snap in" goal on the
unprivileged path, where the risk is low). Also rejected: signature verification of plugin
packages — that is the package manager's job, and a half-implementation would imply a
guarantee ossys cannot make.

**Explicitly out of scope:** sandboxing. Once loading is permitted the plugin has full
process privilege. These controls decide *what loads* and record *what did*; they do not
contain it afterwards. The module docstring says so plainly rather than implying otherwise.

---

## D-022 — Plugins cannot shadow core commands, and duplicates are refused

**Date:** 2026-07-21 · **Status:** Final

A plugin named `useradd`, `check`, `plugins`, etc. is refused. Two distributions claiming the
same name: the first wins, the second is recorded as rejected.

**Why no shadowing:** an installed package could otherwise silently redefine a core command,
and every timer already pointing at it would quietly start running someone else's code
without a single config or unit file changing.

**Why refuse duplicates rather than pick one:** any silent resolution makes behaviour depend
on installation order, which is not reproducible across a fleet. Refusing the second is the
only deterministic outcome, and the rejection is visible in `ossys plugins`.

---

## D-023 — A broken plugin is recorded, not fatal; and every plugin is enumerable

**Date:** 2026-07-21 · **Status:** Final

Import failures are caught per plugin and reported as a row in `ossys plugins` and a check
row in `ossys check`. `ossys check --json` includes each loaded plugin's **distribution**.

**Why isolation:** a broken third-party package must not take down `ossys check` or the core
commands. Otherwise a cosmetic dependency problem becomes a fleet-wide outage, and the one
command that would diagnose it is the one that stopped working.

**Why the inventory:** a plugin host with no way to enumerate what it loaded is a
supply-chain blind spot. Rejected plugins are listed too, so "the subcommand is missing" is
distinguishable from "the allow-list blocked it" without reading config on the box.

---

## D-024 — Plugin registration happens in `main()`, before Typer parses argv

**Date:** 2026-07-21 · **Status:** Final

`main()` pre-scans argv for `--config` / `--profile`, loads Settings, and registers plugins
before invoking the app. The Typer callback then does the authoritative load.

**Why:** a subcommand that is not on the app cannot be dispatched to, so registration must
precede parsing — but the allow-list governing registration lives in the config file that
`--config` selects. The pre-scan is deliberately not a parser; anything it gets wrong is
corrected moments later by the callback.

**Failure handling:** if the pre-load raises, discovery is skipped entirely rather than
falling back to permissive defaults. A config we cannot parse is not a config whose
allow-list we should guess at. The real `ConfigError` still surfaces from the callback with
exit 50.

**Rejected:** registering at module import (no access to `--config`), and registering
everything then filtering at invocation time (the blocked package would already have been
imported, defeating the control).

---

## D-025 — Ship `py.typed`

**Date:** 2026-07-22 · **Status:** Final

**Why:** the package is checked under `mypy --strict`, but without the PEP 561 marker that
guarantee stopped at the package boundary — consumers saw `Any`. This matters more here than
for a typical library because Phase 4 tells plugin authors to import `ossys.validate` and
`ossys.privilege` rather than reimplement the checks. Shipping typed-but-unmarked was quietly
undermining the plugin contract.

---

## D-026 — sdist ships the tests, not the working notes

**Date:** 2026-07-22 · **Status:** Final

`[tool.hatch.build.targets.sdist]` includes `src`, `tests`, `deploy`, `examples`, `scripts`,
`README.md`, `LICENSE` and `SECURITY_AUDIT.md`. It excludes `STATUS.md`, `PROGRESS.md`,
`DECISIONS.md` and `CLAUDE_MEMORY.md`.

**Why include the tests:** they *are* the security contract — `test_system.py` asserts on
exact argv, `test_tasks.py` asserts the symlink refusals. Someone auditing the tarball should
see not just what the code does but how that is verified, and be able to re-run it.

**Why include SECURITY_AUDIT.md:** a consumer evaluating a hardening tool should be able to
read what was found and what was fixed without cloning the repo.

**Why exclude the rest:** session-by-session working notes have no value to a consumer, and
they date rapidly once frozen inside an immutable artefact.

---

## D-027 — The container image does not run as root by default

**Date:** 2026-07-22 · **Status:** Final

`USER ossys` (uid 10001). The privileged path is `docker run --user root`.

**Why:** consistent with every other privilege decision here — sudo-group membership is
opt-in, elevation is detected rather than assumed. A root-by-default image is a loaded gun
the moment somebody adds `-v /:/host`; opting in is one flag, while opting out after an
incident is not. uid 10001 sits outside the range Debian's adduser allocates, so an
in-container `ossys useradd` cannot collide with the image's own account.

**Rejected:** defaulting to root because "the container is the sandbox anyway". True for the
intended use, but the image will also be used in ways nobody predicted, and the default is
what those uses inherit.

**Also rejected:** a HEALTHCHECK. ossys is one-shot, not a service — there is no process to
probe, and a healthcheck on a container that exits immediately is noise. The equivalent
signal is `check --strict`, which exits 60 when the host is unfit.

---

## D-028 — CI executes the privileged path for real, inside a container

**Date:** 2026-07-22 · **Status:** Final

The Docker job runs `ossys useradd` as root in a throwaway container, actually mutating
`/etc/passwd`, then re-runs it to assert exit 40 and confirms the account with `id`.

**Why:** every unit test of that path mocks `subprocess` — deliberately, so no real user is
ever created on a developer's machine. That leaves the actual behaviour untested: argv
construction is verified, but not that `useradd` accepts it, nor that the pwd-based
idempotency probe agrees with real system state. The container makes running it for real
safe, which is the whole reason the Dockerfile exists.

**Constraint:** this must stay confined to the container job. The temptation to "just run it
in the main test job" would create real accounts on CI runners and, worse, normalise the
pattern for anyone running the suite locally.

---

## D-029 — Local gates must be at least as strict as CI

**Date:** 2026-07-22 · **Status:** Final

`.pre-commit-config.yaml` rewritten: mypy gains `additional_dependencies` and CI's exact
invocation, revs are pinned to the versions in `uv.lock`, and shellcheck plus hygiene hooks
are added.

**Why:** a pre-commit hook weaker than the remote check is the wrong way round — work looks
clean locally and fails on push, which trains people to skip the hook. OSSYS-SEC-018 was
exactly this: the mypy hook ran without typer, checked against `Any`, and passed code CI
rejected.

**shellcheck source matters:** `shellcheck-py` (a wheel) rather than
`koalaman/shellcheck-precommit` (a container). The container variant made `pre-commit run`
fail outright on a machine with Docker installed but not started. A local gate that depends
on Docker Desktop being up is a gate developers disable.

**Standing rule:** when a dev dependency is bumped in `uv.lock`, bump the matching
pre-commit rev. They had already drifted from 0.6.9/1.11.2 to 0.15.14/2.1.0.

---

## D-030 — The MCP surface is closed by default and widened only from config

**Date:** 2026-07-22 · **Status:** Final

Only read-only tools (`check`, `plugins`, `version`, `count`, `cubes`) are registered out of
the box. Anything that writes or mutates requires a name in `[defaults.mcp] expose`. There is
no CLI flag and no environment variable that can widen it.

**Why config-only:** an MCP server hands tool invocation to a language model, with
model-chosen arguments, in response to text that may have come from anywhere — a file it
read, a log line, a fetched page. Widening that surface should be an act with an audit trail.
A flag can be added by whatever launched the process; a file lives on the endpoint, is
reviewable, version-controllable and diffable. Same reasoning as `allowed_roots` (D-005).

**Rejected:** exposing everything and relying on the client's confirmation prompts. That
outsources the security boundary to a UI the operator does not control, and to a human who
will click through the twentieth prompt.

---

## D-031 — Privileged MCP tools require two independent opt-ins

**Date:** 2026-07-22 · **Status:** Final

`useradd` requires `allow_privileged = true` **in addition to** appearing in `expose`.
Neither alone is sufficient.

**Why:** the two decisions are genuinely different. "I want the model to be able to make
backups" and "I want the model to be able to create root-capable users" should not share a
switch — otherwise the first, made casually, silently grants the second. Two switches make
the dangerous one impossible to enable by accident or by copy-paste of someone else's config.

**Documented residual risk:** expose `useradd` and run `ossys-mcp` as root, and a
prompt-injected model can create accounts. No in-process validation prevents that. It is a
deployment decision, which is why it takes two switches and is reported by `ossys check`, by
`exposure_report()` and by the server's startup banner. Stating it plainly beats implying a
containment the design cannot deliver.

---

## D-032 — No generic command-runner tool, ever

**Date:** 2026-07-22 · **Status:** Final

There is deliberately no `run_command` / `exec` / `shell` MCP tool, and a test asserts none
appears.

**Why:** it is the single most tempting convenience and it would discard everything. Every
control in `ossys.privilege` — argv lists, resolved absolute paths, timeouts, closed stdin,
the minimal environment — exists because arbitrary command execution was the original defect.
Re-adding it behind an MCP tool would rebuild the `os.system` hole with a language model
holding the keyboard.

**Rejected:** an allow-listed command runner. An allow-list of commands is not the same
control as an allow-list of *operations with validated arguments*, and the distinction is
exactly what `validate_username` provides.

---

## D-033 — MCP tool bodies are MCP-free and return envelopes rather than raising

**Date:** 2026-07-22 · **Status:** Final

Handlers are plain functions taking `Settings` and returning `dict`, with no MCP types.
Failures come back as the same structured envelope the CLI emits under `--json`.

**Why plain functions:** they are testable without the optional `mcp` dependency, and the
registration layer stays a thin adapter instead of somewhere logic accumulates.

**Why returned, not raised:** the model should receive `{"exit_code": 20, "error":
"permission", ...}` — actionable, and identical to what a shell caller gets. An exception
surfaces to the client as an opaque tool error and, worse, may carry a traceback disclosing
host paths (the OSSYS-SEC-009 problem in a new place).

---

## D-034 — Tool annotations must be honest

**Date:** 2026-07-22 · **Status:** Final

`readOnlyHint` and `destructiveHint` are derived from the same table that decides exposure,
and a test asserts destructive tools are never marked read-only.

**Why:** clients use those hints to decide whether to warn or prompt. Marking a destructive
tool read-only to avoid a confirmation dialog would be actively dishonest — it would defeat a
protection the user believes is active. Keeping the annotations and the exposure gate driven
by one table makes them impossible to drift apart.

---

## D-035 — `settings` must never appear in a generated tool schema

**Date:** 2026-07-22 · **Status:** Final — regression-tested

`_bind` computes an explicit trimmed `__signature__` and never sets `__wrapped__`.

**Why:** this was a real defect, not a hypothetical. The first version used
`functools.update_wrapper` on a `functools.partial` to carry the docstring across.
`update_wrapper` sets `__wrapped__`, which makes `inspect.signature` follow through to the
unbound function — so `settings` reappeared as a required argument in every tool schema,
offering the model the object that carries `allowed_roots` and the privilege mode.

Found by printing the generated schemas rather than trusting that `partial` would hide the
parameter. Pinned by a test that iterates every registered tool and asserts `settings` is
absent, plus a CI step that does the same.

**Lesson recorded because it generalises:** `functools.partial` and
`functools.update_wrapper` do not compose the way they appear to. Anything that generates a
schema from a signature needs the schema asserted, not assumed.
