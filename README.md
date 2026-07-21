<div align="center">

# 🛠 ossys

**Small system tasks as safe, testable Python with a non-interactive CLI.**
*משימות מערכת קטנות כפייתון בטוח ובר-בדיקה  עם CLI לא-אינטראקטיבי.*

No more `os.system('... {} ...'.format(user_input))`.

[![CI](https://github.com/www8351/Linux-Hardening-and-System/actions/workflows/ci.yml/badge.svg)](https://github.com/www8351/Linux-Hardening-and-System/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![uv](https://img.shields.io/badge/packaged%20with-uv-DE5FE9?logo=astral&logoColor=white)
![Ruff](https://img.shields.io/badge/lint-ruff-D7FF64?logo=ruff&logoColor=black)
![mypy](https://img.shields.io/badge/types-mypy%20strict-2A6DB2)
![pytest](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Last commit](https://img.shields.io/github/last-commit/www8351/Linux-Hardening-and-System?color=informational)

</div>

---

## 🌍 What is this? · מה זה?

<table>
<tr>
<td width="50%" valign="top">

### 🇬🇧 English

**ossys** turns a set of common Linux admin tasks user management, file writes,
archiving, dice/counting utilities into **pure, testable Python** behind a
non-interactive Typer CLI. It replaces unsafe `os.system(...format())` string-building
with `subprocess` list-args and strict input validation, so user input **never reaches a shell**.

</td>
<td width="50%" valign="top">

<div dir="rtl">

### 🇮🇱 עברית

**ossys** הופך אוסף משימות ניהול נפוצות בלינוקס ניהול משתמשים, כתיבת קבצים, ארכוב,
כלי ספירה/קוביות ל**פייתון טהור ובר-בדיקה** מאחורי CLI לא-אינטראקטיבי מבוסס Typer.
הוא מחליף בניית-מחרוזות מסוכנת של `os.system(...format())` בארגומנטים-כרשימה ל-`subprocess`
ובוולידציית קלט קפדנית, כך שקלט המשתמש **לעולם לא מגיע ל-shell**.

</div>

</td>
</tr>
</table>

---

## 💡 Why

The originals (`all_in_one.py`, `menu_python.py`, `Bash Call Pyhton/pro_*.py`) built shell
commands from user input with `os.system(...format())` a textbook injection hole and ran as
blocking `input()` menus.

| Before ❌ | After ✅ |
|----------|---------|
| `os.system('sudo useradd ' + name)` | `subprocess.run(["sudo","useradd", name])` + username validation |
| `os.system('echo .. > file')`, `os.system('tar ..')` | `pathlib` write, `tarfile` module |
| `while "True"` `input()` menus | non-interactive Typer CLI (args only) |
| Linux-only, no tests | pure functions, cross-platform where possible, `pytest` |

Bash can still drive it see [`scripts/menu.sh`](scripts/menu.sh) but the logic lives in tested Python.

---

## 📦 Use

```bash
uv sync --dev

uv run ossys count 200
uv run ossys cubes 7 --seed 42
uv run ossys details --name Refael --age 30 --phone 555 -o details.txt
uv run ossys archive a.txt b.txt -o backup.tgz
uv run ossys useradd refael --sudo        # Linux only
```

Bash wrapper (forwards args to the CLI):

```bash
./scripts/menu.sh count 200
```

---

---

## 🤖 Automate it · Two paths, one build

ossys runs unattended on either a privileged or an unprivileged endpoint, from the same
install. It detects which it is on, and `ossys check` tells you before anything is scheduled.

| | **Privileged** | **Unprivileged** |
|---|---|---|
| Privilege | root (euid 0), or passwordless `sudo -n` | never elevates |
| Scheduler | `ossys-system.timer` · `/etc/cron.d/ossys` | `systemctl --user` timer · user crontab |
| Config | `/etc/ossys/ossys.toml` | `~/.config/ossys/ossys.toml` |
| `useradd` etc. | runs | refuses cleanly, exit `20` |
| Install | `sudo ./deploy/install-endpoint.sh --path system` | `./deploy/install-endpoint.sh --path user` |

```bash
./deploy/install-endpoint.sh --path auto     # picks the path, installs, verifies, then arms
```

The installer will not enable a timer until `ossys check` passes on that host.

### The checkup

```bash
ossys check              # human table; exit 0 fit, 60 unfit
ossys check --json       # structured, for fleet collection
ossys check --strict     # warnings are failures — the deployment gate
```

Verifies the privilege path, required binaries, config discovery, and that every configured
output root exists and is writable. Read-only — safe to schedule anywhere.

### Exit codes

Scripts branch on the number, never on parsed text.

| Code | Meaning |
|-----:|---------|
| `0` | success |
| `10` | validation error — bad input |
| `20` | permission — no elevation route on this endpoint |
| `30` | external command failed or timed out |
| `40` | **no-op** — already in the desired state (a *success* outcome) |
| `50` | config missing/malformed/unknown profile |
| `60` | preflight failed — host unfit |

`0` and `40` both mean "fine". Both systemd units set `SuccessExitStatus=40`.

### Per-endpoint config

One `ossys.toml` can serve a whole fleet — profiles select themselves by hostname glob.

```toml
[defaults]
mode = "auto"              # auto | root | sudo | user
allowed_roots = ["."]      # where --out may write. This is a security boundary.
timeout = 30

[profile.server]
hosts = ["srv-*", "*.prod.internal"]
mode = "sudo"
allowed_roots = ["/var/lib/ossys"]
json = true

[profile.workstation]
hosts = ["dev-*", "*-laptop"]
mode = "user"
allowed_roots = ["~/ossys"]
```

Start from [`deploy/ossys.toml.example`](deploy/ossys.toml.example).

> **Breaking change:** `--out` is now contained to `allowed_roots` (default: the working
> directory). `ossys details -o /etc/foo` exits `10` instead of writing. See `DECISIONS.md`
> D-005.

### Machine-readable output

```bash
ossys --json archive a.log -o backup.tgz | jq -r .path
ossys --dry-run useradd alice --sudo        # validate and resolve, change nothing
```

`--json` puts a single JSON document on stdout and nothing else — diagnostics go to stderr,
on both the success and failure paths.

---

## 🧱 Layout

| Module | Responsibility |
|--------|----------------|
| `validate.py` | the trust boundary — usernames, output paths, bounds, archive members |
| `exits.py` | exit-code taxonomy + error hierarchy |
| `privilege.py` | root/sudo/user detection; shell-free, bounded command execution |
| `config.py` | TOML per-endpoint config and profile selection |
| `preflight.py` | the `ossys check` endpoint checkup |
| `output.py` | JSON / human emitter (all output goes through here) |
| `tasks.py` | pure logic: `count_to`, `roll_cubes`, `save_details`, `archive_files` |
| `system.py` | privileged ops via the privilege layer + username validation |
| `cli.py` | non-interactive Typer entrypoint and the single exception boundary |
| `scripts/ossys-run.sh` | scheduled-run wrapper — gates on `ossys check`, passes exit codes through |
| `scripts/menu.sh` | thin bash wrapper (replaces the old interactive menu) |
| `deploy/` | systemd units, cron files, config example, endpoint installer |

---

## 🧪 Develop

```bash
uv run ruff check .
uv run ruff format .
uv run mypy src
uv run pytest
```

CI runs lint + format + mypy + tests + `shellcheck` on the wrapper on every push.

## 🔐 Security

User input never reaches a shell. `add_user` validates the username against a strict
pattern and passes argument **lists** to `subprocess`, so `"bob; rm -rf /"` is rejected,
not executed.

Beyond that, from the audit in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) (18 findings —
2 HIGH, 7 MED, 8 LOW, 1 INFO):

- **Output paths are contained.** `--out` is resolved, refused if it or its parent is a
  symlink, and must land inside `allowed_roots`. Previously any path was writable, and
  `write_text` followed symlinks — under `sudo` that was an arbitrary root-owned file write.
- **Writes are atomic.** Temp file in the destination directory, `os.replace` on success. A
  failed archive no longer leaves a truncated `.tgz` that looks like a good one.
- **Binaries are pinned.** Tools are resolved with `shutil.which` and the *resolved absolute
  path* is executed, so a mutable `PATH` cannot swap the binary between check and exec.
- **Nothing can hang.** Every subprocess call has a `timeout`, closed stdin, and `sudo -n`
  — a stalled credential fails fast instead of blocking a cron job forever.
- **Minimal child environment.** `PATH`/`LANG`/`LC_ALL`/`TZ` only. No `LD_PRELOAD`, no `IFS`.
- **All-or-nothing.** Every binary an operation needs is resolved before the first mutating
  call, so a partly-provisioned host cannot leave half-created state behind.
- **No archive surprises.** Members must be regular files (directories are not silently
  recursed into) and basename collisions are rejected rather than losing a file at restore.
- **Clean failures.** No tracebacks leaking absolute paths into CI logs or cron mail.

Enforced on every commit by ruff's `S` (flake8-bandit) ruleset, mypy `--strict`, and an
80% coverage gate.

---

## 🏷 Topics

`python` · `cli` · `typer` · `subprocess` · `security` · `shell-injection` · `rich` ·
`uv` · `mypy` · `ruff` · `pytest` · `devtools` · `sysadmin` · `cross-platform`
