<div align="center">

# 🛠 ossys — Secure System-Task Automation CLI

**Small, real-world system-administration tasks as safe, testable Python — driven by a non-interactive CLI.**

A practical demonstration of secure systems programming: no more `os.system('... {} ...'.format(user_input))`.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![uv](https://img.shields.io/badge/packaged%20with-uv-DE5FE9?logo=astral&logoColor=white)
![Ruff](https://img.shields.io/badge/lint-ruff-D7FF64?logo=ruff&logoColor=black)
![mypy](https://img.shields.io/badge/types-mypy%20strict-2A6DB2)
![pytest](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

## 📖 Overview

`ossys` is a small command-line toolkit for everyday system-administration chores —
provisioning Linux users, creating archive/backup tarballs, and generating files. Its real
purpose is to show these tasks done **securely**: the codebase is a deliberate refactor of a
set of beginner scripts that built shell commands out of user input (a classic injection
vulnerability) into validated, shell-free Python with strict typing, tests, and CI.

> **Scope note:** This is a *secure-automation* and *secure-coding* showcase. It performs
> system automation and demonstrates defensive InfoSec practice (injection remediation, input
> validation, least-privilege execution). It is **not** a host-hardening suite — it does not
> configure firewalls, SSH, `sysctl`, or apply CIS benchmarks.

---

## ⚙️ What the scripts do

Each subcommand of the `ossys` CLI maps to a focused task:

| Command   | Category            | What it does                                                            |
|-----------|---------------------|-------------------------------------------------------------------------|
| `useradd` | OS / Security        | Provisions a Linux user (optionally adding it to `sudo`) via validated, shell-free `subprocess` calls. **Requires root/sudo.** |
| `archive` | Automation / Backup  | Creates a gzip tarball of the given files using the stdlib `tarfile` module (no `tar` shell-out). |
| `details` | Automation / File-gen| Writes contact details to a file with `pathlib` (no `echo >` shell-out). |
| `count`   | Utility / Demo       | Prints `1..N` — a minimal pure-function example.                         |
| `cubes`   | Utility / Demo       | Rolls two cubes per round with an injectable, seedable RNG for reproducibility. |

The logic lives in tested Python; a thin Bash wrapper
([`scripts/menu.sh`](scripts/menu.sh)) can still drive it for shell-centric workflows.

---

## 🔐 Security design

The headline is **input never reaches a shell**. The refactor removed every
`os.system(...format())` call and replaced it with safer primitives:

| Before ❌ | After ✅ |
|----------|---------|
| `os.system('sudo useradd ' + name)` | `subprocess.run(["sudo", "useradd", name])` + strict username validation |
| `os.system('echo .. > file')`, `os.system('tar ..')` | `pathlib` write, `tarfile` module — pure stdlib, no shell |
| `while "True"` `input()` menus | non-interactive Typer CLI (arguments only) |
| Linux-only, untested | pure functions, cross-platform where possible, full `pytest` suite |

Concretely:

- **No shell, ever.** External commands are passed to `subprocess.run` as *argument lists*,
  so a username like `"bob; rm -rf /"` is treated as a single literal argv entry, not two
  shell commands. `shell=True` appears nowhere.
- **Strict input validation.** `validate_username` enforces an anchored allow-list
  (`^[a-z_][a-z0-9_-]{0,31}$`) at the trust boundary, before any value reaches subprocess.
- **Least privilege.** `sudo` is only prefixed when needed, and group escalation happens
  only when the caller explicitly opts in (`--sudo`).
- **Fail loud, not partial.** Required tools (`useradd`, `usermod`) are resolved up front;
  archive members must exist or the operation raises instead of producing a partial result.
- **Privileged code is tested without touching the host.** `subprocess` and tool lookup are
  mocked in the test suite, so the security contract is verified and no real user is created.

---

## 📋 Prerequisites

| Requirement | For |
|-------------|-----|
| **Python 3.10+** | Everything |
| **[`uv`](https://docs.astral.sh/uv/)** (recommended) or `pip` | Installing & running |
| **Linux** with `useradd` / `usermod` available, plus **root or `sudo`** | The `useradd` command only |
| **`shellcheck`** | Linting the Bash wrapper (development) |

The `count`, `cubes`, `details`, and `archive` commands are cross-platform and need no
elevated privileges. Only `useradd` is Linux-specific and privileged.

Install:

```bash
uv sync --dev          # create the environment and install dev tooling
```

---

## ⚠️ Safety Warning

These are system-level execution scripts. Read before running:

- **`ossys useradd` changes real system state.** It creates an account and (with `--sudo`)
  grants administrative group membership. It needs root/sudo and is **not reversible by this
  tool** — it does not delete users. Test it in a **disposable VM or container** before using
  it on a machine you care about.
- **`details` and `archive` write to the filesystem and will overwrite** an existing file at
  the target path (`-o/--out`) without prompting. Point them at safe locations.
- **Review before you run.** As with any privileged automation, read what a command does and
  confirm the arguments — especially the username and output paths — before executing it on a
  real host.
- The randomness in `cubes` uses Python's `random` module and is for demo/utility output
  only; it is **not** suitable for cryptographic or security-sensitive use.

---

## 📦 Usage

```bash
uv run ossys count 200
uv run ossys cubes 7 --seed 42
uv run ossys details --name Refael --age 30 --phone 555 -o details.txt
uv run ossys archive a.txt b.txt -o backup.tgz
uv run ossys useradd refael --sudo        # Linux only; requires root/sudo
```

Bash wrapper (forwards arguments straight to the CLI):

```bash
./scripts/menu.sh count 200
```

---

## 🧱 Project layout

| Path | Responsibility |
|------|----------------|
| `src/ossys/tasks.py` | Pure, shell-free task logic: `count_to`, `roll_cubes`, `save_details`, `archive_files` |
| `src/ossys/system.py` | Privileged ops via validated, list-arg `subprocess` calls + username validation |
| `src/ossys/cli.py` | Non-interactive Typer entrypoint (the `ossys` console script) |
| `scripts/menu.sh` | Thin Bash wrapper (replaces the old interactive menu) |
| `tests/` | `pytest` suite, including mocked privileged-operation tests |

---

## 🧪 Development & CI

```bash
uv run ruff check .          # lint
uv run ruff format .         # format
uv run mypy src              # strict type-checking
uv run pytest                # tests
shellcheck scripts/menu.sh   # lint the Bash wrapper
```

CI runs lint + format check + `mypy --strict` + tests + `shellcheck` on the wrapper on every
push.

---

## 📄 License

Released under the [MIT License](LICENSE).
