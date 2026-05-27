<div align="center">

# 🛠 ossys

**Small system tasks as safe, testable Python — with a non-interactive CLI.**

No more `os.system('... {} ...'.format(user_input))`.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![uv](https://img.shields.io/badge/packaged%20with-uv-DE5FE9?logo=astral&logoColor=white)
![Ruff](https://img.shields.io/badge/lint-ruff-D7FF64?logo=ruff&logoColor=black)
![mypy](https://img.shields.io/badge/types-mypy%20strict-2A6DB2)
![pytest](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

## 💡 Why

The originals (`all_in_one.py`, `menu_python.py`, `Bash Call Pyhton/pro_*.py`) built shell
commands from user input with `os.system(...format())` — a textbook injection hole — and ran as
blocking `input()` menus.

| Before ❌ | After ✅ |
|----------|---------|
| `os.system('sudo useradd ' + name)` | `subprocess.run(["sudo","useradd", name])` + username validation |
| `os.system('echo .. > file')`, `os.system('tar ..')` | `pathlib` write, `tarfile` module |
| `while "True"` `input()` menus | non-interactive Typer CLI (args only) |
| Linux-only, no tests | pure functions, cross-platform where possible, `pytest` |

Bash can still drive it — see [`scripts/menu.sh`](scripts/menu.sh) — but the logic lives in tested Python.

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

## 🧱 Layout

| Module | Responsibility |
|--------|----------------|
| `tasks.py` | pure logic: `count_to`, `roll_cubes`, `save_details`, `archive_files` |
| `system.py` | privileged ops via `subprocess` list-args + username validation |
| `cli.py` | non-interactive Typer entrypoint |
| `scripts/menu.sh` | thin bash wrapper (replaces the old interactive menu) |

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
