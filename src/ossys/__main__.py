"""Module:   ossys.__main__

Purpose:  Makes ``python -m ossys`` equivalent to the ``ossys`` console script.

Why:      SECURITY_AUDIT.md §5 — the uv console-script trampoline fails on paths containing
          spaces ("uv trampoline failed to canonicalize script path"), which blocks local
          smoke-testing on the dev workstation. More importantly for deployment, `python -m`
          needs no PATH entry and no shim, so a systemd unit or cron job can invoke ossys
          through an absolute interpreter path inside a venv without depending on the
          console script having been installed correctly.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
