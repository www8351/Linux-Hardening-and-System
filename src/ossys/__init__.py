"""Package:  ossys

Purpose:  Secure system-task automation. Small, real-world admin tasks (user provisioning,
          archiving, file generation) implemented as safe, testable functions and exposed
          through a non-interactive CLI.

Layout:   tasks.py   -> pure, shell-free task logic
          system.py  -> privileged ops via validated, list-arg subprocess calls
          cli.py     -> Typer entrypoint (the `ossys` console script)

Security: User input never reaches a shell anywhere in this package. See the module-level
          headers in `system.py` and `tasks.py` for the per-module rationale.
"""

__version__ = "0.1.0"
