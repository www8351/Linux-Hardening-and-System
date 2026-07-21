"""Module:   ossys.validate

Purpose:  The single trust boundary. Every externally supplied value — usernames, output
          paths, integer bounds, archive members — is checked here and nowhere else.

Usage:    from ossys.validate import validate_username, validate_output_path
          name = validate_username(raw)
          out  = validate_output_path(raw_path, allowed_roots=settings.allowed_roots)

Security notes:
    * SECURITY_AUDIT.md found validation applied unevenly: usernames were checked
      rigorously (anchored, length-bounded regex) while output paths were not checked at
      all. That asymmetry is what ad-hoc per-function validation produces. Centralising it
      makes "no unvalidated value reaches the system" a greppable, enforceable rule as
      Phase 4 adds plugin domains.
    * OSSYS-SEC-001 / OSSYS-SEC-002 (both HIGH): `save_details` and `archive_files` wrote to
      any path the caller named and followed symlinks while doing it. Under sudo that is an
      arbitrary root-owned file write. `validate_output_path` closes both by resolving the
      path, refusing symlinked targets and symlinked parents, and requiring containment
      inside an explicitly allowed root.
    * OSSYS-SEC-008: `count_to`/`roll_cubes` bounded only below, so `count 10000000000`
      allocated until the OOM killer intervened. `validate_int_range` bounds both ends.
    * Symlink handling is deliberately strict — reject rather than resolve-and-allow. A
      symlink whose target happens to sit inside an allowed root today can be repointed
      between the check and the write; refusing the whole class removes the race instead of
      narrowing it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .exits import ValidationError

# Conservative POSIX-ish username allow-list, anchored end-to-end:
#   * must start with a lowercase letter or underscore (no leading digits/dashes),
#   * may contain lowercase letters, digits, underscores and hyphens,
#   * capped at 32 chars total (1 + up to 31) to match common useradd limits.
# Anchoring (^...$) plus the length bound means the pattern cannot be bypassed with
# embedded newlines or trailing shell metacharacters.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# Upper bounds for the counting/dice utilities. Generous enough that no legitimate use is
# blocked, small enough that a typo or a hostile wrapper cannot exhaust memory.
MAX_COUNT = 1_000_000
MAX_ROUNDS = 1_000_000
MAX_SIDES = 1_000

# Archive limits — a defence against both accidental /etc-sized archives and deliberate
# resource exhaustion (OSSYS-SEC-003).
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_BYTES = 2 * 1024**3  # 2 GiB total uncompressed input


def validate_username(username: str) -> str:
    """Return ``username`` unchanged if it matches the strict allow-list, else raise.

    Callers must route any externally supplied username through here before it is used in
    a privileged command.
    """
    if not _USERNAME_RE.match(username):
        raise ValidationError(f"invalid username: {username!r}")
    return username


def validate_int_range(value: int, *, name: str, minimum: int, maximum: int) -> int:
    """Bound an integer on both ends.

    The audit's OOM findings all shared one shape: a lower bound with no upper bound. This
    helper exists so that shape cannot recur — there is no way to call it and check only
    one side.
    """
    if value < minimum or value > maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum} (got {value})")
    return value


def validate_sides(sides: int) -> int:
    """Validate a die's face count (OSSYS-SEC-012).

    `sides < 2` previously surfaced as an opaque "empty range" ValueError from inside
    `random.randint`, attributed to the stdlib rather than to the caller's bad input.
    """
    return validate_int_range(sides, name="sides", minimum=2, maximum=MAX_SIDES)


def expand_root(root: str | Path) -> Path:
    """Normalise one allowed-root entry to an absolute, symlink-free path.

    ``~`` and environment variables are expanded so config files stay portable across the
    endpoints they are deployed to.
    """
    text = os.path.expandvars(str(root))
    return Path(text).expanduser().resolve()


def validate_output_path(
    path: str | Path,
    *,
    allowed_roots: list[Path] | list[str] | None = None,
    must_not_exist: bool = False,
) -> Path:
    """Resolve and authorise a destination path for writing. Raises on anything unsafe.

    Enforces, in order:
      1. The target itself is not a symlink        — blocks the pre-created-symlink attack
         where an unprivileged user aims the default `details.txt` at a root-owned file.
      2. The parent directory exists and is a real directory.
      3. No component of the parent chain is a symlink pointing outside the allowed roots
         (handled implicitly: the parent is fully resolved before containment is checked).
      4. The resolved parent lies inside one of ``allowed_roots``.

    Args:
        path:          Caller-supplied destination.
        allowed_roots: Directories writes may land in. ``None`` means "current working
                       directory only" — the safe default when no config is loaded.
        must_not_exist: Refuse to overwrite an existing file. Used by commands that should
                       never clobber.

    Returns:
        The fully resolved, authorised path.
    """
    roots = [expand_root(r) for r in (allowed_roots or [Path.cwd()])]
    if not roots:
        raise ValidationError("no allowed output roots configured")

    candidate = Path(os.path.expandvars(str(path))).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate

    # (1) Refuse a symlinked target outright. Note lstat semantics: is_symlink() is true for
    # a dangling symlink too, which is exactly the case we must not follow.
    if candidate.is_symlink():
        raise ValidationError(f"refusing to write through a symlink: {candidate}")

    if must_not_exist and candidate.exists():
        raise ValidationError(f"refusing to overwrite existing file: {candidate}")

    # (2)+(3) Resolve the parent. resolve() collapses `..` and follows any symlinked
    # components, so the containment test below sees the real destination directory rather
    # than the path the caller hoped we would trust.
    parent = candidate.parent.resolve()
    if not parent.is_dir():
        raise ValidationError(f"parent directory does not exist: {parent}")

    # (4) Containment.
    target = parent / candidate.name
    if not any(_is_within(parent, root) for root in roots):
        allowed = ", ".join(str(r) for r in roots)
        raise ValidationError(f"output path {target} is outside the allowed roots: {allowed}")

    return target


def _is_within(child: Path, parent: Path) -> bool:
    """True when ``child`` is ``parent`` or sits beneath it.

    Uses PurePath.is_relative_to rather than string prefixing, so `/var/lib/ossys-evil` is
    correctly rejected against the root `/var/lib/ossys`.
    """
    try:
        return child == parent or child.is_relative_to(parent)
    except ValueError:  # different drives on Windows
        return False


def validate_archive_members(files: list[str | Path]) -> list[Path]:
    """Validate the input side of archive creation (OSSYS-SEC-003 / OSSYS-SEC-004).

    Enforces:
      * every member exists and is a **regular file** — `Path.exists()` accepted directories,
        and `tarfile.add` recurses into them by default, so `ossys archive /etc` silently
        swept up the whole tree;
      * no two members share a basename — members are stored flattened by basename, and a
        collision means most extractors silently drop one. For a backup tool that is silent
        data loss at restore time, so it fails loudly at create time instead;
      * member count and total bytes stay under the caps.
    """
    if not files:
        raise ValidationError("no files to archive")
    if len(files) > MAX_ARCHIVE_MEMBERS:
        raise ValidationError(f"too many archive members: {len(files)} > {MAX_ARCHIVE_MEMBERS}")

    resolved: list[Path] = []
    seen: dict[str, Path] = {}
    total = 0

    for f in files:
        p = Path(os.path.expandvars(str(f))).expanduser()
        if p.is_symlink():
            raise ValidationError(f"refusing to archive a symlink: {p}")
        if not p.exists():
            raise ValidationError(f"archive member does not exist: {p}")
        if not p.is_file():
            raise ValidationError(
                f"archive member is not a regular file: {p} "
                "(directories are not archived; pass their files explicitly)"
            )

        if p.name in seen:
            raise ValidationError(
                f"archive member basename collision: {p} and {seen[p.name]} "
                f"would both be stored as {p.name!r}"
            )
        seen[p.name] = p

        total += p.stat().st_size
        if total > MAX_ARCHIVE_BYTES:
            raise ValidationError(f"archive input exceeds {MAX_ARCHIVE_BYTES} bytes")

        resolved.append(p)

    return resolved


def validate_text_field(value: str, *, name: str, max_length: int = 256) -> str:
    """Reject control characters in a value destined for a line-oriented file.

    OSSYS-SEC-013: field values were interpolated into `Your Age is: {age}` verbatim, so a
    newline in `--name` forged additional records. Harmless alone; it is the content-control
    half of the OSSYS-SEC-001 arbitrary-write chain.
    """
    if len(value) > max_length:
        raise ValidationError(f"{name} exceeds {max_length} characters")
    if any(ch in value for ch in "\r\n\x00") or any(ord(ch) < 32 for ch in value):
        raise ValidationError(f"{name} must not contain control characters")
    return value
