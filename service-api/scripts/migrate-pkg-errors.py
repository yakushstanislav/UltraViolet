#!/usr/bin/env python3
"""Migrate github.com/pkg/errors to stdlib errors + fmt."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

IMPORT_LINE = re.compile(r'\t"github.com/pkg/errors"\n')

WRAP_RE = re.compile(
    r'errors\.Wrap\(\s*([^,]+?)\s*,\s*((?:`[^`]*`|"(?:[^"\\]|\\.)*"))\s*\)',
)
WRAPF_RE = re.compile(
    r'errors\.Wrapf\(\s*([^,]+?)\s*,\s*((?:`[^`]*`|"(?:[^"\\]|\\.)*"))\s*,\s*([^)]+)\)',
)
ERRORF_RE = re.compile(
    r'errors\.Errorf\(\s*((?:`[^`]*`|"(?:[^"\\]|\\.)*"))\s*,\s*([^)]+)\)',
)


def _append_w(msg: str) -> str:
    if msg.startswith('"') and msg.endswith('"'):
        return f'"{msg[1:-1]}: %w"'

    if msg.startswith("`") and msg.endswith("`"):
        return f"`{msg[1:-1]}: %w`"

    return msg


def migrate_content(content: str) -> str:
    if "github.com/pkg/errors" not in content:
        return content

    content = WRAP_RE.sub(lambda m: f"fmt.Errorf({_append_w(m.group(2))}, {m.group(1)})", content)
    content = WRAPF_RE.sub(
        lambda m: f"fmt.Errorf({_append_w(m.group(2))}, {m.group(3)}, {m.group(1)})",
        content,
    )
    content = ERRORF_RE.sub(r"fmt.Errorf(\1, \2)", content)
    content = IMPORT_LINE.sub("", content)

    needs_errors = bool(re.search(r"\berrors\.(New|Is|As|Unwrap)\(", content))
    needs_fmt = "fmt." in content

    if not needs_errors and not needs_fmt:
        return content

    lines = content.splitlines(keepends=True)
    import_idx = None

    for i, line in enumerate(lines):
        if line == "import (\n":
            import_idx = i
            break

    if import_idx is None:
        return content

    block_end = import_idx + 1
    while block_end < len(lines) and lines[block_end].strip() != ")":
        block_end += 1

    block = "".join(lines[import_idx : block_end + 1])
    if needs_errors and '"errors"' not in block:
        insert_at = import_idx + 1
        lines.insert(insert_at, '\t"errors"\n')
        block_end += 1

    block = "".join(lines[import_idx : block_end + 1])
    if needs_fmt and '"fmt"' not in block:
        insert_at = import_idx + 1
        lines.insert(insert_at, '\t"fmt"\n')

    return "".join(lines)


def main() -> int:
    changed = 0

    for path in sorted(ROOT.rglob("*.go")):
        if "/vendor/" in str(path):
            continue

        original = path.read_text()
        updated = migrate_content(original)

        if updated != original:
            path.write_text(updated)
            changed += 1
            print(path.relative_to(ROOT))

    print(f"migrated {changed} files", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
