#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
CONTENT_ROOTS = ("content", "reference")
CHECKED_TOP_LEVEL_FILES = (
    "README.md",
    "AGENTS.md",
    "russian-it-terminology.md",
)

LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
INTEGER_HEADING_RE = re.compile(r"^##\s+(\d+)\.\s+")
DECIMAL_HEADING_RE = re.compile(r"^##\s+\d+\.\d+\s+")
RU_DISCOURAGED_TERMS = re.compile(
    r"\b(credentials|evidence|controls|deployment|finding|findings|remediation|owner|approval"
    r"|require|starting|configured|behavior|results|summary|reviewer|changes)\b"
    r"|\breview decision\b|\bproduction baseline\b"
)
APOSTROPHE_DECLENSION_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_-]*'[а-яё]+\b", re.IGNORECASE)
RU_HYBRID_GRAMMAR_RE = re.compile(
    r"\b[A-Za-z][A-Za-z0-9_/-]*\s+(поведение|согласование|результаты|изменения|проверка)\b"
    r"|\b(отдельного|отдельный|явный)\s+согласование\b"
    r"|\bexизменения\b"
)
MIXED_SCRIPT_WORD_RE = re.compile(r"[A-Za-z][А-Яа-яЁё]|[А-Яа-яЁё][A-Za-z]")


def markdown_files() -> list[Path]:
    files: list[Path] = []
    for name in CHECKED_TOP_LEVEL_FILES:
        path = ROOT / name
        if path.exists():
            files.append(path)
    for root_name in CONTENT_ROOTS:
        root = ROOT / root_name
        if root.exists():
            files.extend(sorted(root.rglob("*.md")))
    return files


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def fail(errors: list[str], path: Path, line: int | None, message: str) -> None:
    location = rel(path)
    if line is not None:
        location = f"{location}:{line}"
    errors.append(f"{location}: {message}")


def check_language_pairs(errors: list[str]) -> None:
    for root_name in CONTENT_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.ru.md")):
            peer = path.with_name(path.name.replace(".ru.md", ".en.md"))
            if not peer.exists():
                fail(errors, path, None, f"missing English pair {rel(peer)}")
        for path in sorted(root.rglob("*.en.md")):
            peer = path.with_name(path.name.replace(".en.md", ".ru.md"))
            if not peer.exists():
                fail(errors, path, None, f"missing Russian pair {rel(peer)}")


def check_line_endings_and_spaces(errors: list[str], path: Path) -> None:
    data = path.read_bytes()
    if b"\r\n" in data:
        fail(errors, path, None, "contains CRLF line endings")

    for index, line in enumerate(data.splitlines(), 1):
        if line.endswith((b" ", b"\t")):
            fail(errors, path, index, "trailing whitespace")


def check_local_links(errors: list[str], path: Path, text: str) -> None:
    for line_no, line in enumerate(text.splitlines(), 1):
        for match in LINK_RE.finditer(line):
            target = match.group(1).strip()
            if not target or target.startswith("#"):
                continue
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):
                continue

            target_path = unquote(target.split("#", 1)[0])
            if not target_path:
                continue

            destination = (path.parent / target_path).resolve()
            try:
                destination.relative_to(ROOT)
            except ValueError:
                fail(errors, path, line_no, f"local link points outside repository: {target}")
                continue

            if not destination.exists():
                fail(errors, path, line_no, f"broken local link: {target}")


def check_top_level_heading_numbering(errors: list[str], path: Path, text: str) -> None:
    numbers: list[tuple[int, int]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if DECIMAL_HEADING_RE.match(line):
            continue
        match = INTEGER_HEADING_RE.match(line)
        if match:
            numbers.append((line_no, int(match.group(1))))

    for previous, current in zip(numbers, numbers[1:]):
        previous_line, previous_number = previous
        current_line, current_number = current
        if current_number != previous_number + 1:
            fail(
                errors,
                path,
                current_line,
                f"top-level heading numbering jumps from {previous_number} to {current_number} "
                f"(previous numbered heading at line {previous_line})",
            )


def check_code_fences(errors: list[str], path: Path, text: str) -> None:
    in_fence = False
    fence_line = 0

    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.startswith("```"):
            continue

        if not in_fence:
            language = line[3:].strip()
            if not language:
                fail(errors, path, line_no, "opening code fence has no language")
            in_fence = True
            fence_line = line_no
        else:
            in_fence = False

    if in_fence:
        fail(errors, path, fence_line, "code fence is not closed")


def check_document_type(errors: list[str], path: Path, text: str) -> None:
    if path.name.endswith(".ru.md"):
        expected = {
            "playbook.ru.md": "# Плейбук",
            "checklist.ru.md": "# Чеклист",
        }
    elif path.name.endswith(".en.md"):
        expected = {
            "playbook.en.md": "Playbook",
            "checklist.en.md": "Checklist",
        }
    else:
        return

    title = text.splitlines()[0] if text else ""
    required = expected.get(path.name)
    if not required:
        return
    if path.name.endswith(".ru.md") and not title.startswith(required):
        fail(errors, path, 1, f"playbook/checklist title must start with {required!r}")
    if path.name.endswith(".en.md") and required not in title:
        fail(errors, path, 1, f"playbook/checklist title must contain {required!r}")


def check_russian_terminology(errors: list[str], path: Path, text: str) -> None:
    if not path.name.endswith(".ru.md"):
        return

    in_fence = False
    for line_no, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue

        prose = re.sub(r"`[^`]*`", "", line)
        match = RU_DISCOURAGED_TERMS.search(prose)
        if match:
            fail(
                errors,
                path,
                line_no,
                f"discouraged untranslated term {match.group(0)!r}; use russian-it-terminology.md",
            )

        match = APOSTROPHE_DECLENSION_RE.search(prose)
        if match:
            fail(
                errors,
                path,
                line_no,
                f"apostrophe declension {match.group(0)!r} is not allowed; use a Russian term or an indeclinable technical name",
            )

        match = RU_HYBRID_GRAMMAR_RE.search(prose)
        if match:
            fail(
                errors,
                path,
                line_no,
                f"mixed-language grammatical construction {match.group(0)!r}; rewrite the phrase in natural Russian",
            )

        match = MIXED_SCRIPT_WORD_RE.search(prose)
        if match:
            fail(
                errors,
                path,
                line_no,
                "word contains adjacent Latin and Cyrillic letters; check for a mechanical replacement artifact",
            )


def check_readme_coverage(errors: list[str]) -> None:
    readme = ROOT / "README.md"
    if not readme.exists():
        fail(errors, readme, None, "README.md is missing")
        return

    text = readme.read_text(encoding="utf-8")
    linked_dirs = set()
    for match in LINK_RE.finditer(text):
        target = match.group(1).split("#", 1)[0]
        if target.startswith(("content/", "reference/")) and target.endswith("/"):
            linked_dirs.add(target)

    actual_dirs = set()
    for root_name in CONTENT_ROOTS:
        root = ROOT / root_name
        if root.exists():
            actual_dirs.update(f"{rel(path.parent)}/" for path in root.rglob("*.md"))

    for directory in sorted(actual_dirs - linked_dirs):
        fail(errors, readme, None, f"missing README entry for {directory}")

    for directory in sorted(linked_dirs - actual_dirs):
        fail(errors, readme, None, f"README links to directory without markdown files: {directory}")


def main() -> int:
    errors: list[str] = []
    files = markdown_files()

    check_language_pairs(errors)
    check_readme_coverage(errors)

    for path in files:
        check_line_endings_and_spaces(errors, path)
        text = path.read_text(encoding="utf-8")
        check_local_links(errors, path, text)
        check_top_level_heading_numbering(errors, path, text)
        check_code_fences(errors, path, text)
        check_document_type(errors, path, text)
        check_russian_terminology(errors, path, text)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"\nValidation failed: {len(errors)} issue(s).", file=sys.stderr)
        return 1

    print("Validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
