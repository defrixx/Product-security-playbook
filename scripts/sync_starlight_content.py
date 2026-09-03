#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (ROOT / "content", ROOT / "reference")
DOCS_ROOT = ROOT / "site" / "src" / "content" / "docs"
def configured_site_base() -> str:
    explicit = os.environ.get("PUBLIC_SITE_BASE")
    if explicit is not None:
        return explicit.rstrip("/")

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository.endswith("/defrixx.github.io"):
        return ""

    return "/Product-security-playbook"


SITE_BASE = configured_site_base()

LANG_RE = re.compile(r"^(?P<stem>.+)\.(?P<lang>ru|en)\.md$")
H1_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)")

TOP_LEVEL_ORDER = {
    "review": 10,
    "application-security": 20,
    "platform-security": 30,
    "supply-chain": 40,
    "ai-security": 50,
    "reference": 60,
}

PAGE_ORDER = {
    "review/architecture/checklist": 10,
    "review/threat-modeling/playbook": 20,
    "review/release-governance/playbook": 30,
    "review/vulnerability-management/playbook": 40,
    "application-security/web/owasp-top-10/playbook": 10,
    "application-security/web/browser-security/playbook": 20,
    "application-security/api/api-security-patterns/playbook": 30,
    "application-security/business-logic/business-logic-abuse/playbook": 40,
    "application-security/secure-coding/code-review/playbook": 50,
    "application-security/identity/oidc-oauth/playbook": 60,
    "platform-security/kubernetes/cluster-security-review/playbook": 10,
    "platform-security/kubernetes/adversarial-validation/playbook": 20,
    "platform-security/kubernetes/pod-security/playbook": 30,
    "platform-security/kubernetes/secrets/playbook": 40,
    "platform-security/kubernetes/seccomp/checklist": 50,
    "platform-security/kubernetes/container-escape-capability-abuse/overview": 60,
    "platform-security/secrets/vault/playbook": 70,
    "supply-chain/slsa-provenance/overview": 10,
    "supply-chain/container-image-security/playbook": 20,
    "ai-security/securing-ai/overview": 10,
    "ai-security/owasp-llm-top-10/overview": 20,
    "ai-security/agentic-ai/playbook": 30,
    "ai-security/mcp-security/playbook": 40,
    "reference/infrastructure-technologies/infrastructure-technologies": 10,
}


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def source_files() -> list[Path]:
    files: list[Path] = []
    for source_root in SOURCE_ROOTS:
        if source_root.exists():
            files.extend(sorted(source_root.rglob("*.md")))
    return files


def source_info(path: Path) -> tuple[str, str, Path]:
    match = LANG_RE.match(path.name)
    if not match:
        raise ValueError(f"{rel(path)} does not use .ru.md or .en.md suffix")

    lang = match.group("lang")
    stem = match.group("stem")

    if path.is_relative_to(ROOT / "content"):
        relative = path.relative_to(ROOT / "content")
        logical = relative.with_name(stem)
    elif path.is_relative_to(ROOT / "reference"):
        relative = path.relative_to(ROOT / "reference")
        logical = Path("reference") / relative.with_name(stem)
    else:
        raise ValueError(f"{rel(path)} is outside supported source roots")

    logical_no_suffix = logical.with_suffix("")
    return lang, logical_no_suffix.as_posix(), logical


def source_route(path: Path, anchor: str = "") -> str:
    lang, logical_key, _ = source_info(path)
    route = f"{SITE_BASE}/{lang}/{logical_key}/" if SITE_BASE else f"/{lang}/{logical_key}/"
    if anchor:
        route += f"#{anchor}"
    return route


def target_path(path: Path) -> Path:
    lang, logical_key, _ = source_info(path)
    return DOCS_ROOT / lang / f"{logical_key}.md"


def peer_path(path: Path) -> Path:
    if path.name.endswith(".ru.md"):
        return path.with_name(path.name.replace(".ru.md", ".en.md"))
    if path.name.endswith(".en.md"):
        return path.with_name(path.name.replace(".en.md", ".ru.md"))
    raise ValueError(f"{rel(path)} does not use a supported language suffix")


def yaml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def extract_title_and_body(path: Path, text: str) -> tuple[str, str]:
    match = H1_RE.search(text)
    if not match:
        raise ValueError(f"{rel(path)} has no H1 title")

    title = match.group(1).strip()
    body = text[: match.start()] + text[match.end() :]
    body = body.lstrip("\n")
    return title, body


def description_from(body: str) -> str:
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-", "|", "```", "---")):
            continue
        if len(line) > 180:
            return line[:177].rstrip() + "..."
        return line
    return "Product security playbook."


def rewrite_markdown_links(source: Path, body: str) -> str:
    def replace(match: re.Match[str]) -> str:
        label = match.group(1)
        raw_target = match.group(2).strip()

        if not raw_target or raw_target.startswith("#"):
            return match.group(0)
        if re.match(r"^[a-z][a-z0-9+.-]*:", raw_target):
            return match.group(0)

        path_part, separator, anchor = raw_target.partition("#")
        if not path_part.endswith((".ru.md", ".en.md")):
            return match.group(0)

        target = (source.parent / unquote(path_part)).resolve()
        try:
            target.relative_to(ROOT)
        except ValueError:
            return match.group(0)

        if not target.exists() or not LANG_RE.match(target.name):
            return match.group(0)

        route = source_route(target, anchor if separator else "")
        return f"[{label}]({route})"

    return MARKDOWN_LINK_RE.sub(replace, body)


def generated_content(source: Path) -> str:
    text = source.read_text(encoding="utf-8")
    title, body = extract_title_and_body(source, text)
    body = rewrite_markdown_links(source, body)
    lang, logical_key, _ = source_info(source)
    order = PAGE_ORDER.get(logical_key, TOP_LEVEL_ORDER.get(logical_key.split("/", 1)[0], 100))
    description = description_from(body)

    frontmatter = [
        "---",
        f"title: {yaml_quote(title)}",
        f"description: {yaml_quote(description)}",
        "sidebar:",
        f"  order: {order}",
        "---",
        "",
    ]
    return "\n".join(frontmatter) + body.rstrip() + "\n"


def index_content(lang: str) -> str:
    base = SITE_BASE
    if lang == "ru":
        return """---
title: "Product Security Playbook"
description: "Практическая база знаний по AppSec, Platform Security, Supply Chain и AI Security."
sidebar:
  order: 0
---

Практическая база знаний по архитектурному ревью, безопасной разработке, Kubernetes, безопасности цепочки поставки ПО, AI Security и управлению контролями релиза.

## Основные разделы

- [Ревью и управление]({base}/ru/review/architecture/checklist/)
- [Application Security]({base}/ru/application-security/web/owasp-top-10/playbook/)
- [Platform Security]({base}/ru/platform-security/kubernetes/cluster-security-review/playbook/)
- [Supply Chain]({base}/ru/supply-chain/slsa-provenance/overview/)
- [AI Security]({base}/ru/ai-security/securing-ai/overview/)
- [Справочник]({base}/ru/reference/infrastructure-technologies/infrastructure-technologies/)

## Об авторе

Меня зовут Олег. Я веду эту базу как рабочую коллекцию материалов по безопасности продуктов.
Сначала готовились английские версии документов, а русские создавались с помощью машинного перевода и затем редактировались вручную.

Не каждый документ здесь написан полностью с нуля одним человеком. Часть материалов объединяет и адаптирует существующие практики, общедоступные знания и рабочие подходы, дополняя их анализом, редактурой и контекстом эксплуатации. Относитесь к репозиторию как к курируемой рабочей базе знаний, а не как к полностью оригинальному самостоятельному тексту.
""".format(base=base)

    return """---
title: "Product Security Playbook"
description: "A practical knowledge base for AppSec, platform security, supply chain, and AI security."
sidebar:
  order: 0
---

A practical knowledge base for architecture review, secure development, Kubernetes, supply chain, AI security, and security quality gates.

## Main Sections

- [Review and Governance]({base}/en/review/architecture/checklist/)
- [Application Security]({base}/en/application-security/web/owasp-top-10/playbook/)
- [Platform Security]({base}/en/platform-security/kubernetes/cluster-security-review/playbook/)
- [Supply Chain]({base}/en/supply-chain/slsa-provenance/overview/)
- [AI Security]({base}/en/ai-security/securing-ai/overview/)
- [Reference]({base}/en/reference/infrastructure-technologies/infrastructure-technologies/)

## About

My name is Oleg. I maintain this knowledge base as a working collection of Product Security materials.

Not every document here was written entirely from scratch by one person. Some sections compile and adapt existing practices, public knowledge, and practical review patterns, with additional analysis, editing, and production context. Treat this repository as curated working material rather than purely original standalone writing.
""".format(base=base)


def validate_pairs(files: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in files:
        if not LANG_RE.match(path.name):
            errors.append(f"{rel(path)} does not use .ru.md or .en.md suffix")
            continue
        peer = peer_path(path)
        if not peer.exists():
            errors.append(f"{rel(path)} is missing language pair {rel(peer)}")
    return errors


def render_all() -> dict[Path, str]:
    files = source_files()
    errors = validate_pairs(files)
    if errors:
        raise ValueError("\n".join(errors))

    rendered: dict[Path, str] = {}
    for source in files:
        rendered[target_path(source)] = generated_content(source)

    rendered[DOCS_ROOT / "ru" / "index.md"] = index_content("ru")
    rendered[DOCS_ROOT / "en" / "index.md"] = index_content("en")
    return rendered


def write_all(rendered: dict[Path, str], check: bool) -> int:
    if check:
        errors: list[str] = []
        for path, expected in sorted(rendered.items()):
            if not path.exists():
                errors.append(f"{rel(path)} is missing")
                continue
            actual = path.read_text(encoding="utf-8")
            if actual != expected:
                errors.append(f"{rel(path)} is not up to date")
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print("Starlight generated content is up to date.")
        return 0

    if DOCS_ROOT.exists():
        shutil.rmtree(DOCS_ROOT)
    DOCS_ROOT.mkdir(parents=True, exist_ok=True)

    for path, content in sorted(rendered.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    print(f"Generated {len(rendered)} Starlight document(s).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="check generated content without writing")
    args = parser.parse_args()

    try:
        rendered = render_all()
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1

    return write_all(rendered, args.check)


if __name__ == "__main__":
    raise SystemExit(main())
