"""
Generate MkDocs reference pages from leanSpec Python specification docstrings.

The generator walks the ``lean_spec.spec`` package, emits one MkDocs page per
module using the ``mkdocstrings`` ``:::`` directive, and rewrites the ``nav``
section of ``mkdocs.yml`` so the reference documentation stays in sync with the
Python source and no manual markdown duplication is required.

Usage::

    uv run python tools/generate_docs.py
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
SPEC_PACKAGE = "lean_spec.spec"
SPEC_PACKAGE_DIRECTORY = SOURCE_ROOT / SPEC_PACKAGE.replace(".", "/")
REFERENCE_DIRECTORY = REPOSITORY_ROOT / "docs" / "reference"
DOCS_DIRECTORY = REPOSITORY_ROOT / "docs"
MKDOCS_CONFIGURATION = REPOSITORY_ROOT / "mkdocs.yml"

MODULE_DOCSTRING_PATTERN = re.compile(
    r'^\s*(?:r|u|f|rf|fr)?"""(.*?)"""',
    re.DOTALL,
)


def discover_source_files() -> list[Path]:
    """
    Return the spec package source files in deterministic order.

    Package ``__init__`` files are kept as section pages. Private modules whose
    names start with an underscore are omitted from the reference.
    """
    return [
        source_file
        for source_file in sorted(SPEC_PACKAGE_DIRECTORY.rglob("*.py"))
        if source_file.name == "__init__.py" or not source_file.stem.startswith("_")
    ]


def import_path(source_file: Path) -> str:
    """Compute the dotted Python import path for a source file."""
    path_parts = list(source_file.relative_to(SPEC_PACKAGE_DIRECTORY).with_suffix("").parts)
    if path_parts and path_parts[-1] == "__init__":
        path_parts = path_parts[:-1]
    if not path_parts:
        return SPEC_PACKAGE
    return f"{SPEC_PACKAGE}.{'.'.join(path_parts)}"


def reference_page_path(source_file: Path) -> Path:
    """Compute the generated Markdown page path for a source file."""
    path_parts = list(source_file.relative_to(SPEC_PACKAGE_DIRECTORY).with_suffix("").parts)
    if source_file.name == "__init__.py":
        path_parts = path_parts[:-1] + ["index"]
    return REFERENCE_DIRECTORY.joinpath(*path_parts).with_suffix(".md")


def module_title(source_file: Path) -> str:
    """Extract a display title from the module docstring first line."""
    docstring_match = MODULE_DOCSTRING_PATTERN.search(source_file.read_text(encoding="utf-8"))
    if docstring_match:
        for line in docstring_match.group(1).splitlines():
            stripped_line = line.strip()
            if stripped_line:
                return stripped_line
    return import_path(source_file).rsplit(".", 1)[-1]


def page_reference(reference_page: Path) -> str:
    """Compute the MkDocs page reference relative to the docs directory."""
    return reference_page.relative_to(DOCS_DIRECTORY).as_posix()


def render_page(title: str, module: str) -> str:
    """Render a single reference page."""
    return f"# {title}\n\n::: {module}\n"


def build_navigation_tree(page_entries: list[tuple[list[str], str]]) -> dict:
    """Build a nested tree from flat page entries."""
    navigation_tree: dict = {}
    for path_parts, reference in page_entries:
        navigation_node = navigation_tree
        for path_part in path_parts:
            navigation_node = navigation_node.setdefault(path_part, {})
        navigation_node["__page__"] = reference
    return navigation_tree


def serialize_navigation_node(navigation_node: dict, node_name: str) -> dict:
    """
    Serialize a navigation node into a single MkDocs nav entry.

    A node with no children is a leaf page. A node with children becomes a
    section whose own page is exposed as an ``Overview`` child.
    """
    child_nodes = {name: value for name, value in navigation_node.items() if name != "__page__"}
    node_page = navigation_node.get("__page__")

    if not child_nodes:
        return {node_name: node_page} if node_page is not None else {node_name: []}

    section_children: list = []
    if node_page is not None:
        section_children.append({"Overview": node_page})
    for child_name in sorted(child_nodes):
        section_children.append(serialize_navigation_node(child_nodes[child_name], child_name))

    return {node_name: section_children}


def format_navigation_entries(entries: list, indent: int = 0) -> list[str]:
    """Format nested nav entries as indented YAML lines."""
    lines: list[str] = []
    indentation = " " * indent
    for entry in entries:
        for name, value in entry.items():
            if isinstance(value, str):
                lines.append(f"{indentation}- {name}: {value}")
            else:
                lines.append(f"{indentation}- {name}:")
                lines.extend(format_navigation_entries(value, indent + 4))
    return lines


def rewrite_navigation(navigation_lines: list[str]) -> None:
    """Replace the ``nav`` block of ``mkdocs.yml`` with generated entries."""
    configuration_text = MKDOCS_CONFIGURATION.read_text(encoding="utf-8")
    navigation_block = "\n".join(navigation_lines)
    new_navigation = f"nav:\n{navigation_block}\n"
    navigation_pattern = re.compile(r"(?m)^nav:.*?(?=^[a-zA-Z_][a-zA-Z0-9_]*:\s)", re.DOTALL)
    updated_configuration = navigation_pattern.sub(
        lambda _: new_navigation, configuration_text, count=1
    )
    MKDOCS_CONFIGURATION.write_text(updated_configuration, encoding="utf-8")


def main() -> None:
    """Generate reference pages and update the MkDocs navigation."""
    if REFERENCE_DIRECTORY.exists():
        shutil.rmtree(REFERENCE_DIRECTORY)
    REFERENCE_DIRECTORY.mkdir(parents=True)

    page_entries: list[tuple[list[str], str]] = []

    for source_file in discover_source_files():
        module = import_path(source_file)
        title = module_title(source_file)
        reference_page = reference_page_path(source_file)

        reference_page.parent.mkdir(parents=True, exist_ok=True)
        reference_page.write_text(render_page(title, module), encoding="utf-8")

        path_parts = list(source_file.relative_to(SPEC_PACKAGE_DIRECTORY).with_suffix("").parts)
        if source_file.name == "__init__.py":
            path_parts = path_parts[:-1]
        page_entries.append((path_parts, page_reference(reference_page)))

    navigation_tree = build_navigation_tree(page_entries)

    reference_entries: list = []
    root_page = navigation_tree.get("__page__")
    root_children = {name: value for name, value in navigation_tree.items() if name != "__page__"}
    if root_page is not None:
        reference_entries.append({"Overview": root_page})
    for child_name in sorted(root_children):
        reference_entries.append(serialize_navigation_node(root_children[child_name], child_name))

    navigation_lines = ["  - Home: index.md", "  - Reference:"]
    navigation_lines.extend(format_navigation_entries(reference_entries, indent=4))
    rewrite_navigation(navigation_lines)

    print(f"Generated {len(page_entries)} reference pages under docs/reference/")
    print(f"Updated navigation in {MKDOCS_CONFIGURATION}")


if __name__ == "__main__":
    main()
