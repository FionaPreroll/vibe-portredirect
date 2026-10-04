#!/usr/bin/env python3
"""Checks that each rendered diagram, docs/<name>.svg, shows what its source, docs/<name>.dot, says.

Renders each source with Graphviz and compares the texts in it, e.g. labels, with those in the
committed SVG. The texts don't depend on the version of Graphviz, unlike the layout, so this works
whichever version rendered the committed SVG.

Usage: utils/check-diagrams.py docs/*.dot
"""

import re
import subprocess
import sys
from pathlib import Path


def texts(svg: str) -> list[str]:
    """Returns the texts of an SVG, sorted."""
    return sorted(re.findall(r"<text[^>]*>(.*?)</text>", svg, re.DOTALL))


def main(sources: list[str]) -> int:
    stale = []
    for source in map(Path, sources):
        rendered = subprocess.run(
            ["dot", "-Tsvg", str(source)], capture_output=True, text=True, check=True
        ).stdout
        svg = source.with_suffix(".svg")
        if not svg.exists() or texts(svg.read_text()) != texts(rendered):
            stale.append(svg)
    for svg in stale:
        print(
            f"{svg} doesn't match its source, run make docs and commit it",
            file=sys.stderr,
        )
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
