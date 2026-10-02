#!/usr/bin/env bash
# render-diagrams.sh: Render DOT files to SVG images, saved to ./docs directory.
#
# Usage: Run this script from the repository's main directory.
#        Resulting SVG files will be saved under the same file name (but svg suffix) to the ./docs directory.
#
# Example: ./utils/render-diagrams.sh docs/*.dot

set -euo pipefail

# Ensure docs directory exists
DOCS_DIR="docs"
if [ ! -d "$DOCS_DIR" ]; then
    echo "Make sure to run this script in the repository's main directory, where ${DOCS_DIR} is located."
    exit 1
fi

echo "Rendering DOT files..."

ERROR=0
for dotfile in $@; do
    if [ ! -f "${dotfile}" ]; then
        echo "File not found: ${dotfile}"
        ERROR=1
        continue
    fi

    filename=$(basename "${dotfile}" .dot)
    output="${DOCS_DIR}/${filename}.svg"
    echo "Rendering ${dotfile} to ${output}"
    dot -Tsvg "${dotfile}" -o "${output}" || ERROR=1
done

echo "Rendering complete."
exit $ERROR
