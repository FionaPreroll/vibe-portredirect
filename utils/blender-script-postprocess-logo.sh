#!/bin/bash
# blender-script-postprocess-logo.sh: Run postprocessing on the logo image rendered by Blender.
#
# Dependencies: imagemagick
#
# Usage: ./blender-script-postprocess-logo.sh

set -e # Exit on any error

# Ensure docs directory exists
DOCS_DIR="docs"
if [ ! -d "$DOCS_DIR" ]; then
    echo "Make sure to run this script in the repository's main directory, where ${DOCS_DIR} is located."
    exit 1
fi

magick docs/portredirect_logo.png -auto-level docs/portredirect_logo.png
