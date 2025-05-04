#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

rm -rf python layer.zip
pip install --no-compile -r requirements.txt -t python/
find python -exec touch -t 198001010000 {} +
find python -type f | LC_ALL=C sort | zip -q -X -@ layer.zip
