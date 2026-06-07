#!/bin/bash
# Usage:
#   ./scripts/rebuild_brain.sh            — incremental (only new/changed content)
#   ./scripts/rebuild_brain.sh --rebuild  — full drop and rebuild from scratch

python generate_nodes.py
python generate_edges.py
python ingest_hacktricks.py "$@"
