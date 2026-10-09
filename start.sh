#!/usr/bin/env bash
set -e

echo "Inventory Manager"
echo "================="

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.10+ and try again."
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "Setting up virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

echo "Starting server..."
echo "Open http://localhost:8080 in your browser (or share your IP with LAN users)"
echo "Press Ctrl+C to stop."
echo ""

python server.py
