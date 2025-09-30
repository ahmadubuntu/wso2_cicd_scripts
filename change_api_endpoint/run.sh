#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found"
  exit 1
fi

if ! python3 -c "import requests" 2>/dev/null; then
  echo "Python 'requests' library not installed. Install with: pip install requests"
  exit 1
fi

python3 update_endpoint.py
