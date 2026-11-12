#!/usr/bin/env bash
# Reveal one challenge answer from answers/answers.b64.
#   ./scripts/answer.sh N3     show the answer to N3
#   ./scripts/answer.sh        list challenge IDs
set -euo pipefail
file="$(cd "$(dirname "$0")/.." && pwd)/answers/answers.b64"

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <challenge-id>"
  echo "IDs: $(awk '{printf "%s ", $1}' "$file")"
  exit 0
fi

id=$(echo "$1" | tr '[:lower:]' '[:upper:]')
line=$(awk -v id="$id" '$1 == id {print $2}' "$file")
if [[ -z "$line" ]]; then
  echo "No challenge called $id. Run $0 with no arguments to list them." >&2
  exit 1
fi

read -r -p "Reveal the answer to $id? [y/N] " ok
[[ "$ok" =~ ^[Yy] ]] || exit 0
echo
echo "$line" | base64 --decode
