#!/usr/bin/env bash
# Scan for secrets with gitleaks (runs in Docker, nothing to install).
# In a git repo it scans all history plus staged changes; otherwise the whole folder.
#   ./scripts/check-secrets.sh
# To run it before every commit:  ln -s ../../scripts/check-secrets.sh .git/hooks/pre-commit
set -euo pipefail
cd "$(dirname "$0")/.."
GL=(docker run --rm -v "$PWD:/repo" -w /repo ghcr.io/gitleaks/gitleaks:v8.28.0)
if [ -d .git ]; then
  "${GL[@]}" git /repo --redact --no-banner "$@"
  "${GL[@]}" git /repo --pre-commit --staged --redact --no-banner "$@"
else
  "${GL[@]}" dir /repo --redact --no-banner "$@"
fi
