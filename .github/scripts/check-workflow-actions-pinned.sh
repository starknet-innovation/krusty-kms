#!/usr/bin/env bash
# Require content-addressed actions and images in every GitHub workflow.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
exec ruby "$repo_root/.github/scripts/check-workflow-actions-pinned.rb" "$@"
