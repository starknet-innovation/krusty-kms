#!/usr/bin/env bash
# Require content-addressed actions in workflows that can publish packages.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
exec ruby "$repo_root/.github/scripts/check-publish-actions-pinned.rb" "$@"
