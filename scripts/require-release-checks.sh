#!/usr/bin/env bash
# Release checks run via workflow_dispatch on the exact tree, outside a synthetic PR merge.
set -euo pipefail
revision=$(git rev-parse --verify 'HEAD^{commit}')
for workflow in ci.yml nightly-live.yml mutation.yml; do
    passed=$(gh run list --repo "$GITHUB_REPOSITORY" --workflow "$workflow" --event workflow_dispatch \
        --commit "$revision" --status success --limit 1 --json headSha --jq '.[0].headSha // ""')
    if [ "$passed" != "$revision" ]; then
        echo "::error::$workflow needs a successful dispatch on $revision before release"
        exit 1
    fi
done
