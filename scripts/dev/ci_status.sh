#!/bin/sh
# ci_status.sh - after a push, wait for the Tests workflow of HEAD and print its verdict.
# Why: 2026-09-18, five releases (v0.6.52-56) went out with CI red. The local suite
# passed because the developer machine had a PSIRT cache the runner did not; nobody
# looked at Actions. "Pushed" is not "green": run this after every push.
#   sh scripts/dev/ci_status.sh        exit 0 = green, 1 = red (failing lines printed)
sha=$(git rev-parse HEAD)
for i in 1 2 3 4 5 6; do
  id=$(GITHUB_TOKEN= gh run list --workflow tests.yml --commit "$sha" --limit 1 --json databaseId -q '.[0].databaseId')
  [ -n "$id" ] && break
  sleep 5
done
[ -z "$id" ] && { echo "no Tests run found for $sha"; exit 1; }
if GITHUB_TOKEN= gh run watch "$id" --exit-status >/dev/null 2>&1; then
  echo "CI green: $sha"
else
  echo "CI RED: $sha"
  GITHUB_TOKEN= gh run view "$id" --log-failed 2>/dev/null | grep -E "FAILED|^E  |passed|failed" | tail -12
  exit 1
fi
