#!/usr/bin/env bash

# We've disabled Github's merge button because it doesn't fast-forward properly.
# Instead, we can use this script to merge an approved PR.
#
# Requires: `git`, `gh`, 'jq'
#
# Usage: $0 [branch-or-pr-number]
#
# If the current branch is `main` then `branch-or-pr-number` is required.

set -e -o pipefail

function bail() {
    msg="$1"
    if [ -n "$msg" ]; then
        # we do want to emit to stderr here
        #shellcheck disable=SC2210
        echo >2 "$msg"
    fi
    exit 1
}

current_branch="$(git branch --show-current)"
if [ -z "$1" ]; then
    if [ "$current_branch" == "main" ]; then
        bail "on main; must specify the PR number or branch name to merge"
    else
        branch="$current_branch"
    fi
else
    # if it's a number, assume it's a PR number and get the branch name. otherwise just a branch.
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        branch="$(gh pr view "$1" --json headRefName | jq -r ".headRefName")"
    else
        branch="$1"
    fi
fi

# ensure the branch is approved
status_json="$(gh pr view "$branch" --json reviewDecision,statusCheckRollup)"
review_decision="$(jq -r .reviewDecision <<< "$status_json")"
if [ "$review_decision" != "APPROVED" ]; then
    bail "$branch has not yet been approved"
fi

# ensure all checks have completed successfully
non_success="$(jq -r '.statusCheckRollup[] | select(.__typename == "CheckRun" and ((.status == "COMPLETED" and (.conclusion == "SUCCESS" or .conclusion == "SKIPPED")) | not)) | .name' <<< "$status_json")"
if [ -n "$non_success" ]; then
    bail "some CI checks are incomplete or unsuccessful:\n$non_success"
fi

# ensure that the branch is at the tip of `origin/main` for a linear history
git fetch
git checkout "$branch"
if ! git rebase origin/main; then
    git rebase --abort
    bail "$branch did not cleanly rebase onto origin/main; do so manually and try again"
fi

# if rebase moved the tip then force-push to ensure github is tracking the new history
# this resets CI, but doesn't mess with the approvals. We can assume CI is OK, at this point.
if [ "$(git rev-parse "$branch")" != "$(git rev-parse "origin/$branch")" ]; then
    git push -f
fi

# we can now actually merge this to main without breaking anything
git checkout main
git merge "$branch" --ff-only
git push
