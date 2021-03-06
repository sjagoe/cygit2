#!/bin/bash

# Warning: This is a dirty script to help subtree-merge a subtree
# (test/ directory) of the pygit2 repostory into cygit2

set -e
set -x

ROOT_TREE=$(git show --pretty=raw pygit2-branch | grep ^tree | cut -d' ' -f2)
TESTS_TREE=$(git ls-tree "$ROOT_TREE" | grep -P "\ttest$" | cut -d' ' -f3 | cut -d$'\t' -f1)
echo "$TESTS_TREE"
COMMIT=$(echo "commit for subtree-merge of pygit2 test/ directory ${TESTS_TREE}" | git commit-tree "${TESTS_TREE}")
git merge --squash -s subtree --no-commit "$COMMIT"
