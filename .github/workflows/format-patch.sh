#!/bin/bash

if [[ $(jq --version 1>/dev/null 2>&1 && echo yes) != "yes" ]]; then
  echo "Tool jq is not installed. Please install it to parse JSON data. For example:"
  echo "   apt install jq"
  echo "   brew install jq"
  echo "   yum install jq"
  echo "See https://github.com/jqlang/jq"
  exit 1
fi

if [ -z "$1" ]; then
  echo "Please provide a PR link or number. For example: https://github.com/ossrs/ffmpeg-webrtc/pull/20"
  exit 1
fi

if [[ "$1" =~ ^https://github.com/ossrs/ffmpeg-webrtc/pull/([0-9]+)$ ]]; then
  PR_NUMBER="${BASH_REMATCH[1]}"
elif [[ "$1" =~ ^[0-9]+$ ]]; then
  PR_NUMBER="$1"
else
  echo "Invalid input format. Please provide a PR link or number. For example: https://github.com/ossrs/ffmpeg-webrtc/pull/20"
  exit 1
fi

PR_URL="https://github.com/ossrs/ffmpeg-webrtc/pull/$PR_NUMBER"
echo "Fetching PR #$PR_NUMBER from $PR_URL"

PR_DATA=$(curl -s "https://api.github.com/repos/ossrs/ffmpeg-webrtc/pulls/$PR_NUMBER")
REPO_NAME=$(echo "$PR_DATA" | jq -r '.head.repo.full_name')
BRANCH_NAME=$(echo "$PR_DATA" | jq -r '.head.ref')
if [[ -z "$REPO_NAME" || -z "$BRANCH_NAME" ]]; then 
  echo "Error: REPO_NAME or BRANCH_NAME is empty!"
  exit 1
fi
echo "Repository: $REPO_NAME, Branch: $BRANCH_NAME"

PR_TITLE=$(echo "$PR_DATA" | jq -r '.title')
PR_DESCRIPTION=$(echo "$PR_DATA" | jq -r '.body // ""')
if [[ -z "$PR_TITLE" ]]; then
  echo "Error: PR title is empty!"
  exit 1
fi

echo "PR information:"
echo "==================================================================="
echo "$PR_TITLE"
echo "$PR_DESCRIPTION"
echo "==================================================================="
echo ""

set -euxo pipefail

git checkout workflows
echo "Switched to workflows branch."

git pull
echo "Pulled latest changes from workflows branch."

REMOTE_NAME=patch-tmp
if git remote | grep -q "^$REMOTE_NAME$"; then
    git remote rm "$REMOTE_NAME"
fi
git remote add $REMOTE_NAME https://github.com/${REPO_NAME}.git
git fetch $REMOTE_NAME $BRANCH_NAME
echo "Fetch remote $REMOTE_NAME at $(git remote get-url $REMOTE_NAME)"

TMP_BRANCH=tmp-branch-for-patch-$PR_NUMBER
if git branch --list "$TMP_BRANCH" | grep -q "^..$TMP_BRANCH$"; then
    git branch -D "$TMP_BRANCH"
fi
git checkout -b $TMP_BRANCH $REMOTE_NAME/$BRANCH_NAME
echo "Checkout branch $TMP_BRANCH from $REMOTE_NAME/$BRANCH_NAME"

FIRST_AUTHOR_NAME=$(git log workflows..HEAD --reverse --format='%an' | head -n1)
FIRST_AUTHOR_EMAIL=$(git log workflows..HEAD --reverse --format='%ae' | head -n1)
echo "Author: $FIRST_AUTHOR_NAME <$FIRST_AUTHOR_EMAIL>"

COAUTHORS=$(git log workflows..HEAD --format='Co-authored-by: %an <%ae>' |grep -v "$FIRST_AUTHOR_NAME" | sort -u)
COAUTHOR_COUNT=$(echo "$COAUTHORS" | wc -l)
if [ "$COAUTHOR_COUNT" -gt 0 ]; then
    echo "$COAUTHORS"
fi

COMMIT_MSG="$PR_TITLE"
if [ -n "$PR_DESCRIPTION" ]; then
  COMMIT_MSG="$COMMIT_MSG\n\n$PR_DESCRIPTION"
fi

if [ "$COAUTHOR_COUNT" -gt 0 ]; then
  COMMIT_MSG="$COMMIT_MSG\n"
  COMMIT_MSG="$COMMIT_MSG\n$COAUTHORS"
fi

echo "Commit information:"
echo "Author: $FIRST_AUTHOR_NAME <$FIRST_AUTHOR_EMAIL>"
echo "==================================================================="
echo -e "$COMMIT_MSG"
echo "==================================================================="
echo ""

git rebase workflows
git reset --soft workflows
git commit --author "$FIRST_AUTHOR_NAME <$FIRST_AUTHOR_EMAIL>" -m "$(echo -e "$COMMIT_MSG")"
echo "Squashed commits into a single commit."
git log -1 --pretty=format:"%an <%ae> %h %s"

PATCH_FILE="patch-$PR_NUMBER-$(date +%s).patch"
rm -f $PATCH_FILE
git format-patch -1 --stdout > $PATCH_FILE

git checkout workflows
#git br -D $TMP_BRANCH
#echo "Removed temporary branch $TMP_BRANCH."

set +e +u +x +o pipefail

echo ""
echo "Patch file created: $PATCH_FILE"
echo ""
