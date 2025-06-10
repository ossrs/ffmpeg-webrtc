#!/bin/bash

LOGPREFIX=">>"

if [[ $(jq --version 1>/dev/null 2>&1 && echo yes) != "yes" ]]; then
  echo "${LOGPREFIX} Tool jq is not installed. Please install it to parse JSON data. For example:"
  echo "${LOGPREFIX}    apt install jq"
  echo "${LOGPREFIX}    brew install jq"
  echo "${LOGPREFIX}    yum install jq"
  echo "${LOGPREFIX} See https://github.com/jqlang/jq"
  exit 1
fi

PR_NUMBER="$1"
PATCH_FILE="$2"
TMP_BRANCH="$3"
if [ -z "$PR_NUMBER" ]; then
  echo "${LOGPREFIX} Please provide a PR link or number. For example: https://github.com/ossrs/ffmpeg-webrtc/pull/20"
  exit 1
fi

if [[ "$1" =~ ^https://github.com/ossrs/ffmpeg-webrtc/pull/([0-9]+)$ ]]; then
  PR_NUMBER="${BASH_REMATCH[1]}"
elif [[ "$1" =~ ^[0-9]+$ ]]; then
  PR_NUMBER="$1"
else
  echo "${LOGPREFIX} Invalid input format. Please provide a PR link or number. For example: https://github.com/ossrs/ffmpeg-webrtc/pull/20"
  exit 1
fi

PR_URL="https://github.com/ossrs/ffmpeg-webrtc/pull/$PR_NUMBER"
echo "${LOGPREFIX} Fetching PR #$PR_NUMBER from $PR_URL"

PR_DATA=$(curl -s "https://api.github.com/repos/ossrs/ffmpeg-webrtc/pulls/$PR_NUMBER")
REPO_NAME=$(printf '%s' "$PR_DATA" | jq -r '.head.repo.full_name')
BRANCH_NAME=$(printf '%s' "$PR_DATA" | jq -r '.head.ref')
echo "${LOGPREFIX} Repository: $REPO_NAME, Branch: $BRANCH_NAME"
if [[ -z "$REPO_NAME" || -z "$BRANCH_NAME" ]]; then 
  echo "${LOGPREFIX} Error: REPO_NAME or BRANCH_NAME is empty!"
  exit 1
fi

PR_TITLE=$(printf '%s' "$PR_DATA" | jq -r '.title')
PR_DESCRIPTION=$(printf '%s' "$PR_DATA" | jq -r '.body // ""')
echo "${LOGPREFIX} PR information:"
echo "${LOGPREFIX} ==================================================================="
echo "${LOGPREFIX} $PR_TITLE"
echo "${LOGPREFIX} $PR_DESCRIPTION"
echo "${LOGPREFIX} ==================================================================="
echo "${LOGPREFIX} "
if [[ -z "$PR_TITLE" ]]; then
  echo "${LOGPREFIX} Error: PR title is empty!"
  exit 1
fi

git checkout workflows &&
echo "${LOGPREFIX} Switched to workflows branch." &&
git pull &&
echo "${LOGPREFIX} Pulled latest changes from workflows branch."
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to switch to workflows branch or pull latest changes."
    exit 1
fi

REMOTE_NAME=patch-tmp &&
if git remote | grep -q "^$REMOTE_NAME$"; then
    git remote rm "$REMOTE_NAME"
fi &&
git remote add $REMOTE_NAME https://github.com/${REPO_NAME}.git &&
git fetch $REMOTE_NAME $BRANCH_NAME &&
echo "${LOGPREFIX} Fetch remote $REMOTE_NAME at $(git remote get-url $REMOTE_NAME)"
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to fetch remote branch $BRANCH_NAME from $REMOTE_NAME."
    exit 1
fi

if [[ -z "$TMP_BRANCH" ]]; then
    TMP_BRANCH="tmp-branch-for-patch-$PR_NUMBER"
fi &&
if git branch --list "$TMP_BRANCH" | grep -q "^..$TMP_BRANCH$"; then
    git branch -D "$TMP_BRANCH"
fi &&
git checkout -b $TMP_BRANCH $REMOTE_NAME/$BRANCH_NAME &&
echo "${LOGPREFIX} Checkout branch $TMP_BRANCH from $REMOTE_NAME/$BRANCH_NAME"
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to checkout branch $TMP_BRANCH from $REMOTE_NAME/$BRANCH_NAME."
    exit 1
fi

FIRST_AUTHOR_NAME=$(git log workflows..HEAD --reverse --format='%an' | head -n1)
FIRST_AUTHOR_EMAIL=$(git log workflows..HEAD --reverse --format='%ae' | head -n1)
echo "${LOGPREFIX} Author: $FIRST_AUTHOR_NAME <$FIRST_AUTHOR_EMAIL>"
if [[ -z "$FIRST_AUTHOR_NAME" || -z "$FIRST_AUTHOR_EMAIL" ]]; then
    echo "${LOGPREFIX} Error: Unable to determine the first author of the PR."
    exit 1
fi

COAUTHORS=$(git log workflows..HEAD --format='Co-authored-by: %an <%ae>' |grep -v "$FIRST_AUTHOR_NAME" | sort -u)
COAUTHOR_COUNT=$(echo "$COAUTHORS" | wc -l)
if [[ "$COAUTHOR_COUNT" -gt 0 ]]; then
    echo "${LOGPREFIX} $COAUTHORS"
fi

COMMIT_MSG="$PR_TITLE"
if [[ -n "$PR_DESCRIPTION" ]]; then
  COMMIT_MSG="$COMMIT_MSG\n\n$PR_DESCRIPTION"
fi

if [[ "$COAUTHOR_COUNT" -gt 0 ]]; then
  COMMIT_MSG="$COMMIT_MSG\n"
  COMMIT_MSG="$COMMIT_MSG\n$COAUTHORS"
fi

echo "${LOGPREFIX} Commit information:"
echo "${LOGPREFIX} Author: $FIRST_AUTHOR_NAME <$FIRST_AUTHOR_EMAIL>"
echo "${LOGPREFIX} ==================================================================="
echo -e "$COMMIT_MSG"
echo "${LOGPREFIX} ==================================================================="
echo "${LOGPREFIX} "

if [[ $(git config --list  --local |grep 'user.name' >/dev/null 2>&1 && echo yes) != "yes" ]]; then
    git config --local user.name "$FIRST_AUTHOR_NAME"
fi &&
if [[ $(git config --list  --local |grep 'user.email' >/dev/null 2>&1 && echo yes) != "yes" ]]; then
    git config --local user.email "$FIRST_AUTHOR_EMAIL"
fi &&
git config --list &&
echo "${LOGPREFIX} Set local git user configuration to: $FIRST_AUTHOR_NAME <$FIRST_AUTHOR_EMAIL>"
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to set local git user configuration."
    exit 1
fi

git rebase workflows &&
git reset --soft workflows &&
echo "${LOGPREFIX} Rebased onto workflows branch and reset to soft."
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to rebase or reset changes."
    exit 1
fi

git status &&
git restore --staged .github &&
git restore .github &&
git status &&
echo "${LOGPREFIX} Restored .github directory to the state of workflows branch."
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to restore .github directory."
    exit 1
fi

git commit --author "$FIRST_AUTHOR_NAME <$FIRST_AUTHOR_EMAIL>" -m "$(echo -e "$COMMIT_MSG")" &&
echo "${LOGPREFIX} Squashed commits into a single commit."
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to rebase or commit changes."
    exit 1
fi

git branch -vv &&
git log -1 --pretty=format:"%an <%ae> %h %s"
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to display branch information or last commit."
    exit 1
fi

if [[ -z "$PATCH_FILE" ]]; then
  PATCH_FILE="whip-patch-$PR_NUMBER-$(date +%s).patch" 
fi &&
rm -f $PATCH_FILE &&
git format-patch --add-header "X-Unsent: 1" --to ffmpeg-devel@ffmpeg.org -1 --stdout > $PATCH_FILE &&
echo "${LOGPREFIX} Created patch file: $PATCH_FILE"
if [[ $? -ne 0 ]]; then
    echo "${LOGPREFIX} Failed to create patch file."
    exit 1
fi

git checkout workflows
#git br -D $TMP_BRANCH
#echo "${LOGPREFIX} Removed temporary branch $TMP_BRANCH."

echo "${LOGPREFIX} "
echo "${LOGPREFIX} Patch file created: $PATCH_FILE"
echo "${LOGPREFIX} "
