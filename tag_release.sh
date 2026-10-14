#!/usr/bin/env bash
# This script tags the latest commit on main with a version number and pushes the tag to the remote repository.
set -e
# Check if a version number is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi
VERSION="$1"
# Check if the version number is valid
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: Version number must be in the format X.Y.Z (e.g., 1.0.0)"
  exit 1
fi
# Ensure the local repository is clean (including untracked files)
if [ -n "$(git status --porcelain)" ]; then
  echo "Error: Your working directory is not clean. Please commit or stash your changes before tagging."
  exit 1
fi
# Ensure you are on the main branch and up to date with the remote
git checkout main
git pull --ff-only origin main
git fetch --tags origin
# Ensure the tag does not already exist locally or on the remote
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
  echo "Error: Tag v$VERSION already exists. Please use a different version number."
  exit 1
fi
# Create a tag with the provided version number
git tag -a "v$VERSION" -m "Release version $VERSION"
# Push the tag to the remote repository
git push origin "v$VERSION"
echo "Successfully tagged and pushed version $VERSION"
