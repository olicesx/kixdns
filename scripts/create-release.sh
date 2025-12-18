#!/bin/bash
# Script to create a new release tag for KixDNS

set -e

# Check if version argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.0"
    exit 1
fi

VERSION=$1
TAG="v${VERSION}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not in a git repository"
    exit 1
fi

# Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Error: Tag $TAG already exists"
    exit 1
fi

# Check if there are uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "Error: You have uncommitted changes. Please commit or stash them first."
    exit 1
fi

# Verify Cargo.toml version matches
CARGO_VERSION=$(grep '^version = ' Cargo.toml | head -n 1 | sed 's/version = "\(.*\)"/\1/')
if [ "$CARGO_VERSION" != "$VERSION" ]; then
    echo "Warning: Cargo.toml version ($CARGO_VERSION) does not match release version ($VERSION)"
    read -p "Do you want to continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "Creating release tag: $TAG"
echo "This will trigger the release workflow on GitHub."
echo

read -p "Are you sure you want to create this release? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Release cancelled."
    exit 1
fi

# Create and push the tag
git tag -a "$TAG" -m "Release $TAG"
echo "Tag $TAG created locally."
echo
echo "To push the tag and trigger the release workflow, run:"
echo "  git push origin $TAG"
echo
echo "Or to push all tags:"
echo "  git push --tags"
