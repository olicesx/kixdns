# How to Create a Release

This document describes the process for creating a new release of KixDNS.

## Prerequisites

- Write access to the repository
- Git installed and configured
- All changes merged to the main branch

## Release Process

### 1. Prepare the Release

1. Ensure the version in `Cargo.toml` matches the release version (currently: `0.1.0`)
2. Update `CHANGELOG.md` with the changes for this release
3. Commit all changes to the main branch

### 2. Create the Release Tag

The easiest way to create a release is to use the provided helper script:

```bash
./scripts/create-release.sh 0.1.0
```

This script will:
- Verify the version matches `Cargo.toml`
- Create an annotated git tag `v0.1.0`
- Provide instructions for pushing the tag

Alternatively, create the tag manually:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
```

### 3. Push the Tag

Push the tag to GitHub to trigger the release workflow:

```bash
git push origin v0.1.0
```

Or push all tags:

```bash
git push --tags
```

### 4. Automated Release Process

Once the tag is pushed, the GitHub Actions workflow (`.github/workflows/release.yml`) will automatically:

1. Create a new GitHub Release with the tag
2. Build binaries for all supported platforms:
   - Linux (x86_64, ARM64)
   - FreeBSD (x86_64, ARM64)
3. Upload the compiled binaries as release assets
4. Generate and upload SHA256 checksums for verification

### 5. Verify the Release

After the workflow completes:

1. Go to the [Releases page](https://github.com/olicesx/kixdns/releases)
2. Verify the release was created with the correct version
3. Check that all binary assets are present
4. Test download and verification of checksums

## For v0.1.0 Release

To create the v0.1.0 release from the current main branch:

```bash
# Make sure you're on the main branch
git checkout main
git pull origin main

# Create and push the tag
git tag -a v0.1.0 -m "Release v0.1.0 - Initial public release"
git push origin v0.1.0
```

The release workflow will automatically build and package the binaries from the main branch commit `195715c`.

## Troubleshooting

### Tag Already Exists

If you need to recreate a tag:

```bash
# Delete local tag
git tag -d v0.1.0

# Delete remote tag
git push origin :refs/tags/v0.1.0

# Create and push the new tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### Release Workflow Failed

If the automated release workflow fails:

1. Check the [Actions tab](https://github.com/olicesx/kixdns/actions) for error details
2. Fix any issues in the workflow file
3. Delete and recreate the release/tag
4. Try again

## Manual Release (Fallback)

If the automated workflow cannot be used:

1. Build binaries locally for each platform
2. Create checksums: `sha256sum kixdns-* > checksums.txt`
3. Create a release manually on GitHub
4. Upload all binaries and checksums as assets

## Post-Release Tasks

After creating a release:

1. Announce the release (if applicable)
2. Update documentation with new version numbers
3. Begin development for the next version
