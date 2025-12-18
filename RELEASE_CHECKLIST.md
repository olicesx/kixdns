# Release v0.1.0 Checklist

This document provides a step-by-step checklist for completing the v0.1.0 release.

## ✅ Completed Tasks

The following infrastructure has been set up and is ready for the release:

- [x] **CHANGELOG.md**: Comprehensive changelog documenting all features
- [x] **Release Workflow**: Automated GitHub Actions workflow (`.github/workflows/release.yml`)
  - Builds for Linux (x86_64, ARM64) and FreeBSD (x86_64, ARM64)
  - Creates release with artifacts and checksums
  - Uses modern `softprops/action-gh-release` action
- [x] **RELEASE_NOTES.md**: User-facing release notes
- [x] **RELEASING.md**: Developer documentation for future releases
- [x] **Helper Script**: `scripts/create-release.sh` for easy tag creation
- [x] **README Updates**: Added installation instructions for pre-built binaries
- [x] **Version Verification**: Cargo.toml already has version 0.1.0
- [x] **Code Review**: All changes reviewed and approved
- [x] **Security Check**: No security issues found

## 🔲 Remaining Actions (Manual)

To complete the v0.1.0 release, follow these steps:

### 1. Merge this PR

First, review and merge this pull request to the main branch.

### 2. Create and Push the Release Tag

After merging, create the v0.1.0 tag on the main branch:

```bash
# Checkout and update main branch
git checkout main
git pull origin main

# Create the release tag
git tag -a v0.1.0 -m "Release v0.1.0 - Initial public release"

# Push the tag to trigger the release workflow
git push origin v0.1.0
```

Alternatively, use the helper script:

```bash
git checkout main
git pull origin main
./scripts/create-release.sh 0.1.0
# Then push the tag as instructed by the script
```

### 3. Monitor the Release Workflow

1. Go to the [Actions tab](https://github.com/olicesx/kixdns/actions)
2. Watch the "Release" workflow execution
3. Verify all build jobs complete successfully

The workflow will:
- Build binaries for all 4 platforms (takes ~5-10 minutes)
- Create a GitHub Release
- Upload all binaries and checksums

### 4. Verify the Release

After the workflow completes:

1. Visit the [Releases page](https://github.com/olicesx/kixdns/releases)
2. Verify the v0.1.0 release is created
3. Check that all 8 files are present:
   - kixdns-linux-x86_64.tar.gz
   - kixdns-linux-x86_64.tar.gz.sha256
   - kixdns-linux-arm64.tar.gz
   - kixdns-linux-arm64.tar.gz.sha256
   - kixdns-freebsd-x86_64.tar.gz
   - kixdns-freebsd-x86_64.tar.gz.sha256
   - kixdns-freebsd-arm64.tar.gz
   - kixdns-freebsd-arm64.tar.gz.sha256
4. Test downloading and verifying a binary:

```bash
wget https://github.com/olicesx/kixdns/releases/download/v0.1.0/kixdns-linux-x86_64.tar.gz
wget https://github.com/olicesx/kixdns/releases/download/v0.1.0/kixdns-linux-x86_64.tar.gz.sha256
sha256sum -c kixdns-linux-x86_64.tar.gz.sha256
```

### 5. Post-Release (Optional)

- Announce the release (social media, forums, etc.)
- Update project website (if applicable)
- Close any milestone or project board items related to v0.1.0

## 🎉 Success!

Once these steps are complete, KixDNS v0.1.0 will be officially released!

## Troubleshooting

### If the workflow fails:

1. Check the error logs in the Actions tab
2. Common issues:
   - Build failures: Check Rust toolchain compatibility
   - Permission errors: Verify workflow permissions are set correctly
   - Upload errors: Check GitHub token permissions

### If you need to redo the release:

1. Delete the failed release from GitHub
2. Delete the tag: `git push origin :refs/tags/v0.1.0`
3. Fix any issues
4. Create and push the tag again

## Support

For questions or issues with the release process, please:
- Review the [RELEASING.md](RELEASING.md) documentation
- Check the GitHub Actions workflow logs
- Open an issue if you encounter problems
