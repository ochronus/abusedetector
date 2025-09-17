# Release Process Documentation

This document outlines the complete process for creating releases of the abusedetector project, including automated builds, testing, and distribution.

## Overview

The project uses GitHub Actions to automatically build cross-platform binaries and create GitHub releases when git tags are pushed. The process ensures consistent, secure, and tested releases across all supported platforms.

## Supported Platforms

The release process builds binaries for the following targets:

- **Linux x86_64**: `x86_64-unknown-linux-gnu` (with glibc)
- **Linux x86_64 (static)**: `x86_64-unknown-linux-musl` (static binary, no dependencies)
- **Linux ARM64**: `aarch64-unknown-linux-gnu`
- **macOS Intel**: `x86_64-apple-darwin`
- **macOS Apple Silicon**: `aarch64-apple-darwin`
- **Windows x86_64**: `x86_64-pc-windows-msvc`

## Release Workflow

### 1. Pre-Release Checklist

Before creating a release, ensure:

- [ ] All tests pass locally: `cargo test --all --all-features`
- [ ] Code is properly formatted: `cargo fmt --check`
- [ ] No clippy warnings: `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Documentation is up to date
- [ ] CHANGELOG.md is updated with the new version
- [ ] Version in `Cargo.toml` matches the intended release version

### 2. Local Testing

Use the provided script to test the release build process locally:

```bash
# Test current platform
./scripts/test-release.sh

# Test specific target
./scripts/test-release.sh --target x86_64-unknown-linux-musl

# Test multiple targets (if cross-compilation is available)
./scripts/test-release.sh --target x86_64-apple-darwin --target aarch64-apple-darwin

# Quick test without running full test suite
./scripts/test-release.sh --skip-tests
```

This script will:
- Validate prerequisites (Rust, cross-compilation tools)
- Run tests and linting (unless `--skip-tests`)
- Build release binaries for specified targets
- Generate SHA256 checksums
- Report binary sizes and total package size

### 3. Version Management

Update the version in `Cargo.toml`:

```toml
[package]
name = "abusedetector"
version = "0.2.0"  # Update this
edition = "2021"
```

Follow [Semantic Versioning](https://semver.org/):
- **Major** (X.0.0): Breaking changes to CLI or output format
- **Minor** (0.X.0): New features, significant improvements
- **Patch** (0.0.X): Bug fixes, minor improvements

### 4. Changelog Updates

Update `CHANGELOG.md` with the new version:

```markdown
## [0.2.0] - 2024-01-15

### Added
- New feature descriptions

### Changed
- Modified behavior descriptions

### Fixed
- Bug fix descriptions

### Deprecated
- Deprecated feature warnings

### Removed
- Removed feature descriptions

### Security
- Security-related changes
```

### 5. Creating the Release

1. **Commit all changes**:
   ```bash
   git add Cargo.toml CHANGELOG.md
   git commit -m "Prepare release v0.2.0"
   git push origin main
   ```

2. **Create and push the git tag**:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. **GitHub Actions automatically**:
   - Validates version consistency between git tag and `Cargo.toml`
   - Runs the full test suite
   - Builds binaries for all supported platforms
   - Generates SHA256 checksums for all binaries
   - Creates a GitHub release with release notes
   - Uploads all binaries and checksums as release assets

## Automated Release Pipeline

### Validation Phase

The release pipeline first validates:
- Version consistency between git tag and `Cargo.toml`
- Project builds successfully
- All tests pass
- Documentation builds without errors
- Basic CLI functionality works

### Build Phase

For each supported platform:
- Sets up the appropriate build environment
- Installs necessary cross-compilation tools
- Builds the release binary with optimizations
- Strips debug symbols (Unix platforms)
- Generates SHA256 checksum
- Uploads binary and checksum to the release

### Release Phase

- Creates a GitHub release with auto-generated release notes
- Includes installation instructions
- Provides SHA256 checksums for security verification
- Marks pre-releases for versions containing hyphens (e.g., `v1.0.0-beta.1`)

## Manual Release (Emergency)

In case the automated process fails, you can trigger a manual release:

1. **Via GitHub UI**:
   - Go to Actions → Release workflow
   - Click "Run workflow"
   - Enter the tag name (e.g., `v0.2.0`)

2. **Local emergency build**:
   ```bash
   # Build for current platform only
   cargo build --release --locked
   
   # Manual checksum generation
   shasum -a 256 target/release/abusedetector > abusedetector.sha256
   ```

## Release Asset Organization

Each release includes:

### Binaries
- `abusedetector-linux-x86_64` - Linux x86_64 (glibc)
- `abusedetector-linux-x86_64-musl` - Linux x86_64 (static)
- `abusedetector-linux-aarch64` - Linux ARM64
- `abusedetector-macos-x86_64` - macOS Intel
- `abusedetector-macos-aarch64` - macOS Apple Silicon
- `abusedetector-windows-x86_64.exe` - Windows x86_64

### Checksums
- `<binary-name>.sha256` - SHA256 checksum for each binary

### Security Verification

Users can verify downloads using the provided checksums:

```bash
# Linux/macOS
shasum -c abusedetector-linux-x86_64.sha256

# Windows
certutil -hashfile abusedetector-windows-x86_64.exe SHA256
```

## Troubleshooting

### Common Issues

1. **Version Mismatch Error**:
   - Ensure `Cargo.toml` version matches the git tag
   - Example: tag `v0.2.0` should have `version = "0.2.0"` in Cargo.toml

2. **Cross-compilation Failures**:
   - Check that cross-compilation dependencies are available
   - Some targets may require specific system packages

3. **Test Failures**:
   - All tests must pass before release
   - Check platform-specific test issues

4. **Binary Size Issues**:
   - Large binaries may indicate debug symbols weren't stripped
   - Static musl binaries are typically larger than dynamic ones

### Recovery Procedures

1. **Failed Release**:
   - Delete the problematic tag: `git tag -d v0.2.0 && git push origin :refs/tags/v0.2.0`
   - Fix issues and recreate the tag

2. **Incomplete Assets**:
   - Use manual workflow dispatch to rebuild specific platforms
   - Upload missing assets manually through GitHub UI if needed

3. **Corrupted Release**:
   - Delete the GitHub release
   - Recreate by pushing the tag again

## Best Practices

1. **Pre-release Testing**:
   - Always run local release testing before tagging
   - Test on multiple platforms when possible
   - Validate with real-world use cases

2. **Version Planning**:
   - Plan breaking changes for major versions
   - Document deprecations in advance
   - Maintain backward compatibility in minor versions

3. **Release Notes**:
   - Write clear, user-focused release notes
   - Include migration guides for breaking changes
   - Highlight security fixes prominently

4. **Security**:
   - Always provide and verify checksums
   - Sign releases for critical security updates
   - Announce security releases through appropriate channels

## Release Schedule

- **Patch releases**: As needed for critical bugs
- **Minor releases**: Monthly or bi-monthly for features
- **Major releases**: Quarterly or as needed for breaking changes

## Post-Release

After a successful release:

1. **Announce** the release through appropriate channels
2. **Monitor** for user feedback and issues
3. **Update** documentation sites if applicable
4. **Plan** the next release cycle

## Contact

For questions about the release process:
- Open an issue in the GitHub repository
- Contact the maintainers team
- Check existing documentation and FAQ