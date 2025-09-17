#!/bin/bash
set -euo pipefail

# Local release testing script for abusedetector
# This script helps test the release build process locally before tagging

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}==== $1 ====${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get file size in a cross-platform way
get_file_size() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        stat -f%z "$1" 2>/dev/null
    else
        stat -c%s "$1" 2>/dev/null
    fi
}

# Function to format file size
format_size() {
    local size=$1
    if (( size > 1048576 )); then
        echo "$(( size / 1048576 ))MB"
    elif (( size > 1024 )); then
        echo "$(( size / 1024 ))KB"
    else
        echo "${size}B"
    fi
}

# Parse command line arguments
TARGETS=()
SKIP_TESTS=false
CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGETS+=("$2")
            shift 2
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --target TARGET     Build for specific target (can be used multiple times)"
            echo "  --skip-tests        Skip running tests"
            echo "  --clean             Clean build artifacts first"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Default targets:"
            echo "  - Current platform (detected automatically)"
            echo ""
            echo "Available targets:"
            echo "  - x86_64-unknown-linux-gnu"
            echo "  - x86_64-unknown-linux-musl"
            echo "  - aarch64-unknown-linux-gnu"
            echo "  - x86_64-apple-darwin"
            echo "  - aarch64-apple-darwin"
            echo "  - x86_64-pc-windows-msvc"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# Detect current platform if no targets specified
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    case "$OSTYPE" in
        linux*)
            TARGETS=("x86_64-unknown-linux-gnu")
            ;;
        darwin*)
            if [[ $(uname -m) == "arm64" ]]; then
                TARGETS=("aarch64-apple-darwin")
            else
                TARGETS=("x86_64-apple-darwin")
            fi
            ;;
        msys*|cygwin*|win32*)
            TARGETS=("x86_64-pc-windows-msvc")
            ;;
        *)
            print_warning "Unknown OS: $OSTYPE, defaulting to x86_64-unknown-linux-gnu"
            TARGETS=("x86_64-unknown-linux-gnu")
            ;;
    esac
fi

print_header "Release Build Test for abusedetector"
echo "Targets: ${TARGETS[*]}"
echo "Skip tests: $SKIP_TESTS"
echo "Clean build: $CLEAN"
echo ""

# Check prerequisites
print_header "Checking Prerequisites"

if ! command_exists cargo; then
    print_error "cargo not found. Please install Rust."
    exit 1
fi
print_success "cargo found"

if ! command_exists rustc; then
    print_error "rustc not found. Please install Rust."
    exit 1
fi
print_success "rustc found"

# Check if cross is needed and available
CROSS_NEEDED=false
for target in "${TARGETS[@]}"; do
    case "$target" in
        x86_64-unknown-linux-musl|aarch64-unknown-linux-gnu)
            if [[ "$OSTYPE" == "linux"* ]]; then
                CROSS_NEEDED=true
                break
            fi
            ;;
    esac
done

if $CROSS_NEEDED; then
    if ! command_exists cross; then
        print_warning "cross not found. Installing..."
        cargo install cross --git https://github.com/cross-rs/cross
    fi
    print_success "cross available"
fi

# Clean if requested
if $CLEAN; then
    print_header "Cleaning Build Artifacts"
    cargo clean
    print_success "Build artifacts cleaned"
fi

# Run tests if not skipped
if ! $SKIP_TESTS; then
    print_header "Running Tests"

    echo "Running format check..."
    if cargo fmt -- --check; then
        print_success "Format check passed"
    else
        print_error "Format check failed"
        exit 1
    fi

    echo "Running clippy..."
    if cargo clippy --all-targets --all-features -- -D warnings; then
        print_success "Clippy passed"
    else
        print_error "Clippy failed"
        exit 1
    fi

    echo "Running tests..."
    if cargo test --all --all-features; then
        print_success "Tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
else
    print_warning "Skipping tests"
fi

# Create release directory
RELEASE_DIR="$PROJECT_ROOT/target/release-test"
mkdir -p "$RELEASE_DIR"

# Build for each target
print_header "Building Release Binaries"

for target in "${TARGETS[@]}"; do
    echo ""
    echo "Building for target: $target"

    # Install target if needed
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Installing target $target..."
        rustup target add "$target"
    fi

    # Determine build command and binary name
    case "$target" in
        x86_64-unknown-linux-musl|aarch64-unknown-linux-gnu)
            if [[ "$OSTYPE" == "linux"* ]]; then
                BUILD_CMD="cross build --release --target $target --locked"
            else
                BUILD_CMD="cargo build --release --target $target --locked"
            fi
            ;;
        *)
            BUILD_CMD="cargo build --release --target $target --locked"
            ;;
    esac

    # Execute build
    echo "Running: $BUILD_CMD"
    if $BUILD_CMD; then
        print_success "Build completed for $target"
    else
        print_error "Build failed for $target"
        continue
    fi

    # Determine binary name and copy to release directory
    if [[ "$target" == *"windows"* ]]; then
        BINARY_NAME="abusedetector.exe"
        ASSET_NAME="abusedetector-${target}.exe"
    else
        BINARY_NAME="abusedetector"
        ASSET_NAME="abusedetector-${target}"
    fi

    BINARY_PATH="$PROJECT_ROOT/target/$target/release/$BINARY_NAME"

    if [[ -f "$BINARY_PATH" ]]; then
        cp "$BINARY_PATH" "$RELEASE_DIR/$ASSET_NAME"

        # Strip binary on Unix systems
        if [[ "$target" != *"windows"* ]] && command_exists strip; then
            strip "$RELEASE_DIR/$ASSET_NAME" 2>/dev/null || true
        fi

        # Get file size
        SIZE=$(get_file_size "$RELEASE_DIR/$ASSET_NAME")
        FORMATTED_SIZE=$(format_size "$SIZE")

        print_success "Binary created: $ASSET_NAME ($FORMATTED_SIZE)"

        # Generate checksum
        if command_exists shasum; then
            (cd "$RELEASE_DIR" && shasum -a 256 "$ASSET_NAME" > "$ASSET_NAME.sha256")
        elif command_exists sha256sum; then
            (cd "$RELEASE_DIR" && sha256sum "$ASSET_NAME" > "$ASSET_NAME.sha256")
        else
            print_warning "No SHA256 utility found, skipping checksum"
        fi
    else
        print_error "Binary not found at $BINARY_PATH"
    fi
done

print_header "Release Test Summary"

if [[ -d "$RELEASE_DIR" ]]; then
    echo "Release artifacts created in: $RELEASE_DIR"
    echo ""
    echo "Files:"
    ls -la "$RELEASE_DIR"

    echo ""
    echo "Total size of all binaries:"
    TOTAL_SIZE=0
    for file in "$RELEASE_DIR"/abusedetector-*; do
        if [[ -f "$file" && ! "$file" == *.sha256 ]]; then
            SIZE=$(get_file_size "$file")
            TOTAL_SIZE=$((TOTAL_SIZE + SIZE))
        fi
    done
    echo "$(format_size "$TOTAL_SIZE")"

    print_success "Release test completed successfully!"
    echo ""
    echo "To test the binaries:"
    echo "  cd $RELEASE_DIR"
    echo "  ./abusedetector-<target> --help"
else
    print_error "No release artifacts created"
    exit 1
fi

echo ""
print_header "Next Steps"
echo "1. Test the binaries manually"
echo "2. If everything looks good, create and push a git tag:"
echo "   git tag v0.1.0"
echo "   git push origin v0.1.0"
echo "3. The GitHub Actions workflow will automatically create a release"
