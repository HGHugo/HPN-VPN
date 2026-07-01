#!/bin/bash
#
# HPN VPN Packaging Script
#
# Creates a deployable tarball containing:
#   - hpn-server binary
#   - hpn-relay binary
#   - install.sh deployment script
#   - Example configurations
#
# Usage:
#   ./package.sh [output_dir]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$PROJECT_ROOT/dist}"

# Get version from Cargo.toml or git
VERSION=$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
if [ -z "$VERSION" ]; then
    VERSION="0.1.0"
fi

# Get git commit hash
GIT_HASH=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Package name
PACKAGE_NAME="hpn-server-${VERSION}-linux-amd64"
PACKAGE_DIR="$OUTPUT_DIR/$PACKAGE_NAME"

echo "Packaging HPN VPN Server v${VERSION} (${GIT_HASH})..."

# Clean and create output directory
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Copy binaries
if [ -f "$PROJECT_ROOT/target/release/hpn-server" ]; then
    cp "$PROJECT_ROOT/target/release/hpn-server" "$PACKAGE_DIR/"
    echo "  Added: hpn-server"
else
    echo "WARNING: hpn-server binary not found in target/release/"
fi

if [ -f "$PROJECT_ROOT/target/release/hpn-relay" ]; then
    cp "$PROJECT_ROOT/target/release/hpn-relay" "$PACKAGE_DIR/"
    echo "  Added: hpn-relay"
else
    echo "WARNING: hpn-relay binary not found in target/release/"
fi

# Copy deployment script
cp "$SCRIPT_DIR/install.sh" "$PACKAGE_DIR/"
chmod +x "$PACKAGE_DIR/install.sh"
echo "  Added: install.sh"

# Copy example configs
mkdir -p "$PACKAGE_DIR/config"
cp "$PROJECT_ROOT/config/server.example.toml" "$PACKAGE_DIR/config/"
cp "$PROJECT_ROOT/config/relay.example.toml" "$PACKAGE_DIR/config/"
echo "  Added: config/server.example.toml"
echo "  Added: config/relay.example.toml"

# Create README for the package
cat > "$PACKAGE_DIR/README.md" << EOF
# HPN Post-Quantum VPN Server

Version: ${VERSION}
Build: ${GIT_HASH}
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

## Quick Start

### Server Installation

\`\`\`bash
# Extract the package
tar -xzf ${PACKAGE_NAME}.tar.gz
cd ${PACKAGE_NAME}

# Run the installer (as root)
sudo ./install.sh server

# Edit the configuration
sudo nano /etc/hpn/server.toml

# Start the service
sudo systemctl start hpn-server
sudo systemctl enable hpn-server
\`\`\`

### Relay Installation

\`\`\`bash
# Run the installer
sudo ./install.sh relay

# Edit the configuration (set upstream server)
sudo nano /etc/hpn/relay.toml

# Start the service
sudo systemctl start hpn-relay
sudo systemctl enable hpn-relay
\`\`\`

## Files Included

- \`hpn-server\` - VPN server binary
- \`hpn-relay\` - Relay/multi-hop binary
- \`install.sh\` - Deployment script
- \`config/server.example.toml\` - Server configuration template
- \`config/relay.example.toml\` - Relay configuration template

## System Requirements

- Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+, Rocky 8+)
- x86_64 architecture
- Root privileges (for TUN device and networking)
- UDP port 51820 (server) or 51821 (relay)

## Support

For issues and documentation:
https://github.com/HGHugo/HPN-PQ
EOF

echo "  Added: README.md"

# Create version file
cat > "$PACKAGE_DIR/VERSION" << EOF
VERSION=${VERSION}
GIT_HASH=${GIT_HASH}
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo "  Added: VERSION"

# Create tarball
cd "$OUTPUT_DIR"
tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
rm -rf "$PACKAGE_NAME"

TARBALL_PATH="$OUTPUT_DIR/${PACKAGE_NAME}.tar.gz"
TARBALL_SIZE=$(du -h "$TARBALL_PATH" | cut -f1)

echo ""
echo "Package created successfully!"
echo "  File: $TARBALL_PATH"
echo "  Size: $TARBALL_SIZE"
echo ""
echo "Deploy with:"
echo "  scp ${PACKAGE_NAME}.tar.gz user@server:/tmp/"
echo "  ssh user@server 'cd /tmp && tar -xzf ${PACKAGE_NAME}.tar.gz && cd ${PACKAGE_NAME} && sudo ./install.sh server'"
