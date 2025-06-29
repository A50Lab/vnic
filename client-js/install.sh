#!/bin/bash

echo "🔧 Setting up VietChain KYC DID JavaScript Client..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js >= 18.0.0"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2)
REQUIRED_VERSION="18.0.0"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$NODE_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Node.js version $NODE_VERSION is too old. Required: >= $REQUIRED_VERSION"
    exit 1
fi

echo "✅ Node.js version: $NODE_VERSION"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Make script executable
chmod +x did-client.js

echo "🎉 Setup complete!"
echo ""
echo "Usage:"
echo "  node did-client.js help          # Show help"
echo "  node did-client.js status        # Check chain status"
echo "  node did-client.js register      # Register new DID"
echo "  node did-client.js query <id>    # Query existing DID"
echo ""
echo "Make sure your VietChain node is running:"
echo "  ignite chain serve"