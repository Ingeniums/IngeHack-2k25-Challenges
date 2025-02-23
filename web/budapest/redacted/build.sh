#!/bin/bash

# Create build directory if it doesn't exist
mkdir -p build

# Build for Linux (64-bit) with CGO_ENABLED=1
echo "Building for Linux (amd64)..."
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-elf-gcc go build -o build/budapast-linux-amd64 main.go

# Build for Linux (ARM64) with CGO_ENABLED=1
echo "Building for Linux (arm64)..."
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=x86_64-elf-gcc go build -o build/budapast-linux-arm64 main.go

# Build for Windows (64-bit) with CGO_ENABLED=1
echo "Building for Windows (amd64)..."
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o build/budapast-windows-amd64.exe main.go

# Build for macOS (64-bit Intel)
echo "Building for macOS (amd64)..."
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o build/budapast-macos-amd64 main.go

# Build for macOS (Apple Silicon)
echo "Building for macOS (arm64)..."
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o build/budapast-macos-arm64 main.go

echo "Build complete! Binaries are in the 'build' directory."
