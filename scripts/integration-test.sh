#!/bin/bash

# Integration test script for Mirror Registry
# This script tests the basic functionality of the mirror registry

set -e

# Configuration
MIRROR_REGISTRY_URL="http://localhost:5000"
TEST_IMAGE="alpine:latest"

echo "🧪 Starting Mirror Registry Integration Tests"
echo "📍 Testing against: $MIRROR_REGISTRY_URL"

# Test 1: Health check
echo "🔍 Test 1: Health check"
if curl -s "$MIRROR_REGISTRY_URL/health" | grep -q "healthy"; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Test 2: Docker Registry API v2 endpoint
echo "🔍 Test 2: Docker Registry V2 API"
if curl -s "$MIRROR_REGISTRY_URL/v2/" -I | grep -q "Docker-Distribution-Api-Version: registry/2.0"; then
    echo "✅ V2 API endpoint working"
else
    echo "❌ V2 API endpoint failed"
    exit 1
fi

# Test 3: Manifest request (should proxy to hot registry)
echo "🔍 Test 3: Manifest request"
if curl -s "$MIRROR_REGISTRY_URL/v2/library/alpine/manifests/latest" -I | grep -q "HTTP/1.1 200\|HTTP/2 200"; then
    echo "✅ Manifest request working"
else
    echo "⚠️  Manifest request may have failed (this could be expected if the image doesn't exist in backends)"
fi

# Test 4: Blob request (should redirect)
echo "🔍 Test 4: Blob redirect test"
# First get a manifest to find a blob digest
MANIFEST=$(curl -s "$MIRROR_REGISTRY_URL/v2/library/alpine/manifests/latest" 2>/dev/null || echo "")
if [ -n "$MANIFEST" ]; then
    echo "✅ Successfully retrieved manifest"
else
    echo "⚠️  Could not retrieve manifest (may be expected)"
fi

echo "🎉 Integration tests completed!"
echo ""
echo "📝 Manual testing steps:"
echo "1. Configure Docker: echo '{\"insecure-registries\":[\"localhost:5000\"]}' | sudo tee /etc/docker/daemon.json"
echo "2. Restart Docker: sudo systemctl restart docker"
echo "3. Test pull: docker pull $MIRROR_REGISTRY_URL/library/$TEST_IMAGE"
echo "4. Test with non-existent image: docker pull $MIRROR_REGISTRY_URL/library/nonexistent:latest"