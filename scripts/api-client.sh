#!/bin/bash

#
# A simple script to test the endpoints
#

# Exit on error
set -e

# Simple call
#
# curl -X POST http://localhost:8080/prove/compare-bytes \
#   -H "Content-Type: application/json" \
#   -d @payload.json \
#   | jq '.'

# Proof creation and verification

echo -e "=== ZK Proof Generation and Verification ===\n"

# Generate proof
prove_response=$(curl -s -X POST http://localhost:8080/prove/compare-bytes \
  -H "Content-Type: application/json" \
  -d @payload.json)

# Check for errors
if echo "$prove_response" | jq -e '.error' > /dev/null 2>&1; then
  echo -e "Error generating proof:"
  echo "$prove_response" | jq '.'
  exit 1
fi

echo -e "Proof generated successfully!"
echo "$prove_response" | jq '.'
echo

# Extract proof
proof=$(echo "$prove_response" | jq -r '.proof')
echo "Proof (first 80 chars): ${proof:0:80}..."
echo

# Step 2: Create verification payload
echo -e "Step 2: Verifying proof..."

# extract the public input
public_input=$(jq .public_input payload.json)
echo $public_input

cat > verify_payload.json <<EOF
{
  "public_input": $public_input,
  "proof": "$proof"
}
EOF

echo "Verification payload:"
cat verify_payload.json | jq '.'
echo

# Verify proof
verify_response=$(curl -s -X POST http://localhost:8080/verify/compare-bytes \
  -H "Content-Type: application/json" \
  -d @verify_payload.json)

echo "Verification response:"
echo "$verify_response" | jq '.'
echo
