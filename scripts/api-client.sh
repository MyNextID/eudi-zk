#!/bin/bash

#
# A simple script to test the endpoints
#

# Exit on error
set -e

# Proof creation and verification

echo -e "=== ZK Proof Generation and Verification ===\n"


# Validate input argument
if [ -z "$1" ]; then
    echo "Error: No input file provided"
    echo "Usage: $0 <input-json-file>"
    exit 1
fi

input="$1"

# Check if file exists
if [ ! -f "$input" ]; then
    echo "Error: Input file '$input' not found"
    exit 1
fi

# Validate JSON syntax
if ! jq empty "$input" 2>/dev/null; then
    echo "Error: Invalid JSON in file '$input'"
    exit 1
fi

echo "Input file: $input"
echo -e "\n--- Generating Proof ---"

# Generate proof
prove_response=$(curl -s -X POST http://localhost:8080/prove/compare-bytes \
  -H "Content-Type: application/json" \
  -d @"${input}")

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
public_input=$(jq .public payload.json)
echo $public_input

cat > verify_payload.json <<EOF
{
  "public": $public_input,
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
