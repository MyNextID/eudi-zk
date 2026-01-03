#!/bin/bash
#
# A simple script to test the endpoints
# Version: 2

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

# Extract circuit name from file path
# Removes directory path and .json extension
circuit_name=$(basename "$input" .json)

echo "Input file: $input"
echo "Circuit name: $circuit_name"
echo

echo -e "--- Generating Proof ---"

# Generate proof using extracted circuit name
prove_response=$(curl -s -X POST "http://localhost:8080/prove/${circuit_name}" \
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
public_input=$(jq -c .public "${input}")
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

# Verify proof using extracted circuit name
verify_response=$(curl -s -X POST "http://localhost:8080/verify/${circuit_name}" \
  -H "Content-Type: application/json" \
  -d @verify_payload.json)

echo "Verification response:"
echo "$verify_response" | jq '.'
echo