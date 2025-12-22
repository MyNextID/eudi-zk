# JWS/JWT Membership Verification Without Decoding

We present an efficient method for verifying membership of key-value pairs in
JWS/JWT payloads within zero-knowledge circuits without performing full payload
decoding. The algorithm exploits the base64url encoding properties to enable
direct comparison of encoded strings, reducing computational overhead in
resource-constrained environments.

## Introduction

Modern digital signature formats such as JWS (JSON Web Signature) and JWT (JSON
Web Token) apply cryptographic signatures to base64url-encoded content.
Verification of specific claims within these tokens traditionally requires
decoding the payload—an operation that proves computationally expensive within
zero-knowledge circuits.

The fundamental problem. Let $P$ denote a JSON payload and $E(P)$ its
base64url encoding. Given a key-value pair $(k,v)$ and access only to E(P),
we wish to verify $(k,v) \in P$ without computing $P = D(E(P))$, where $D$
represents the decoding operation.

Our approach: Rather than decode $E(P)$, we construct $E(S)$ where $S$ is a
properly formatted JSON fragment containing $(k,v)$, then perform substring
matching on the encoded representations. The central challenge lies in aligning
base64url encoding boundaries between arbitrary JSON positions and 6-bit base64
chunks.

## Preliminaries

### Encoding fundamentals

Let us establish the basic parameters of our encoding scheme:

- JSON text is UTF-8 encoded, where each character occupies 8 bits
- Base64url encoding maps 6-bit chunks to printable ASCII characters
- The encoding function $E: \{0,1\}^{8n} \to \mathcal{B}^{\lceil 4n/3 \rceil}$
maps $n$ bytes to base64url alphabet $\mathcal{B}$

The alignment problem. Since $\gcd(6,8) = 2$, the encoding boundaries align only at positions where $`\text{bit\_offset} \equiv 0 \pmod{6}`$. At arbitrary byte positions $p$ in the original text, we have $`\text{bit\_offset} = 8p \bmod 6 \in \{0,2,4\}`$.

### Assumptions

We make the following simplifying assumptions, valid for most practical credential formats:

- Assumption 1 (Unique keys). All keys appearing in the JSON object are distinct.
- Assumption 2 (Canonical form). The JSON representation contains no extraneous whitespace, newlines, or duplicate keys.

## The Alignment Algorithm

### Computing boundary adjustments

Let $w = (i_{\text{start}}, i_{\text{end}})$ denote the byte positions of a target substring in the original JSON. We compute adjusted positions $(i'_{\text{start}}, i'_{\text{end}})$ that align with base64 chunk boundaries.

**Algorithm ALIGN** (Boundary adjustment)

```bash
function ALIGN(i_start, i_end)
    r_start <- (i_start × 8) mod 6
    r_end <- (i_end × 8) mod 6
    
    i'_start <- i_start - ⌊r_start/2⌋
    
    if r_end = 2 then
        i'_end <- i_end + 2
    else if r_end = 4 then
        i'_end <- i_end + 1
    else
        i'_end <- i_end
    
    return (i'_start, i'_end)
```

After applying ALIGN, we have $(i'_{\text{start}} \times 8) \bmod 6 = 0$ and the encoding of bytes $[i'_{\text{start}}, i'_{\text{end}}]$ aligns with base64 character boundaries.

Proof. The residue $r_{\text{start}} \in \{0,2,4\}$ by construction. Subtracting $\lfloor r_{\text{start}}/2 \rfloor$ yields: for $r=0$, subtract 0; for $r=2$, subtract 1 byte (8 bits); for $r=4$, subtract 2 bytes (16 bits). In each case, $(i'_{\text{start}} \times 8) \bmod 6 = 0$. The end adjustment ensures complete base64 character coverage.

### Substring construction and comparison

Having computed aligned boundaries, we construct a matchable fragment:

Algorithm VERIFY-MEMBERSHIP

1. Identify target key-value pair $(k,v)$ in original JSON coordinate space
2. Compute $(i_{\text{start}}, i_{\text{end}})$ spanning the complete JSON expression for $(k,v)$
3. Apply ALIGN to obtain $(i'_{\text{start}}, i'_{\text{end}})$
4. Construct JSON fragment $S$ containing $(k,v)$ with appropriate delimiters
5. Prepend/append padding characters to $S$ to match aligned boundaries
6. Compute $E(S)$ and extract corresponding substring from $E(P)$
7. Return whether $E(S)$ equals the extracted substring

Example: Consider verifying `"role":"admin"` appears in a JWT payload. If this string starts at byte position 10:

- Compute $r = (10 \times 8) \bmod 6 = 80 \bmod 6 = 2$
- Adjust: $i'_{\text{start}} = 10 - 1 = 9$
- Construct padded fragment matching byte 9 through end of value
- Compare base64url encodings directly

### Delimiter handling

To ensure exact matching, we must include appropriate JSON structural
characters:

- For key-value verification: include surrounding quotes and colon: `"key":"value"`
- For object membership: may include braces: `{"key":"value"}`
- For array elements: may include brackets and commas as needed

The padding characters added during alignment must come from the actual JSON
context to ensure encoding equivalence.

## Limitations and Extensions

**Multiple matches.** If Assumption 1 fails and keys are non-unique, our method returns success if any instance matches. Disambiguation requires additional positional constraints.

**Complex JSON structures.** For nested objects or arrays, the fragment construction must carefully preserve structural context and more sophisticated processing.

**Non-canonical JSON.** Variable whitespace violates Assumption 2 and breaks exact matching. Preprocessing or canonicalization may be necessary.

## Conclusion

We have presented a practical algorithm for membership verification in
base64url-encoded JSON without full decoding. The key insight—that base64 encoding alignment can be computed and corrected in constant time—enables direct comparison of encoded substrings, eliminating expensive decoding operations while maintaining verification soundness under reasonable assumptions about JSON structure.
