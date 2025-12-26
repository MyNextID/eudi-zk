# Domain-Bound Certificate Revocation List (DB-CRL) <!-- omit in toc -->

Version: draft

## Table of Contents <!-- omit in toc -->

- [0. Performance improvement](#0-performance-improvement)
- [1. Introduction](#1-introduction)
  - [1.1 Purpose](#11-purpose)
  - [1.2 Goals](#12-goals)
  - [1.3 Non-Goals](#13-non-goals)
  - [1.4 Threat Model](#14-threat-model)
    - [Trusted Entities](#trusted-entities)
    - [Untrusted Entities](#untrusted-entities)
    - [Out of Scope](#out-of-scope)
- [2. Terminology](#2-terminology)
  - [2.1 Definitions](#21-definitions)
  - [2.2 Notation](#22-notation)
- [3. System Overview](#3-system-overview)
  - [3.1 Architecture](#31-architecture)
  - [3.2 Workflow Overview](#32-workflow-overview)
- [4. Cryptographic Primitive](#4-cryptographic-primitive)
  - [4.1 Hash Function](#41-hash-function)
  - [4.2 Domain-Bound Revocation ID Computation](#42-domain-bound-revocation-id-computation)
  - [4.3 Random Value Generation](#43-random-value-generation)
- [5. Domain Canonicalization](#5-domain-canonicalization)
- [6. Protocol Specification](#6-protocol-specification)
  - [6.1 Credential Issuance](#61-credential-issuance)
  - [6.2 Credential Presentation](#62-credential-presentation)
  - [6.3 Presentation Verification](#63-presentation-verification)
  - [6.4 CRL Format](#64-crl-format)
  - [6.5 Status Updates](#65-status-updates)
- [7. Extension - time-dependent revocation id](#7-extension---time-dependent-revocation-id)

## 0. Performance improvement

In the 1st proposal CRLs hold all credential revocation IDs, hence are fully populated.

Proposed simplification:

```text
Circuit proves:

1. revocation_id and domain_rev_id are valid for this credential
2. domain_rev_id = H(revocation_id || domain)
3. CRL ID matches credential's assigned CRL

CRL contains:

- Only REVOKED domain_rev_ids (not valid/suspended)
- Much smaller size (only revoked entries)

Verification:
IF domain_rev_id ∈ CRL.revoked_set:
    REJECT
ELSE:
    ACCEPT (assuming proof is valid)
```

## 1. Introduction

### 1.1 Purpose

This specification defines the Domain-Bound Certificate Revocation List (DB-CRL)
system, which enables credential status verification in zero-knowledge proof
systems while maintaining unlinkability across different verifiers.

### 1.2 Goals

- Verifier Unlinkability: Prevent different verifiers from correlating credentials by comparing revocation identifiers
- Independent Verification: Enable verifiers to check credential status without holder cooperation
- Privacy-Preserving: Minimize information leakage about credential usage patterns
- Practical: Maintain reasonable computational and operational costs

### 1.3 Non-Goals

- Holder Anonymity from Issuer: The issuer is expected to know which credentials are issued to which holders
- Complete Verifier Anonymity: The issuer may observe which verifiers query which CRL lists

### 1.4 Threat Model

#### Trusted Entities

- Issuers: Trusted to generate valid credentials and maintain accurate CRLs
- Cryptographic Primitives: Hash functions and ZKP systems operate as specified

#### Untrusted Entities

- Holders: May attempt to present revoked credentials or manipulate domain bindings
- Verifiers (individually): Assumed honest but may be curious
- Colluding Verifiers: May attempt to correlate credentials across domains

#### Out of Scope

- Compromise of cryptographic primitives
- Issuer misbehavior or collusion with holders

## 2. Terminology

### 2.1 Definitions

- Verifiable Credential: A digitally signed attestation containing claims about a holder.
- Revocation Identifier (revocation_id): A secret, randomly generated value
assigned to a credential at issuance, used to compute domain-bound revocation
identifiers.
- Domain-Bound Revocation Identifier (domain_rev_id): A public value computed as
`H(revocation_id || domain || status)`, used by verifiers to check credential
status.
- CRL List: A collection of credentials grouped together for revocation
management. Each credential belongs to exactly one CRL list.
- CRL List Identifier (list_index): An identifier for a CRL list (e.g., batch number, issuance date).
- Domain: A canonical string identifier for a verifier, typically derived from their DNS domain name.
- Status: The current state of a credential, one of: `valid`, `suspended`, `revoked`.
- Verifier: An entity that receives and verifies credentials and their status.
- Holder: An entity that possesses and presents credentials.
- Issuer: An entity that issues credentials and maintains CRLs.

### 2.2 Notation

- `||`: Byte concatenation
- `H()`: Cryptographic hash function (defined in Section 4)
- `a == b`: Equality check
- `a ∈ S`: Membership check (a is in set S)
- `[a, b, c]`: Array/list of elements
- `{k: v}`: Key-value mapping

## 3. System Overview

### 3.1 Architecture

Issuer issues credentials and and manages the CRL. Verifier can obtain the CRL
directly from the issuer or via the holder's wallet.

```bash
┌──────────────────────────────────────────────┐
│                  ISSUER                      │
│  ┌──────────────┐      ┌──────────────┐      │
│  │ Credential   │      │   CRL        │      │
│  │ Issuance     │─────▶│ Management   │      │
│  └──────────────┘      └──────────────┘      │
│         │                 │    │             │
│         │                 │    │ CRL Query   │
│         │ Issue           │    │ Endpoint    │
└─────────┼─────────────────┼────┼─────────────┘
          │  _______________│    │
          │ │                    │
          ▼ ▼                    ▼
    ┌──────────┐           ┌──────────┐
    │  HOLDER  │──Present─▶│ VERIFIER │
    │  Wallet  │           │          │
    └──────────┘           └──────────┘
         │                      │
         │                      │
         └──────ZKP Proof───────┘
            (domain_rev_id)
```

### 3.2 Workflow Overview

1. Issuance: Issuer generates credential with secret `revocation_id` and assigns `list_index`
2. Storage: Holder stores credential and associated cryptographic material
3. Presentation: Holder computes `domain_rev_id` for target verifier's domain
4. Proof Generation: Holder creates ZKP proving correct computation of `domain_rev_id`
5. Verification: Verifier validates proof and credential claims
6. Status Check: Verifier queries CRL for their domain to check credential status
7. Decision: Verifier accepts or rejects credential based on status

## 4. Cryptographic Primitive

### 4.1 Hash Function

Algorithm: SHA-256

Properties Required:

- Collision resistance
- Pre-image resistance
- Second pre-image resistance

Implementation Notes:

- MUST use SHA-256 as defined in FIPS 180-4
- Input encoding MUST be UTF-8 for strings
- Output MUST be 32 bytes (256 bits)

### 4.2 Domain-Bound Revocation ID Computation

Design

```go
// Circuit outputs (public)
domain_rev_id = H(revocation_id || domain)

// Verifier computes (off-circuit)
valid_hash = H(domain_rev_id || "valid")
suspended_hash = H(domain_rev_id || "suspended")
revoked_hash = H(domain_rev_id || "revoked")

// CRL contains only one of these hashes
// Verifier checks which one is present to determine status
```

```go
// Encode inputs
domain_bytes = domain.encode('UTF-8')
status_bytes = status.encode('UTF-8')

// Concatenate: revocation_id || domain || status
domain_rev_id = H(revocation_id + domain_bytes)
domain_rev_status = H(domain_revocation_id + status_bytes)
```

Input Requirements:

- `revocation_id`: MUST be exactly 32 bytes
- `domain`: MUST be canonical ASCII domain (see Section 5)
- `status`: MUST be one of: `"valid"`, `"suspended"`, `"revoked"`

Note: status can be extended with custom statues.

Security Properties:

- Given `domain_rev_id`, computationally infeasible to determine `revocation_id`
- Different domains produce statistically independent `domain_rev_id` values
- Cannot compute `domain_rev_id` for different status without `revocation_id`

### 4.3 Random Value Generation

- MUST use cryptographically secure random number generator
- MUST generate at least 256 bits of entropy
- MUST be unique per credential

## 5. Domain Canonicalization

Domain canonicalization ensures that different representations of the same
verifier domain produce identical `domain_rev_id` values, preventing validation
errors due to formatting differences.

A *canonical domain* is the effective top-level domain plus one label (eTLD+1),
represented in lowercase ASCII.

Canonicalization Function:

Let `canonicalize: String → String` be defined as follows.
Given input string `s`:

1. Remove protocol prefix (if `://` ∈ s`, take substring after first`://`)
2. Remove port suffix (if `:` ∈ s`, take substring before first`:`)
3. Remove path suffix (if `/` ∈ s`, take substring before first`/`)
4. Convert to lowercase
5. Apply Punycode transformation (internationalized domains → ASCII)
6. Extract eTLD+1 using Public Suffix List
7. Validate against RFC 1035/1123 domain syntax

Return resulting string, or error if any step fails.

Examples:

- canonicalize("https://www.example.com:443/path") = "example.com"
- canonicalize("api.staging.example.co.uk") = "example.co.uk"
- canonicalize("MÜNCHEN.DE") = "xn--mnchen-3ya.de"

Implementation Requirement.

Implementations MUST use the Public Suffix List (<https://publicsuffix.org/>)
updated at least quarterly to correctly identify eTLD boundaries.

Special Cases:

IP addresses (IPv4, IPv6) and localhost are rejected (return ⊥).

## 6. Protocol Specification

### 6.1 Credential Issuance

**Issuer generates:**

- `revocation_id <- {0,1}` (cryptographically random, 32 bytes)
- CRL identifier `CRL_ID`
- Issuer signature over credential
- Secure storage: `credential_id -> (revocation_id, CRL_ID)`

Issuer transmits to holder:

- Credential document (WITHOUT `revocation_id`)
- Issuer signature
- `revocation_id` (via secure out-of-band channel)

### 6.2 Credential Presentation

Input: Presentation request from verifier containing:

- `verifier_domain` (raw domain string)
- `challenge` (nonce for replay protection)
- Requested credential types and constraints

Holder computes:

1. `canonical_domain <- canonicalize(verifier_domain)`
2. `domain_rev_id <- H(revocation_id || canonical_domain)`
3. Generate ZKP with public inputs:
   - `domain = canonical_domain`
   - `domain_rev_id`
   - `CRL_ID`
   - `challenge`
4. Prove in zero-knowledge:
   - Knowledge of `revocation_id` such that `H(revocation_id || domain) = domain_rev_id`
   - Valid issuer signature over credential
   - Credential satisfies requested constraints

Holder transmits: `(zkp, domain_rev_id, listIndex, challenge, disclosed_claims)`

### 6.3 Presentation Verification

Verifier validates:

1. Domain binding:

```bash
canonical_own_domain <- canonicalize(own_domain)
ASSERT proof.domain = canonical_own_domain
```

CRITICAL: This check MUST NOT be skipped.

2. Challenge freshness: `ASSERT proof.challenge = expected_challenge`
3. Zero-knowledge proof: `ASSERT zkp_verify(proof) = true`
4. Credential status: Query CRL and check status:

 ```bash
 FOR each status ∈ {"valid", "suspended", "revoked"}:
     status_hash ← H(domain_rev_id || status)
     IF status_hash ∈ CRL.entries[status]:
         RETURN status
 
 IF not found: REJECT ("credential not in CRL")
   ```

5. Policy decision:

- `status = "valid"` -> ACCEPT
- `status = "suspended"` -> ACCEPT or REJECT (policy-dependent)
- `status = "revoked"` -> REJECT

### 6.4 CRL Format

```json
{
  "id": "batch-2025-01",
  "issuer": "did:example:issuer",
  "domain": "example.com",
  "generated": "2025-12-26T10:30:00Z",
  "nextUpdate": "2025-12-26T11:30:00Z",
  "entries": ["a1b2c3...", "d4e5f6...", ...]
}
```

Entry computation: Each entry is `H(revocation_id || domain || status)` in hexadecimal.

Padding requirement: Each status array MUST contain ≥1000 entries (pad
with random values if needed) to prevent size-based correlation attacks.

**Query API:** `GET /crl/{listIndex}?domain={domain}` returns signed CRL document.

**Verifier caching:** Verifiers SHOULD cache CRLs until `nextUpdate` timestamp.

### 6.5 Status Updates

**To revoke credential with `credential_id`:**

1. Lookup: `revocation_id <- storage[credential_id]`
2. For each domain `d` that has queried this `listIndex`:
   - Remove `H(revocation_id || d || "valid")` from `CRL[d].entries.valid`
   - Add `H(revocation_id || d || "revoked")` to `CRL[d].entries.revoked`
3. Sign and publish updated CRLs

Note: Holder cooperation not required; verifiers detect revocation on next CRL query.

## 7. Extension - time-dependent revocation id

```go
// Circuit outputs (public)
domain_rev_id = H(revocation_id || domain)

t_i = floor((t-now) / duration)

// Verifier computes (off-circuit)
valid_hash(t_i) = H(domain_rev_id || t_i || "valid")
suspended_hash(t_i) = H(domain_rev_id || t_i || "suspended")
revoked_hash(t_i) = H(domain_rev_id || t_i || "revoked")

// CRL contains only one of these hashes
// Verifier checks which one is present to determine status
```

This way verifier cannot monitor the status updates of other entries.
