# Domain-Bound Credential Revocation List (DB-CRL) <!-- omit in toc -->

Version: draft

Implementation: WIP

## Table of Contents <!-- omit in toc -->

- [1. Overview](#1-overview)
  - [1.1. The Revocation Problem in Zero-Knowledge Systems](#11-the-revocation-problem-in-zero-knowledge-systems)
  - [1.2. Our Approach: Domain-Bound Revocation Identifiers](#12-our-approach-domain-bound-revocation-identifiers)
  - [1.3. Document Scope](#13-document-scope)
- [2. Introduction](#2-introduction)
  - [2.1. Purpose](#21-purpose)
  - [2.2. Goals](#22-goals)
  - [2.3. Non-Goals](#23-non-goals)
  - [2.4. Threat Model](#24-threat-model)
    - [2.4.1. Trusted Entities](#241-trusted-entities)
    - [2.4.2. Untrusted Entities](#242-untrusted-entities)
    - [2.4.3. Out of Scope](#243-out-of-scope)
- [3. Terminology](#3-terminology)
  - [3.1. Definitions](#31-definitions)
  - [3.2. Notation](#32-notation)
- [4. System Overview](#4-system-overview)
  - [4.1. Architecture](#41-architecture)
  - [4.2. Workflow Overview](#42-workflow-overview)
- [5. Cryptographic Primitive](#5-cryptographic-primitive)
  - [5.1. Hash Function](#51-hash-function)
  - [5.2. Domain-Bound Revocation ID Computation](#52-domain-bound-revocation-id-computation)
  - [5.3. Random Value Generation](#53-random-value-generation)
- [6. Domain Canonicalization](#6-domain-canonicalization)
- [7. Protocol Specification](#7-protocol-specification)
  - [7.1. Credential Issuance](#71-credential-issuance)
  - [7.2. Credential Presentation](#72-credential-presentation)
  - [7.3. Presentation Verification](#73-presentation-verification)
  - [7.4. CRL Format](#74-crl-format)
  - [7.5. Status Updates](#75-status-updates)
- [8. Extension - Time-dependent revocation id](#8-extension---time-dependent-revocation-id)

## 1. Overview

### 1.1. The Revocation Problem in Zero-Knowledge Systems

Traditional credential revocation mechanisms publish a list mapping credential
identifiers to their status (valid, suspended, revoked). While effective, this
approach is incompatible with zero-knowledge systems where (metadata)
unlinkability is essential: different verifiers must not be able to correlate
presentations of the same credential by comparing identifiers.

Existing ZK-compatible solutions either:

1. Include entire revocation lists as circuit inputs (inefficient, scales poorly)
2. Prove non-membership using cryptographic accumulators (requires holder to update witness data)
3. Sacrifice verifier independence (require holder cooperation for status checks)

### 1.2. Our Approach: Domain-Bound Revocation Identifiers

We introduce Domain-Bound Certificate Revocation Lists (DB-CRL), which enables:

- Unlinkability: Each verifier sees a different revocation identifier
- Verifier Independence: Status checks require no holder cooperation  
- Efficiency: Small revocation lists, simple lookups
- Temporal Validity: Proofs remain valid; verifiers check current status independently at any point in time

Core Mechanism:

Each credential contains a secret `revocation_id`. When presenting to a verifier
with domain `d`, the holder computes:

```bash
domain_rev_id = SHA256(revocation_id || d)
```

The holder proves in zero-knowledge:

1. Knowledge of `revocation_id` matching the credential
2. Correct computation of `domain_rev_id` for domain `d`
3. Credential satisfies requested validation policies

The verifier:

1. Validates the ZK proof
2. Queries the issuer's CRL endpoint for domain `d`
3. Checks if `domain_rev_id ∈ CRL.revoked`
4. Accepts if not revoked; rejects otherwise

Key Properties:

- Different domains -> different identifiers: `SHA256(revocation_id || "verifier-a.com") != SHA256(revocation_id || "verifier-b.com")`
- Verifiers cannot correlate: Even colluding verifiers cannot determine if two `domain_rev_id` values derive from the same credential
- Issuer generates domain-specific CRLs: When queried, issuer computes `SHA256(revocation_id || requesting_domain)` for each revoked credential
- Small CRLs: Only revoked credentials listed (approx. 1% of issued credentials)
- No holder involvement in status checks: Verifier queries CRL directly; proof remains valid regardless of status changes
- Verifier can check the status at any point in time

Limitation: When a single credential is newly revoked, timing analysis could enable
correlation. Mitigation: batch revocations or pad lists to minimum size.

### 1.3. Document Scope

This specification defines:

- Cryptographic primitives for domain-bound identifier computation
- Domain canonicalization to prevent validation errors
- Complete issuance, presentation, and verification protocols
- CRL format, generation, and distribution
- Zero-knowledge circuit requirements

Out of Scope: Temporal validity proofs enabling verification of credential
validity at specific past or future timestamps. See separate specification:
[Temporal Validation within ZKPs](./temporal-validation-zkp.md).

## 2. Introduction

### 2.1. Purpose

This specification defines the Domain-Bound Credential Revocation List (DB-CRL)
system, which enables credential status verification in zero-knowledge proof
systems while maintaining unlinkability across different verifiers.

### 2.2. Goals

- Verifier Unlinkability: Prevent different verifiers from correlating credentials by comparing revocation identifiers
- Independent Verification: Enable verifiers to check credential status without holder cooperation
- Privacy-Preserving: Minimize information leakage about credential usage patterns
- Practical: Maintain reasonable computational and operational costs

### 2.3. Non-Goals

- Holder Anonymity from Issuer: The issuer is expected to know which credentials are issued to which holders
- Complete Verifier Anonymity: The issuer may observe which verifiers query which CRL lists, but they don't learn for which Verifiable Credential

### 2.4. Threat Model

#### 2.4.1. Trusted Entities

- Issuers: Trusted to generate valid credentials and maintain accurate CRLs
- Cryptographic Primitives: Hash functions and ZKP systems operate as specified

#### 2.4.2. Untrusted Entities

- Holders: May attempt to present revoked credentials or manipulate domain bindings
- Verifiers (individually): Assumed honest but may be curious
- Colluding Verifiers: May attempt to correlate credentials across domains

#### 2.4.3. Out of Scope

- Compromise of cryptographic primitives
- Issuer misbehaviour or collusion with holders

## 3. Terminology

### 3.1. Definitions

- Revocation Identifier (revocation_id): A secret, randomly generated value
assigned to a credential at issuance, used to compute domain-bound revocation
identifiers.
- Domain: A canonical string identifier for a verifier, typically derived from their DNS domain name.
- Domain-Bound Revocation Identifier (domain_rev_id): A public value computed as
`HASH(revocation_id || domain)`, used by verifiers to check credential
status.
- CRL List: A collection of credentials grouped together for revocation
management. Each credential belongs to exactly one CRL list.
- CRL List Identifier (list_index): An identifier for a CRL list (e.g., serial number, batch number).
- Status: The current state of a credential, one of: `valid`, `suspended`, `revoked`.

### 3.2. Notation

- `||`: Byte concatenation
- `H()`: Cryptographic hash function (defined in Section 4)
- `a == b`: Equality check
- `a ∈ S`: Membership check (a is in set S)
- `[a, b, c]`: Array/list of elements
- `{k: v}`: Key-value mapping

## 4. System Overview

### 4.1. Architecture

Issuer issues credentials and and manages the CRL. Verifier can obtain the CRL
directly from the issuer or via the holder's wallet. Verifier can verify the CRL
status at any time without holder's involvement.

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
          │ ┌───────────────┘    │
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

### 4.2. Workflow Overview

1. Issuance: Issuer generates credential with secret `revocation_id` and assigns `list_index`
2. Storage: Holder stores credential and associated cryptographic material
3. Presentation: Holder computes `domain_rev_id` for target verifier's domain
4. Proof Generation: Holder creates ZKP proving correct computation of `domain_rev_id`
5. Verification: Verifier validates proof and credential claims
6. Status Check: Verifier queries CRL for their domain to check credential status
7. Decision: Verifier accepts or rejects credential based on status

## 5. Cryptographic Primitive

### 5.1. Hash Function

Algorithm: SHA-256

Properties Required:

- Collision resistance
- Pre-image resistance

Implementation Notes:

- MUST use SHA-256 as defined in FIPS 180-4
- Revocation id size MUST be 32 bytes (256 bits)
- Input encoding MUST be UTF-8 for strings

### 5.2. Domain-Bound Revocation ID Computation

Domain-bound revocation id is computed as

```go
domain_rev_id := SHA256(revocation_id || domain)
```

Within the ZK circuit we prove that:

- the VC status can be checked at the given CRL ID
- for the domain `d`, `domain_rev_id` is computed correctly

ZK inputs are:

- public: domain `d`, `domain_rev_id`, `crl_id`
- private: domain `revocation_id`

The ZK circuit performs a simple membership check and the correctness of the
computation of the `domain_rev_id`.

Input Requirements:

- `revocation_id`: MUST be exactly 32 bytes
- `domain`: MUST be canonical ASCII domain (see Section [Domain Canonicalization](#6-domain-canonicalization))

Note: status can be extended with custom statues.

Security Properties:

- Given `domain_rev_id`, computationally infeasible to determine `revocation_id`
- Different domains produce statistically independent `domain_rev_id` values
- Cannot compute `domain_rev_id` for different status without `revocation_id`

### 5.3. Random Value Generation

- MUST use cryptographically secure random number generator
- MUST generate at least 256 bits of entropy
- MUST be unique per credential

## 6. Domain Canonicalization

Domain canonicalization ensures that different representations of the same
verifier domain produce identical `domain_rev_id` values, preventing validation
errors due to formatting differences.

A *canonical domain* is the effective top-level domain plus one label (eTLD+1),
represented in lowercase ASCII.

Canonicalization Function:

Let `canonicalize: String -> String` be defined as follows.
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

IP addresses (IPv4, IPv6) and localhost are rejected.

## 7. Protocol Specification

### 7.1. Credential Issuance

**Issuer generates:**

- `revocation_id <- {0,1}` (cryptographically random, 32 bytes)
- CRL identifier `crl_id`
- Issuer signature over credential
- Secure storage: `credential_id -> (revocation_id, crl_id)`

Issuer transmits to holder:

- Credential document (with `revocation_id, crl_id`)
- Issuer signature
- `revocation_id` (via the signature metadata)

### 7.2. Credential Presentation

Input: Presentation request from verifier containing:

- `verifier_domain` (raw domain string)
- `challenge` (nonce for replay protection)
- Requested credential types and validation policies

Holder computes:

1. `canonical_domain <- canonicalize(verifier_domain)`
2. `domain_rev_id <- HASH(revocation_id || canonical_domain)`
3. Generate ZKP with public inputs:
   - `domain = canonical_domain`
   - `domain_rev_id`
   - `CRL_ID`
   - `challenge`
4. Prove in zero-knowledge:
   - Knowledge of `revocation_id` such that `HASH(revocation_id || domain) = domain_rev_id`
   - Valid issuer signature over credential
   - Credential satisfies requested constraints

Holder transmits: `(zkp, domain_rev_id, crl_id, challenge, disclosed_claims)`

### 7.3. Presentation Verification

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
IF domain_rev_id ∈ CRL.entries:
    RETURN status
IF not found: OK ("credential is valid")
   ```

5. Policy decision:

- `status = "valid"` -> ACCEPT
- `status = "suspended"` -> ACCEPT or REJECT (policy-dependent)
- `status = "revoked"` -> REJECT

### 7.4. CRL Format

The model works with any CRL profile.

Query API proposal: `GET /crl/{crlId}?domain={domain}` returns signed CRL document.

Verifier caching: Verifiers SHOULD cache CRLs until `nextUpdate` timestamp.

### 7.5. Status Updates

CRLs are dynamically computed per request with well defined time of next update, hence CRL lists are re-computed every time when requested (caching mechanism can be implemented).

## 8. Extension - Time-dependent revocation id

The proposed model allows users to track the status of CRL entries. If required,
additional time component can be plugged in as follows:

```go
domain_rev_id = HASH(revocation_id || domain)

t_i = floor((t-now) / duration)

domain_rev_id(t_i) = HASH(domain_rev_id || t_i)

// or if we want to mask the status:
domain_rev_id(t_i) = HASH(domain_rev_id || status || t_i)
```

This way verifier cannot monitor the status updates of other entries.
