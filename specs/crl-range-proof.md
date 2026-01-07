# Mini CRL - CRL Range Proof Format Specification

Version: draft

## Overview

A minimal CRL format profile for zero-knowledge revocation proofs based on the
[Longfellow-ZK
revocation](https://github.com/google/longfellow-zk/blob/main/lib/circuits/mdoc/mdoc_revocation.h).
Each CRL contains exactly two consecutive entries from a sorted revocation list,
enabling efficient range-based non-revocation proofs.

## Concept

Issuer maintains: Sorted list of all revoked serials `L = {s_1, s_2, ..., s_N}`

Non-revoked certificate: Has serial `S` where `s_i < S < s_{i+1}` for some `i`

Proof method: Holder proves `s_i < S < s_{i+1}` using a minimal CRL containing
only entries `s_i` and `s_{i+1}`

Note: format presented in
[Longfellow-ZK
revocation](https://github.com/google/longfellow-zk/blob/main/lib/circuits/mdoc/mdoc_revocation.h) results with a smaller number of ZK constraints.

## CRL Format

### Structure

Standard X.509v2 CRL (RFC 5280) with exactly **two entries** in `revokedCertificates`:

```asn1
CertificateList ::= SEQUENCE {
    tbsCertList          TBSCertList,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}

TBSCertList ::= SEQUENCE {
    version                 INTEGER OPTIONAL,
    signature               AlgorithmIdentifier,
    issuer                  Name,
    thisUpdate              Time,
    nextUpdate              Time OPTIONAL,
    revokedCertificates     SEQUENCE OF SEQUENCE {
        userCertificate     INTEGER,  -- s_i
        revocationDate      Time
    },
    SEQUENCE {
        userCertificate     INTEGER,  -- s_{i+1}
        revocationDate      Time
    }
}
```

### Requirements

- Entry count: Exactly 2 entries
- Ordering: First entry serial < second entry serial
- Boundaries:
  - If `S < s_1`: Use `(0, s_1)` or `(MIN_SERIAL, s_1)`
  - If `S > s_N`: Use `(s_N, MAX_SERIAL)`
- DER encoding: Standard X.509 DER format
- Size: Approximately 200-500 bytes

### Serial Number Format

- Type: DER INTEGER (tag 0x02)
- Length: Variable (typically 8-20 bytes)
- Comparison: Lexicographic byte order (must be padded accordingly)
- Circuit parameter: `maxSerialLen` defines fixed comparison width
