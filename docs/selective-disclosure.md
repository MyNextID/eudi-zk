# Redaction, selective disclosure, and multi-credential presentation

## Redaction

Redaction means presenting a verifiable credential with some information
concealed from the verifier while preserving the cryptographic integrity of the
disclosed portions. The verifier can verify that the redacted credential was
validly issued, but cannot access or infer the hidden information.

## Selective Disclosure

Selective disclosure means that the holder reveals only a chosen subset of
claims from a credential, typically in response to a verifier's request, while
keeping all other claims hidden. In the strongest form, all claims begin in a
hidden state, and the holder explicitly chooses which to disclose—no claim is
revealed by default.

Unlike simple redaction, selective disclosure is designed as the primary
interaction model: the credential structure anticipates granular disclosure
decisions at presentation time rather than assuming full revelation as the
default case.

## Multi-Credential Presentation

Multi-credential presentation means combining claims from two or more distinct
verifiable credentials into a single presentation protocol. The holder may
selectively disclose different claims from each credential, creating a composite
proof that draws on multiple issued credentials while maintaining cryptographic
verifiability of each component.

Example: A holder might combine an age claim from a government-issued identity
credential with a professional certification claim from a university credential,
presenting both to a verifier in a single interaction without revealing other
attributes from either credential.

## Linkability Properties of Redaction and Selective Disclosure

Redaction and selective disclosure do not provide any unlinkability by default.
The ability to hide information does not, by itself, prevent verifiers from
correlating presentations.

The most widespread selective disclosure mechanisms such as salt-hash table
approaches used in mDocs, SD-JWT, and similar formats—exhibit metadata
linkability even when claims are selectively disclosed. Each credential
typically contains stable metadata elements: a unique credential identifier,
issuance timestamp, issuer signature, and the hash table structure itself. When
a holder presents the same credential multiple times (even with different claim
subsets disclosed), colluding verifiers can correlate these presentations by
comparing the invariant metadata.

In these cases, additional mitigation strategies must be implemented:

- **One-time-use credentials:** The issuer provides fresh credentials for each
presentation, eliminating stable metadata as a correlation vector. This approach
trades increased issuance overhead for stronger unlinkability guarantees. Note
that the unlikability heavily relies on correct implementation of the issuer and
the wallet.

- **Cryptographic unlinkability:** Advanced schemes such as CL signatures or
BBS+ signatures generate cryptographically unlinkable presentations. In this
case, however, issuers must support the given cryptographic suite.

Without such measures, selective disclosure provides granular control over which
claims are revealed, but not unlinkability across presentations.

## Zero-Knowledge Circuit-Based Systems

Zero-knowledge circuit-based systems offer a more flexible and powerful
alternative. Unlike salt-hash approaches that bake linkability properties into
the credential format at issuance, ZK circuits decouple the linkability
guarantees from the issuance process itself. The issuer need not anticipate
every privacy requirement or coordinate with wallet implementations—the same
credential, issued once in a canonical form, can be presented with different
linkability properties depending on the holder's needs and the verifier's
requirements.

A single credential issued via a ZK system enables the holder to generate:

- **Fully unlinkable presentations** that reveal only non-unique predicates
(e.g., "over 18 years of age"), placing the holder within a large anonymity set;
- **Metadata-unlinkable presentations** for regulated contexts where subject
information linkability is legally required but metadata-based tracking must be
prevented;
- **Fully linkable presentations** that expose both metadata and subject
information when accountability demands outweigh privacy considerations.

This adaptability emerges from the mathematical properties of zero-knowledge
proofs: the holder proves possession of a validly signed credential and
satisfaction of arbitrary predicates*without revealing the credential itself.
Each presentation constitutes a fresh cryptographic proof, unlinkable to other
presentations unless the holder deliberately includes correlating information.
The holder retains fine-grained control over the privacy-utility trade-off at
presentation time, not at issuance time—a fundamental architectural advantage
for systems spanning diverse regulatory and trust contexts.
