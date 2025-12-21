# PII linkability, pseudonymity, and anonymity

Zero-knowledge proofs find their most widespread application in contexts
requiring unlinkability and selective disclosure. The ETSI TR 119 476 standard
establishes two fundamental definitions:

- **Verifier unlinkability** ensures that one or more verifiers cannot collude
to determine whether selectively disclosed attributes describe the same identity
subject.

- **Full unlinkability** provides a stronger guarantee: no party whatsoever can
*collude to determine whether selectively disclosed attributes describe the same
*identity subject.

We introduce additional precision by distinguishing between two categories of
information within verifiable credentials:

- **Metadata** encompasses all information the verifiable credential contains that
does not express claims about the subject, e.g., the credential number,
digital signature, signer information, and revocation index.
- **Subject information** comprises all information the verifiable credential
asserts about the subject.

## Fully linkable presentations

A credential exhibits full linkability when colluding parties can determine
either from the credential metadata or from the subject information that two or
more credential presentations refer to the same identity subject.

Examples:

- The holder presents the identical verifiable credential to multiple verifiers.
Any metadata element (credential identifier, issuance timestamp, signature)
enables the verifiers to recognize they have received the same credential.
- The holder presents distinct verifiable credentials, each cryptographically
bound to the same public key, to different verifiers. The shared public key
serves as a stable correlating identifier across presentations.
- The holder presents credentials containing unique but correlatable subject
attributes—such as a government-issued identification number, biometric hash, or
other persistent identifier—allowing verifiers to link presentations even when
the credentials themselves differ.

## Subject information linkable presentations

A credential exhibits subject information linkability when colluding parties can
determine from the subject information, but not from the metadata, that two or
more credential presentations refer to the same identity subject.

Goal: Prevent metadata-based tracking while preserving the ability to
demonstrate legal and regulatory compliance through verifiable subject
attributes.

Example:

- A holder presents two distinct credentials to different verifiers. Although
the credentials have different metadata (unique credential identifiers,
different issuance dates, separate signatures, or ZK proofs), both contain the
holder's national identification number. The verifiers can collude to determine
that both presentations refer to the same person by comparing this persistent
subject attribute, even though the metadata provides no such correlation.

Contrast with full linkability: Here, the metadata alone reveals nothing about
common identity only the disclosed subject information enables linkage. This
represents a deliberate privacy-utility trade-off: metadata unlinkability
protects against casual tracking, while subject information linkability
satisfies legitimate requirements for identity verification and accountability.

## Fully unlinkable presentations

Full unlinkability can be achieved only when the disclosed subject information
is non-unique to the holder—for example, "over 18 years of age" or "resident of
the European Union." Such attributes place the holder within a large anonymity
set, preventing verifiers from distinguishing one holder from another based on
the disclosed information alone. If any claim can uniquely identify the subject,
only metadata unlikable presentations are possible.

## Pseudonymity

Pseudonymity allows a verifier to recognize a returning holder without learning
their real-world identity. The verifier learns only a pseudonymous identifier,
not the holder's legal name, government-issued identification number, or other
true identity attributes.

Pseudonyms may be scoped per verifier (recommended) or shared globally across
verifiers (not recommended, as global pseudonyms create correlation surfaces
that enable tracking). With per-verifier pseudonyms, each service can maintain
continuity—enabling account-like interactions, preference storage, or reputation
accumulation—while preserving holder privacy across services. Holders may
generate unlimited pseudonyms; verifiers cannot determine whether two distinct
pseudonyms belong to the same individual.

Goal: Enable ongoing holder–service relationships without exposing real
identity or enabling cross-service tracking.

## Anonymity

Anonymity provides a stronger privacy guarantee than pseudonymity: a verifier
cannot distinguish one holder from another, neither in terms of real identity
nor in terms of repeat interactions.

The verifier cannot determine whether two service accesses originate from the
same holder or from different holders. No persistent identifier (pseudonymous or
otherwise) is shared with the verifier, and no long-term relationship between
holder and service is established by default. Each interaction stands
independent of all others.

In practice, full anonymity at the credential layer can be undermined by
network-level and device-level identifiers: IP addresses, browser fingerprints,
tracking cookies, session tokens, and behavioural patterns. These must be
mitigated separately through additional privacy-enhancing technologies such as
onion routing, browser isolation, or randomized timing patterns.

Goal: Make each interaction computationally indistinguishable from all
others, eliminating any basis for linkability or longitudinal profiling.
