# PII linkability, pseudonymity, and anonymity

Zero Knowledge Proof frameworks allows us to support various use cases, when it
comes to (un)linkability.

## Full linkability

Information shared by a holder with all the verifiers is the same (from the same
VC).

## User-Info linkability

User-Info linkability refers to preventing linking via identifiers, information that
can be observed outside the User Info in the VC or as part of its cryptographic
envelope.

- Metadata such as serial numbers, issuer-assigned IDs, credential public keys,
or any stable cryptographic material must not be unique in a way that lets
verifiers correlate different presentations.
- If metadata is stable across uses, different verifiers can trivially link
presentations even without opening the VC.
- Proper unlinkability requires metadata to be randomized, rotated, or hidden
(e.g., via ZKP).

Goal: Prevent metadata-based tracking while ensuring full legal and regulatory
compliance and proofs.

## Pseudonymity

Pseudonymity allows a verifier to recognize a returning user without learning
their real-world identity.

- The verifier learns only a pseudonymous identifier, not the holder’s true
identity.
- Pseudonyms can be scoped per verifier (recommended) or used globally across
verifiers (not recommended, as it creates correlation surfaces).
- With per-verifier pseudonyms, each service can maintain continuity (e.g.,
account-like interactions) while still preserving user privacy.  Users may
generate unlimited pseudonyms; verifiers cannot detect whether two pseudonyms
belong to the same individual.

Goal: Enable ongoing user–service relationships without exposing real identity
or enabling cross-service tracking.

## Anonymity

Anonymity ensures that a verifier cannot distinguish one user from another, not
only in terms of real identity, but also in terms of repeat interactions.

- The verifier cannot determine whether two service accesses originate from the same or different holders.
- No persistent identifier (pseudonymous or otherwise) is shared with the verifier.
- No long-term relationship between user and service is created by default.

In practice, full anonymity can be weakened by network-level and device-level
identifiers (e.g., IP addresses, browser fingerprints, cookies, behavioural
patterns). These must be mitigated separately through additional privacy
technologies.

Goal: Make each interaction indistinguishable from all others, eliminating any
linkability or ongoing user profiling.