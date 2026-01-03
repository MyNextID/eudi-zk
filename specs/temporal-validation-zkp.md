# Extending e-signature validity proof beyond the time of signature creation

## Challenge

Within Zero Knowledge Proofs (ZKPs) we usually prove validity of information at
the time of proof creation. In the digital signatures world, however, we must
prove validity of a signature at the time of signature creation. Additionally,
according to Article 34 of eIDAS, we need mechanisms to extend the
trustworthiness of signatures/seals beyond their original technological validity
period.

The challenge arises because traditional preservation services (as per eIDAS
Article 34) use techniques like re-timestamping and archival formats that can be
applied iteratively over time to extend trustworthiness. However, once ZKPs are
created, they are immutable and cannot be modified or extended with new
timestamps. Therefore, we need to build long-term validity proof capabilities
into the ZKP at creation time.

## Solution

Instead of proving a VC/signature is valid at a single point in time "t", we
prove the VC/signature is valid within a time window \[t_min, t_max\]. This
approach satisfies both:

- Article 32 requirement: Proves the certificate was valid at the time of
signing (t_signing must fall within \[t_min, t_max\])
- Article 34 requirement: Extends the trustworthiness by enabling validation
beyond the signature creation time, as long as verification happens within \[t_min,
t_max\]

`t_max` should be the the time of shortes living elment within the e-signature
validation that happens within the Zero Knowledge Proofs.

## Summary of relevant eIDAS regulation articles

[Article 32 of eIDAS](https://eur-lex.europa.eu/eli/reg/2014/910/oj/eng)
specifies that the validation process shall confirm the validity of a qualified
electronic signature provided that the certificate that supports the signature
was, at **the time of signing**, a qualified certificate complying with Annex I,
and the qualified certificate was issued by a qualified trust service provider
and was valid at the time of signing European Commission.

[Article 34 of eIDAS](https://eur-lex.europa.eu/eli/reg/2014/910/oj/eng) addresses
qualified preservation service for qualified electronic signatures, requiring
qualified trust service providers to **use procedures and technologies capable
of extending the trustworthiness** of the qualified electronic signature beyond
the technological validity period.

[Article 40 of eIDAS](https://eur-lex.europa.eu/eli/reg/2014/910/oj/eng) applies these preservation requirements mutatis mutandis to
qualified electronic seals.

