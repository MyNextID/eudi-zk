# Mini CRL - CRL Range Proof

We introduce an implementation of the revocation method proposed by [Longfellow
ZK](https://github.com/google/longfellow-zk/blob/main/lib/circuits/mdoc/mdoc_revocation.h),
extending it to support the established [Certificate Revocation List (CRL)
format](https://en.wikipedia.org/wiki/Certificate_revocation_list).

In summary, the issuer sorts all the revocation identifiers. Each CRL contains
exactly two revocation entries, denoted as `S_i` and `S_{i+1}`, where `S_i <
S_{i+1}`. Within the ZK circuit, we prove that the revocation identifier of the
credential lies strictly between these two entries, thereby establishing that
the credential has not been revoked.

## Circuit design

The circuit focuses on two main operations:

- extract the certificate serial number
- prove that the serial number is in the range between the two CRL entries

Signature verification and cross-matching the issuer identity (of the credential
and the revocation list) are out of scope of this circuit.

The circuit can be extended to support (almost) any credential and signature format.
