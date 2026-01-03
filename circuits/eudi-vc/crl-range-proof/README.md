# CRL with a range proof

This is a simple simulation of revocation introduced by ZK Longfellow
<https://github.com/google/longfellow-zk/blob/main/lib/circuits/mdoc/mdoc_revocation.h>.
We are showcasing an implementation using CRLs with two entries, where we prove
that the certificate serial number lies between the two serial numbers in the
CRL.

TODO: refactor and improve performance.
