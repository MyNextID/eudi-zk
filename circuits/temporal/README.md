# Temporal validation Circuits

Version: draft

## What We Prove

These circuits prove temporal validity of X.509 certificates or credentials.

## Use Cases

### Over XX

The Over18 Circuit serves a specific verification purpose: to establish that a
person's date of birth, as attested in the birthdate claim of a JWS payload,
indicates sufficient age according to a threshold date specified by the
verifier.

The verification mechanism itself is remarkably simple, relying on
lexicographical comparison. This approach works because the date format
has been carefully chosen, specifically, YYYY-MM-DD (ISO 8601), which possesses a
crucial property: for any two dates d1 and d2, we have d1 < d2 chronologically
if and only if d1 < d2 lexicographically when both are represented as strings in
this format. The year-first ordering ensures that string comparison naturally
mirrors temporal ordering.

The verifier establishes a minimal date of birth d_min; the circuit then checks
whether the claimant's birthdate d_claim satisfies d_claim < d_min, which
confirms that the claimant was born before the threshold date and is therefore
of sufficient age.

It is worth noting that this comparison technique generalizes naturally: any
claim values that can be represented in a lexicographically-ordered format may
be compared using this same fundamental mechanism, making the approach broadly
applicable beyond age verification alone.

## Date and time formats

The following date and date-time formats appear in different credentials or certificates:

- ISO 8601: `YYYY-DD-MM`
- UTC Time: `YYMMDDHHMMSSZ` (not applicable)
- GeneralizedTime: `YYYYMMDDHHMMSSZ`
- Unix Timestamp: seconds elapsed since the Unix epoch (January 1, 1970, 00:00:00 UTC); See paragraph [Unix Timestamp](#unix-timestamp)

### Application to X.509 Certificates

One might naturally wonder whether this lexicographical comparison technique
extends to the date-time formats found in X.509 certificates, which employ two
distinct ASN.1 time representations: UTCTime (format `YYMMDDHHMMSSZ`) for dates
through 2049, and GeneralizedTime (format `YYYYMMDDHHMMSSZ`) for dates in 2050
and beyond.

The answer reveals both the power and the limitations of our approach.
**Importantly, UTCTime does not support lexicographical comparison even within
its own format**, due to its year encoding scheme: the two-digit year YY is
interpreted with a pivot rule (50-99 represents 1950-1999, while 00-49
represents 2000-2049), which means "50" (1950) follows "49" (2049)
lexicographically despite representing an earlier date. This non-monotonic
encoding breaks the fundamental requirement for lexicographical comparison.

If one wishes to perform lexicographical comparison of date-times in UTCTime format, the correct century prefix must be added first—transforming "49..." to "2049..." and "50..." to "1950..." thereby converting the representation to an equivalent GeneralizedTime-like format before comparison.

GeneralizedTime, however, works admirably—GeneralizedTime strings compare
correctly with other GeneralizedTime strings, since this format maintains the
crucial property that lexicographical ordering mirrors chronological ordering
(its four-digit year eliminates the pivot ambiguity).

A critical constraint remains: when using this technique with GeneralizedTime,
the reference date d_min must be expressed in the same format as the claim being
verified. One cannot meaningfully compare a UTCTime string against a
GeneralizedTime string lexicographically, as they differ in length and
structure—indeed, the string "491231235959Z" (December 31, 2049) would
incorrectly appear greater than "20500101000000Z" (January 1, 2050) under
lexicographical comparison, despite representing an earlier moment in time.

Thus, when applying this technique to X.509 validity periods, lexicographical
comparison is only viable for GeneralizedTime values, and the verifier must
ensure the reference threshold is also encoded in GeneralizedTime format.

Note: extension for UTCTime representation has not been implemented.

### Unix Timestamp

An alternative representation that merits consideration is the Unix timestamp:
the number of seconds elapsed since the Unix epoch (January 1, 1970, 00:00:00
UTC). This representation offers a compelling advantage—temporal comparison
reduces to simple numeric comparison of integers. If a claim t_claim and
reference threshold t_min are both expressed as Unix timestamps, then the
verification condition t_claim < t_min is evaluated directly in the arithmetic
domain, without any need for string manipulation or format parsing.

However—and this is a subtle but important point—when Unix timestamps are
transmitted as strings (as they often are in JSON Web Tokens and similar
formats), lexicographical comparison becomes problematic. Consider: the
timestamp "999999999" (September 9, 2001) and "1000000000" (September 9, 2001,
one second later) do not compare correctly lexicographically, since the
former has 9 digits while the latter has 10, and lexicographically "999999999" >
"1000000000". The remedy is straightforward: one must either (1) parse the
strings into integers before comparison, thereby returning to proper numeric
ordering, or (2) normalize the string representation by padding with leading
zeros to a fixed width, say "0999999999" and "1000000000", which does preserve
lexicographical ordering.

The Unix timestamp thus illustrates a general principle: the applicability of
lexicographical comparison depends not merely on the semantics of the data
format, but critically on its syntactic representation as a string.

Note: extension for UnixTimestamp representation has not been implemented.

## Circuit Profiles

### Verifiable Credentials signed as JWS

Digital signature format: JWS

Private inputs:

- Base64URL encoded protected header
- Base64URL encoded payload
- TODO: list other endpoints here

Public inputs:

- Credential type (vct)
- Name of the ephemeral claim
- Date and time of validity check

## Credential Profiles

- JAdES-B-B signed (JWT) where we only include the `kid`
  - eIDAS minimum dataset
  - PID dataset
- cnf:kid is in the protected header

Presentation: using KB-JWT
