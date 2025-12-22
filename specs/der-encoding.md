# Notes DER encoding

**DER** is a binary format for data structures described by ASN.1. DER is
*providing for exactly one way to encode an ASN.1 value. DER is intended
for situations when a unique encoding is needed, such as in cryptography, and
ensures that a data structure that needs to be digitally signed produces a
unique serialized representation.

**ASN.1** (Abstract Syntax Notation One) is a standard interface description
language (IDL) for defining data structures that can be serialized and
deserialized in a cross-platform way.

## DER and TVL

DER always follows a Tag, Length, Value (TLV) format. The format is usually
referred to as a TLV triplet in which each field (T, L, or V) contains one or
more bytes.

### Tags

Size: 1 byte

- 0x02 - INTEGER
- 0x03 - BIT STRING
- 0x04 - OCTET STRING
- 0x05 - NULL
- 0x06 - OBJECT IDENTIFIER (OID)
- 0x0C - UTF8String
- 0x13 - PrintableString
- 0x17 - UTCTime
- 0x18 - GeneralizedTime
- 0x30 - SEQUENCE (constructed)
- 0x31 - SET (constructed)
- 0xA0, 0xA1, 0xA3 - Context-specific tags (for optional fields)

### Length

The Length field in a TLV triplet identifies the number of bytes encoded in the
Value field. The bit 7 in the length field signals whether the value length is
less or equal to 127 or more:

- bit number 7 == 0: value of length <= 127
- bit number 7 == 1: value of length > 127

**Short form**: the remaining bits identify the number of bytes of content being
*sent.
Example: 0x05 = 5 bytes follow

**Long form**: the remaining bits identify the number of bytes needed to contain
*the length.

Examples:

- 0x81 0x85       = 133 bytes (1 length byte)
- 0x82 0x01 0xF4  = 500 bytes (2 length bytes)

## References

- [A Layman's Guide to a Subset of ASN.1, BER, and DER](https://luca.ntop.org/Teaching/Appunti/asn1.html)
- [A Warm Welcome to ASN.1 and DER](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)
