# Simple CAdES signer

A simple CAdES signer

Supported profiles:

- CAdES-BES embedded and detached
  - Enveloping signature - digital signature embedding the Signed Data Object
  - Detached signature - digital signature where the signed data is external, not in the SignedData structure

Standards:

- [ETSI TS 103 173 V2.2.1](https://www.etsi.org/deliver/etsi_ts/103100_103199/103173/02.02.01_60/ts_103173v020201p.pdf)
- [ETSI EN 319 122-1 V1.1.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.01.01_60/en_31912201v010101p.pdf)
- [ETSI EN 319 122-2 V1.1.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912202/01.01.01_60/en_31912202v010101p.pdf)

Enveloping signature passes the [ETSI CAdES Conformance](https://signatures-conformance-checker.etsi.org/checker/cades)
validation. Note: Detached signature validation is not supported.

## References

- [ETSI conformance](https://signatures-conformance-checker.etsi.org/)
- [ETSI TS 103 173 V2.2.1](https://www.etsi.org/deliver/etsi_ts/103100_103199/103173/02.02.01_60/ts_103173v020201p.pdf)
- [ETSI EN 319 122-1 V1.1.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.01.01_60/en_31912201v010101p.pdf)
- [ETSI EN 319 122-2 V1.1.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912202/01.01.01_60/en_31912202v010101p.pdf)
