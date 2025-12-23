# Temporal validation Circuits

Version: draft

## What We Prove

These circuits prove temporal validity of X.509 certificates or credentials.

We begin with: Over18 use case - comparing YYYY-MM-DD dates

## Date and time formats

## Summary of the public and private inputs

Private inputs:

- Subject's verifiable credential

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
