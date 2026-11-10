# Security policy

## Supported versions

Vail is pre-1.0. Security fixes are applied to the current `main` branch and the
latest tagged release.

## Reporting a vulnerability

Please use GitHub's private security advisory feature on the repository rather
than opening a public issue. Include:

- a description of the issue and its impact;
- the affected commit or version;
- a minimal reproducer or test case;
- any relevant platform, compiler, or target details.

Do not include exploit code for unrelated systems or real credentials.

## Scope

Security-relevant areas include:

- TLS/QUIC handshake and record processing;
- X.509 path building, policy, CRL, and OCSP verification;
- signature verification and key parsing;
- AEAD, hash, MAC, KDF, and key-exchange implementations;
- secret handling, zeroization, and constant-time behavior;
- embedded third-party assembly and generated tables.

## Response

The maintainers will acknowledge a report, investigate it, and coordinate a fix
and disclosure timeline. Please allow time for a fix before public disclosure.

## Not a bug bounty program

This repository does not currently advertise a bug bounty. Do not assume a
reward or safe-harbor policy beyond what is explicitly stated by the project
owner.
