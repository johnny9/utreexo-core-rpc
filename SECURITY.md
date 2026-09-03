# Security policy

This project is beta software that handles untrusted network and checkpoint
input. Do not treat it as an independent Bitcoin consensus implementation;
Bitcoin Core remains the consensus and active-chain authority.

## Supported versions

Security fixes are made on the current `master` branch and the newest tagged
beta release. Older snapshots are unsupported.

## Reporting a vulnerability

Please use the repository's private **Report a vulnerability** security-advisory
form. If private advisories are unavailable, contact a maintainer privately
through the repository owner's established contact channel before publishing
details. Include the affected revision, configuration, reproduction steps, and
impact. Do not attach private keys, RPC credentials, cookies, or production
checkpoint data.

Allow maintainers time to reproduce and coordinate a fix before disclosure.
Ordinary bugs that do not have a confidentiality, integrity, or availability
impact can use the public issue tracker.
