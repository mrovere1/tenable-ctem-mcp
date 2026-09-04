# Security policy

## Reporting a vulnerability

Report privately through **GitHub Security Advisories** on this repository
(*Security* › *Report a vulnerability*), not through a public issue.

Please include what an attacker would gain, the steps to reproduce, and the version or commit. A
first response should be expected within a few business days.

This is community and partner tooling with no promised SLA. If the issue turns out to be in the
Tenable platform rather than in this project, it should be reported to Tenable through their own
channels — this repository is not a route to Tenable Support.

## What this project does with credentials

Read this before reporting, because it is the answer to most questions.

- **API keys are read only from the environment**, from `TIO_ACCESS_KEY` and `TIO_SECRET_KEY`. No
  tool accepts a key as a parameter, no key is written to a configuration file, and no key is
  written to a log.
- **The key is used in exactly one place**: the `X-ApiKeys` header of the outgoing request. It is
  never included in an error message, a diagnostic output or an exception.
- **`ctem_diagnostics` never prints the key**, nor any part of it. It reports whether credentials
  are present and whether the connection works.
- **Certificate verification cannot be disabled.** There is no flag, and there should not be:
  without verification the tenant's API keys travel over a channel that may be being read. On a
  network that inspects TLS, `TIO_CA_BUNDLE` points at the corporate bundle and verification stays
  on.
- **The server is read-only.** It issues no write to the tenant.

## What is in this repository, and what is not

- The test fixtures are recorded responses from a laboratory tenant, sanitised structurally — by
  key, not by value shape. `tests/test_fixture_safety.py` fails the build if any fixture contains
  something shaped like a credential, an IP outside the RFC 5737 documentation ranges, a hostname or
  a long opaque identifier. It carries a guard test proving its own patterns catch the two cases
  that once escaped a regex-based pass.
- No customer data, no production tenant data, and no vendor API specification is redistributed
  here.

If you find any of the above to be untrue in a released commit, that is itself the vulnerability and
is worth reporting.
