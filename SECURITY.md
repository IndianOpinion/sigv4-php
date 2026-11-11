# Security policy

sigv4-php signs AWS requests and handles AWS credentials, so we treat
security reports as the most urgent thing in the queue.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Email **hello@indianopinion.org** with "sigv4-php security" in the subject.
Please do not open a public issue for a vulnerability.

Include what you can:

- the version, PHP version and environment (EC2, ECS, EKS, other);
- what an attacker can do, and the steps to reproduce it;
- a proof of concept if you have one. Never send real AWS credentials:
  use the `AKIDEXAMPLE` keys from the AWS test suite.

## What happens next

- We acknowledge your report within **3 working days**.
- We send a first assessment (accepted, need more information, or not a
  vulnerability, with reasons) within **10 working days**.
- For an accepted report we aim to ship a fix within **30 days**, sooner
  for anything that can leak credentials. We agree a disclosure date with
  you and credit you in the release notes unless you ask us not to.

## In scope

Anything that could:

- leak a secret key, session token, signing key or container
  authorization token (in exceptions, logs, debug output or caches);
- write credentials to a shared cache in plain text;
- send credential requests through a proxy, follow a redirect, or reach a
  host other than the documented metadata and container endpoints;
- produce a signature that AWS would accept for a request other than the
  one the caller signed.

## Out of scope

- Credentials exposed by the application that uses this library (for
  example a world-readable cache directory chosen by the caller).
- Weaknesses in AWS Signature Version 4 itself.
- Denial of service through very large inputs passed in by the caller.
