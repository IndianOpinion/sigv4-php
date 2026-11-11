---
name: Bug report
about: Something signs wrongly, fails to resolve credentials, or throws when it should not
labels: bug
---

**What happened**

A clear description. For a `SignatureDoesNotMatch`, paste the canonical
request AWS returned and the one from
`$signed->getDetails()->getRedactedCanonicalRequest()`.

**What you expected**

**How to reproduce**

The smallest script that shows it. Use the `AKIDEXAMPLE` keys from the AWS
test suite. Never paste real credentials, session tokens or presigned URLs.

**Environment**

- sigv4-php version:
- PHP version and SAPI (FPM, CLI):
- Where it runs (EC2, ECS, EKS, laptop, other):
- AWS service and region:
- Installed with Composer or `bootstrap.php`:
