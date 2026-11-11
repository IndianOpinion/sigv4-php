# AWS Signature Version 4 test suite

These 38 directories are the official AWS SigV4 test vectors, copied
unmodified from the `tests/aws-signing-test-suite/v4` directory of
[awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4)
at commit `bdb7cef99d8bd1ad3c189b1400140a7787e47105` (2 November 2026).

They are licensed under the Apache License 2.0. The licence text is in
`LICENSE` and the upstream notice in `NOTICE`, both copied from the same
commit. No file in this directory has been modified, except this README,
which is ours. The rest of the sigv4-php project is MIT licensed.

The `v4a` directory (SigV4A, ECDSA) is not copied: SigV4A is a non-goal.

Each case holds:

- `request.txt`: the unsigned HTTP request;
- `context.json`: credentials, region, service, timestamp, expiry and flags
  (`normalize`, `sign_body`, `omit_session_token`);
- `header-*.txt`: canonical request, string to sign, signature and signed
  request for the Authorization header variant;
- `query-*.txt`: the same for the presigned URL variant.

`tests/OfficialVectorsTest.php` runs every case, both variants.
