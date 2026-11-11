# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-11

### Added

- `Signer::sign()`: AWS Signature Version 4 with the Authorization header.
  Double encoding and path normalisation for every service except S3;
  single encoding and no normalisation for S3. Ordinal query sorting,
  repeated keys, empty values, header trimming and folding, session
  tokens, `x-amz-content-sha256`, precomputed and unsigned payloads.
- `Signer::presign()`: presigned URLs, 1 second to 7 days, refusing by
  default an expiry that outlives temporary credentials.
- `Request::fromRawPath()` so a raw path is encoded exactly once.
- Debug products (canonical request, string to sign) with the session
  token redacted in debug output.
- Credential providers: static, environment, container (ECS and EKS Pod
  Identity) and EC2 instance metadata (IMDSv2 only), a chain, a caching
  provider with a five-minute refresh margin, and `DefaultChain`.
- Encrypted shared cache (libsodium secretbox, key derived from your
  application secret) with array, APCu, file and PSR-16 adapters.
- curl and stream transports (no proxy, no redirects, TLS verification on,
  64 KiB response cap), and a fake transport for tests.
- `ErrorInfo` to read the AWS error type and request id from a response,
  and `RetryOnExpired` to refresh credentials and resend exactly once.
- Optional PSR-7 adapter, used only when PSR-7 is installed.
- `bootstrap.php` for use without Composer.
- The 38 official AWS SigV4 test vectors (Apache-2.0) as fixtures, run in
  both the header and query variants.

### Not yet

- Shared config and credentials files (`~/.aws/config`,
  `~/.aws/credentials`), SSO, `credential_process`, and web identity
  (`AssumeRoleWithWebIdentity`). Use environment variables or an instance
  or container role meanwhile.
- Adding the session token after signing (unsigned). The token is always
  signed; no supported AWS service needs otherwise.
- Chunked (`aws-chunked`) payload signing and SigV4A.

[Unreleased]: https://github.com/IndianOpinion/sigv4-php/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/IndianOpinion/sigv4-php/releases/tag/v0.1.0
