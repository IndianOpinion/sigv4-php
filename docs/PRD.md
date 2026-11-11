# sigv4-php: product requirements

Status: draft for review. Audience: the builder of version 0.1.0 and anyone
who later asks "why does it work like this?".

AWS SigV4 signing and IMDSv2 instance-role credentials in about a hundred
lines of PHP. No SDK, no Composer.

## 1. Problem

A PHP application that makes a handful of AWS API calls (send one email,
put one object, read one parameter) has two choices today:

- Install the AWS SDK for PHP. It is large, it pulls in a dependency tree
  (an HTTP client, PSR packages, promise libraries), and it needs Composer
  and a `vendor/` directory. Plugins and small tools that ship as plain
  files cannot carry that cleanly, and two copies of the SDK in one PHP
  process (one per plugin) collide.
- Hand-roll the signer. Every guide shows the happy path. The traps are in
  the edges: double encoding of the path for every service except S3,
  query parameters with empty values, header whitespace, session tokens,
  credentials that expire mid-process, and the metadata service that only
  answers to a session token.

Without a small, correct, tested signer and credential chain, the result
is either a heavy dependency for three API calls, or a fragile copy-paste
that fails with `403 SignatureDoesNotMatch` the first time a path contains
a space.

Measured result: in production on indianopinion.org, a signer and IMDSv2
credential reader of about a hundred lines has carried every AWS call the
site makes, on an instance role with no static access key on the machine,
with no SDK and no `vendor/` directory.

Why a hundred-line signer is reasonable: the algorithm is fully specified
by AWS, it is deterministic, and it has an official test suite. It is also
exercised by every single call, so a regression is never silent: it shows
up at once as a 403. That is a better failure profile than most code.

When to use the SDK instead: when you call many services, need retries
with backoff and jitter, paginators, waiters, streaming uploads with
chunked signing, SigV4A (multi-region access points), SSO or
`credential_process` profiles, or the shared config and credentials files.
This library will not grow into any of those.

## 2. Goals and non-goals

Goals:

1. Sign an arbitrary HTTP request with AWS Signature Version 4 exactly as
   the AWS documentation specifies: canonical request, string to sign,
   signing key, `Authorization` header.
2. Produce presigned URLs (the query-string variant) with an expiry.
3. Resolve credentials through a chain: explicit static, environment
   variables, the ECS or EKS container credentials endpoint, and EC2
   IMDSv2.
4. Cache temporary credentials in memory and through a pluggable cache,
   refreshing before expiry. Encrypt them when the cache is shared storage.
5. Pluggable HTTP transport and clock, so every path is testable offline.
6. Handle the S3 differences (single encoding, no path normalisation,
   `x-amz-content-sha256`, `UNSIGNED-PAYLOAD`).
7. Pass the official AWS SigV4 test-suite vectors, shipped as fixtures.
8. Zero runtime dependencies. PHP 8.1+. Usable via Composer
   (`indianopinion/sigv4-php`, namespace `IndianOpinion\SigV4`) or with one
   `require` of a bootstrap file.

Non-goals:

- A service client (no SES, S3 or STS wrappers, no response parsing beyond
  extracting an AWS error type for the caller's convenience, see 4.6).
- SigV4A (`AWS4-ECDSA-P256-SHA256`).
- Signature Version 2 or any older scheme.
- Chunked (`aws-chunked`, streaming) payload signing. Documented as a limit.
- Shared config and credentials files (`~/.aws/config`), SSO, web identity
  (`AssumeRoleWithWebIdentity`), `credential_process`. Possible later; not
  in 0.1.0 (see section 13).
- Retries with backoff. The library sends nothing on its own except
  credential fetches. The one built-in retry is the refresh-and-retry
  helper in 4.6, which callers opt into.
- IMDSv1. The library never falls back to it.

## 3. Users and setting

- PHP developers who need a few AWS calls from a WordPress plugin, a small
  framework app, a CLI script or a cron job, and do not want the SDK.
- Runs on: EC2 (instance role through IMDSv2), ECS and EKS (container
  credentials endpoint), any host with environment variables or explicit
  keys (laptops, CI, other clouds, S3-compatible stores that accept SigV4).
- Installed by Composer, or by copying the `src/` directory and requiring
  one bootstrap file.
- Concurrency: PHP-FPM workers or CLI processes, many processes at once,
  sharing at most a cache backend (APCu, a database row, a file,
  Redis). There is no long-lived daemon.

## 4. Behaviour

Cases are numbered so section 12 can map each one to a test. S is signing,
P is presigning, C is credentials, K is caching, T is transport, F is
failure modes.

### 4.1 Signing (header variant)

Input: method, full URL (scheme, host, optional port, path, query),
headers, body (string, or a precomputed payload hash, or the unsigned
marker), region, service, credentials, and a time from the clock.

Output: the same request with `Authorization`, `X-Amz-Date`, and when
needed `X-Amz-Security-Token` and `X-Amz-Content-Sha256` added. The signer
never sends anything.

- S1. Method is used as given, upper-cased. An empty method is rejected.
- S2. Canonical URI, non-S3 services: each path segment is URI-encoded
  twice (once for the wire, once more for the canonical request), the path
  is normalised (remove `.` segments, resolve `..`, collapse repeated
  slashes) per the test suite's `normalize: true` cases. The caller
  supplies either a raw path (library encodes) or an already-encoded wire
  path (library decodes and re-encodes); the API must make the choice
  explicit so nobody encodes three times.
- S3. Canonical URI, S3 (service `s3`, and any service the caller marks as
  "S3-style"): each segment is encoded once, `/` inside the key is kept,
  and the path is not normalised: `a/./b`, `a//b` and `a/../b` are signed
  as written, because they are distinct object keys.
- S4. Empty path is signed as `/`.
- S5. URI encoding: every byte except `A-Z a-z 0-9 - . _ ~` is encoded as
  `%XX` with upper-case hex. Space is `%20`, never `+`. `~` is never
  encoded. Multi-byte UTF-8 is encoded byte by byte.
- S6. Canonical query string: each name and value is encoded (rules of
  S5), then pairs are sorted by encoded name, then by encoded value. Sort
  is byte order (ordinal), not locale, and is case-sensitive (`B` sorts
  before `a`).
- S7. Repeated keys (`a=2&a=1`) are kept, each pair separately, and sorted
  by value (`a=1&a=2`). Callers can supply the query as a list of pairs to
  preserve repeats; a PHP associative array cannot hold repeats, so a list
  form is required.
- S8. Empty values: `?acl` and `?acl=` both sign as `acl=`. A key with an
  empty name is signed as `=value` per the test suite case for empty query
  keys.
- S9. A query string already present in the URL is parsed, decoded and
  re-encoded under S5 to S8 (so `%7E` and `~` sign the same). `+` in an
  incoming query is treated as a literal plus, not a space, and the
  documentation says so.
- S10. Canonical headers: names lower-cased, sorted, values trimmed, runs
  of internal whitespace collapsed to one space, multi-line values folded,
  repeated headers joined with `,` in the order given.
- S11. Headers signed by default: `host`, every `x-amz-*` header present,
  and `content-type` when present. Callers may add more (for example
  `content-md5`, `range`). The signer refuses to sign hop-by-hop headers
  (`connection`, `keep-alive`, `transfer-encoding`, `te`, `trailer`,
  `upgrade`, `proxy-authorization`, `proxy-authenticate`) and the volatile
  `user-agent`, `expect` and `x-amzn-trace-id`, even when asked; asking is
  ignored with a documented reason, not an error.
- S12. Host: taken from the URL. Default ports (`443` for https, `80` for
  http) are omitted; a non-default port is included (`host:9000`). A
  caller-supplied `Host` header that disagrees with the URL is an error,
  because the transport will send the URL's host.
- S13. Content type: never invented. If the caller sends a body with a
  content type, it is signed; if not, nothing is added.
- S14. Empty body: payload hash is the SHA-256 of the empty string. This
  covers GET, HEAD, DELETE and a POST with no body.
- S15. Binary body: hashed as raw bytes. No string conversion, no
  newline translation, no charset handling. A body with a NUL byte and
  invalid UTF-8 must sign correctly.
- S16. Precomputed payload hash: the caller may pass a 64-character
  lower-case hex hash instead of the body (for a large file hashed in
  streaming fashion). Anything else is rejected.
- S17. Unsigned payload: the caller may pass the unsigned marker; the
  canonical request uses `UNSIGNED-PAYLOAD`. Allowed for S3. For other
  services it is allowed but documented as service-dependent.
- S18. `x-amz-content-sha256`: added automatically for S3 with the payload
  hash (or `UNSIGNED-PAYLOAD`) and signed. For other services it is added
  only when the caller asks.
- S19. Session token: when credentials carry a token, `x-amz-security-token`
  is added and signed. The option to add it after signing (some services
  want it unsigned) exists, off by default, documented with the services
  known to need it as an open question (section 13).
- S20. Date: `x-amz-date` in `YYYYMMDD'T'HHMMSS'Z'`, UTC, from the clock.
  The credential scope date is the first eight characters of the same
  value. The two must never come from two clock reads (a call that crosses
  midnight UTC would otherwise produce a scope that disagrees with the
  timestamp).
- S21. A caller-supplied `x-amz-date` or `date` header is honoured as the
  signing time only when an explicit option says so; otherwise it is
  replaced, so a stale header copied from elsewhere does not sign.
- S22. Credential scope: `date/region/service/aws4_request`. Region and
  service are lower-case and validated (`[a-z0-9-]+`). `us-east-1` style
  region codes are examples only; any valid code is accepted.
- S23. Signing key: HMAC chain over date, region, service and
  `aws4_request`, seeded with `AWS4` plus the secret. The derived key may
  be memoised per (secret hash, date, region, service) for the life of the
  process; never cached outside the process.
- S24. `Authorization` header: `AWS4-HMAC-SHA256 Credential=...,
  SignedHeaders=..., Signature=...` with commas and one space as in the
  documentation; signature is lower-case hex.
- S25. The signer can return its intermediate products (canonical request,
  string to sign, signed headers) for debugging and for the test suite.
  These never contain the secret or the signing key.
- S26. Clock skew: AWS rejects requests more than 15 minutes from its own
  time (`RequestTimeTooSkewed`, or `SignatureDoesNotMatch` on some
  services). The signer does not guess. It accepts a clock offset from the
  clock abstraction, and the error helper (4.6) exposes the skew error type
  so the caller can correct the offset from the response `Date` header.
- S27. Signing is pure: the same inputs and the same clock produce the
  same bytes. No randomness.

### 4.2 Presigned URLs (query variant)

- P1. Adds `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
  `X-Amz-Expires`, `X-Amz-SignedHeaders`, and `X-Amz-Security-Token` when
  credentials carry a token, to the query; all are part of the canonical
  query string. `X-Amz-Signature` is computed last and appended; it is not
  part of the canonical query.
- P2. Expiry: integer seconds, 1 to 604800 (seven days). Out of range is
  an error, not a clamp.
- P3. With temporary credentials, a URL lives no longer than the
  credentials that signed it. If the requested expiry is past the
  credentials' expiry, the library still signs (the URL is valid until the
  credentials expire) but returns the effective expiry so the caller can
  see it, and a strict option turns this into an error.
- P4. Payload hash for presigning is `UNSIGNED-PAYLOAD` for S3 and the
  empty-string hash for other services, overridable.
- P5. Signed headers default to `host` only. Extra headers the caller asks
  to sign must then be sent by whoever uses the URL; this is documented.
- P6. Existing query parameters on the URL are kept and signed. If the
  URL already contains `X-Amz-*` signing parameters, it is an error
  (re-presigning a presigned URL is always a mistake).
- P7. Presigning uses the same canonical URI rules as S2 and S3.

### 4.3 Credentials and the provider chain

A credential is: access key id, secret access key, optional session token,
optional expiry (absolute UTC time), and a source label for logs
(`static`, `env`, `container`, `imds`). Credentials without an expiry
never expire.

Default chain order, first success wins:

1. Static (explicit) credentials passed in code.
2. Environment variables.
3. Container credentials endpoint (ECS, EKS Pod Identity).
4. EC2 instance metadata (IMDSv2).

The chain is a list; the caller can build any order or subset.

- C1. Static: key and secret required, token optional, expiry optional.
  Empty key or secret is an error at construction, not at signing time.
- C2. Environment: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN` (optional). Read through `getenv()` and `$_ENV` and
  `$_SERVER` in that order, because PHP-FPM often exposes variables in only
  one of them. If neither key variable is set, the provider yields
  "not found" and the chain moves on. If exactly one of the pair is set, it
  is an error, not "not found": a half-configured environment must be
  loud.
- C3. Container, relative: if `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` is
  set, GET `http://169.254.170.2` plus that path. It takes precedence over
  the full URI.
- C4. Container, full: else if `AWS_CONTAINER_CREDENTIALS_FULL_URI` is set,
  GET that URL. Allowed only when the scheme is https, or the host is a
  loopback address, or the host is one of the documented container
  endpoints (`169.254.170.2`, `169.254.170.23`, `[fd00:ec2::23]`). Any
  other host is refused so an injected variable cannot send the
  authorization token anywhere.
- C5. Container authorization: if `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`
  is set, read the token from that file on every fetch (EKS rotates it);
  else if `AWS_CONTAINER_AUTHORIZATION_TOKEN` is set, use it. Sent as the
  `Authorization` header. A token containing CR or LF is refused.
- C6. Container response: JSON with `AccessKeyId`, `SecretAccessKey`,
  `Token`, `Expiration`. Missing fields or non-JSON is an error from this
  provider.
- C7. Neither container variable set: "not found", no network call.
- C8. IMDSv2 token: PUT `/latest/api/token` with
  `X-aws-ec2-metadata-token-ttl-seconds`. Default TTL 21600 seconds (the
  maximum), configurable 1 to 21600. The token is reused for later
  metadata calls until shortly before its TTL ends.
- C9. IMDSv2 role: GET `/latest/meta-data/iam/security-credentials/` with
  the token header. The first non-empty line is the role name. The name
  is validated against the IAM role name character set
  (`[A-Za-z0-9+=,.@_-]`, 1 to 64 characters) before it is placed in a URL.
  A configured role name skips this call.
- C10. IMDSv2 credentials: GET `.../security-credentials/<role>`. Success
  requires `Code` equal to `Success` and non-empty key, secret, token and
  expiration. `Expiration` is parsed as UTC ISO 8601.
- C11. IMDS endpoint: `http://169.254.169.254` by default;
  `AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE=IPv6` selects
  `http://[fd00:ec2::254]`; `AWS_EC2_METADATA_SERVICE_ENDPOINT` overrides
  both. `AWS_EC2_METADATA_DISABLED=true` makes the provider yield
  "not found" with no network call.
- C12. Not on EC2: the token PUT fails to connect or times out. Short
  timeouts (connect 1 second, total 2 seconds by default, configurable)
  bound the delay. Result: "not found" with the reason, so a chain on a
  laptop moves on quickly.
- C13. Hop limit: the PUT response has an IP hop limit of 1 by default. In
  a container on EC2 with the default hop limit, the PUT times out even
  though the instance has a role. The error message must name this cause
  ("token request timed out; if running in a container, the instance
  metadata hop limit may need to be 2") so nobody spends an afternoon on
  it.
- C14. IMDSv1 is never used. A 403, 404 or 405 on the token PUT is an
  error that says IMDSv2 is unavailable; no fallback.
- C15. A 401 on a metadata GET means the session token expired or was
  rejected: fetch a new token once and retry the GET once.
- C16. Instance with no role attached: the role listing returns 404 or an
  empty body. Error: "no instance role attached", final for this provider.
- C17. The metadata requests never send `X-Forwarded-For` (IMDS rejects a
  PUT that carries it), never use a proxy, and never follow redirects.
- C18. Chain semantics: "not found" moves to the next provider; a
  configuration error (C2 half-set, C4 refused host, C5 bad token) stops
  the chain and is raised, because silently falling through to a different
  identity is worse than failing. A transient error (timeout, 5xx) on a
  provider whose environment says it applies (container variables set)
  is raised, not skipped. The final error lists every provider tried and
  why each declined.
- C19. Expiry parsing: an `Expiration` that does not parse is an error. An
  `Expiration` already in the past is accepted but immediately counts as
  needing refresh (see K3), and a warning is reported.

### 4.4 Caching and refresh

- K1. In-memory cache: the resolved credential is held for the life of the
  provider object (one request in PHP-FPM, one run in CLI).
- K2. Pluggable cache: an interface with get, set with TTL, and delete.
  Shipped implementations: in-memory (array) and APCu (when the extension
  is loaded). Other stores (a database row, Redis, a file) are adapters the
  caller writes; the documentation includes a short recipe for a
  WordPress transient adapter and a PSR-16 adapter, as prose.
- K3. Refresh margin: a cached credential is used only while
  `expiry - margin > now`. Default margin 300 seconds (five minutes),
  configurable. AWS makes new instance-role credentials available at least
  five minutes before the old ones expire, so this margin always finds
  fresh credentials.
- K4. TTL written to the shared cache is `expiry - margin - now`. If that
  is under 60 seconds the credential is not written to shared storage at
  all (not worth the round trip), only kept in memory.
- K5. Static and environment credentials without an expiry are not written
  to shared storage, ever.
- K6. Read order: memory, then shared cache, then the provider. A shared
  cache hit fills memory.
- K7. Forced refresh: the caller can ask for a refresh that bypasses both
  caches (after an expired-token answer). The new credential overwrites
  both caches.
- K8. Invalidation must not fail silently and must not leave a usable
  stale value. Where a backend's delete is unreliable (some object caches
  return early or race), the cache layer overwrites the entry with an
  empty marker and a short TTL; an empty or unreadable entry is always a
  miss.
- K9. Encryption at rest: when the cache is shared storage (anything but
  in-memory), the cached credential must be encrypted. The shipped
  encrypting decorator uses libsodium secretbox (XSalsa20-Poly1305) with a
  random nonce per write, stored as nonce plus ciphertext, base64.
- K10. Key derivation: the encryption key is derived from an application
  secret the caller provides (for example a framework's app key, or a
  WordPress salt), with BLAKE2b (`generichash`) over a fixed,
  versioned domain-separation label plus the secret. The label carries a
  version so a format change can rotate keys. The secret itself is never
  stored.
- K11. Decryption failure (wrong key after a secret rotation, truncated
  blob, tampered blob, not base64): treated as a miss, the credential is
  fetched again and the entry overwritten. Reported once as a warning.
  Never an exception to the caller.
- K12. No sodium extension: the encrypting decorator refuses to construct
  (typed error). The library never writes plaintext credentials to a
  shared cache. In-memory caching still works.
- K13. Cached payload: key, secret, token, expiry, source. Nothing else
  (no role name needed; it is not a secret, but it is identifying and
  there is no reason to store it).
- K14. Concurrency: many processes may refresh at once near expiry. That
  is accepted (each fetch is cheap and idempotent); last write wins. No
  locking in 0.1.0.

### 4.5 Transport and clock

- T1. Transport interface: one method taking method, URL, headers, body,
  timeouts, returning status, headers (lower-cased names), body, and a
  transport error string. Used only for credential fetches; signing never
  touches it.
- T2. Default transport: curl when loaded, else PHP streams. Both: TLS
  verification on, no redirects, no proxy (curl `NOPROXY *`; streams
  without a proxy context), explicit connect and total timeouts.
- T3. Metadata and container calls must bypass any proxy even when
  `HTTP_PROXY` or `http_proxy` is set in the environment. This is a
  requirement, not a default, because a proxy that sees the IMDS response
  sees the credentials.
- T4. Clock interface returns the current UTC time as an immutable date
  time. System clock by default, with an optional fixed offset in seconds
  (S26). A frozen clock ships for tests.
- T5. A response body over 64 KiB from a credential endpoint is refused
  (credentials JSON is under 2 KiB).

### 4.6 Error helper and refresh-and-retry

- F-helper. A small helper extracts the AWS error type from a response the
  caller received: from the `x-amzn-ErrorType` header (strip anything
  after `:`), else from a JSON `__type` (strip everything up to `#`), else
  from an XML `<Code>` element (S3 style), else `HTTP<status>`. It also
  extracts the request id from `x-amzn-RequestId` or `x-amz-request-id`.
- F-retry. An opt-in helper runs a caller-supplied send function. If the
  answer is a 403 with an expired or unrecognised credential error type
  (`ExpiredToken`, `ExpiredTokenException`, `InvalidClientTokenId`,
  `UnrecognizedClientException`), it forces a credential refresh (K7),
  re-signs and sends exactly once more. Never twice. Any other error is
  returned untouched.

### 4.7 Failure modes

Every failure is a typed exception (section 5) or a documented "not
found". Nothing returns false, nothing is suppressed with `@`.

- F1. Invalid signing input (bad region, bad service, empty method,
  malformed URL, relative URL, host mismatch, bad payload hash):
  exception before any hashing. Fail closed.
- F2. No credentials anywhere in the chain: exception listing each
  provider and its reason. Fail closed: the caller must never send an
  unsigned request by accident.
- F3. IMDS unreachable (not EC2): "not found" for that provider within the
  timeout (C12). Fail through to the next provider, or F2 if last.
- F4. IMDS reachable but token PUT refused (403, 405): exception naming
  IMDSv2. Fail closed, no IMDSv1 (C14).
- F5. IMDS token PUT times out on EC2 in a container: as F3, with the hop
  limit hint (C13).
- F6. Role missing or credentials JSON bad: exception from the provider.
- F7. Container endpoint returns non-200 or bad JSON: exception (C18).
- F8. Container full URI with a refused host: configuration exception,
  chain stops (C4, C18).
- F9. Shared cache read error, decrypt failure: miss, refetch (K11). Fail
  open to the provider, never to plaintext.
- F10. Shared cache write error: credential still returned; a warning is
  reported. Fail open, because the request can proceed.
- F11. Credentials expire between resolve and send (long-running CLI):
  covered by the margin (K3); if AWS still answers expired, F-retry.
- F12. Clock skew over 15 minutes: AWS answers 403. The helper exposes the
  error type; the library does not adjust the clock on its own. Fail
  closed with a clear message.
- F13. Presign expiry out of range: exception (P2).
- F14. Transport layer missing (no curl, no `allow_url_fopen`): exception
  when a network provider is first used, not at load time, so static-key
  users on locked-down hosts are unaffected.
- F15. Secret material in exceptions: no exception message, log line, or
  debug output may contain a secret key, session token, signing key or
  authorization token. Access key ids may appear (they are not secret
  and they are what an operator needs).

## 5. Public interface

Names below are the intended public surface. The builder may adjust
names in ARCHITECTURE.md with a reason; behaviour may not change.

Namespace `IndianOpinion\SigV4`.

- `Signer`: constructed with a clock and options. Signs a request (header
  variant) and returns the signed request. Presigns a request and returns
  a URL plus the effective expiry. Can return the intermediate products
  (S25). Takes region, service and a credentials object per call.
- `Request`: an immutable value object (method, URL, headers as a list of
  name and value pairs, body or payload hash or unsigned marker). Has a
  constructor from a PSR-7 request only if the PSR-7 interface exists at
  runtime; no dependency on it.
- `Payload`: named constructors for "string body", "precomputed hash",
  "unsigned".
- `Credentials`: immutable value object (key id, secret, token, expiry,
  source). Its string form and debug output mask the secret and token.
- `Credentials\Provider` interface: returns credentials or signals
  "not found".
- Providers: `StaticProvider`, `EnvironmentProvider`, `ContainerProvider`,
  `InstanceMetadataProvider`, `ChainProvider` (ordered list),
  `CachingProvider` (decorator: memory plus optional shared cache, margin,
  forced refresh).
- A default chain factory that builds the order in 4.3 with sensible
  options, and accepts static credentials first when given.
- `Cache\CredentialCache` interface (get, set with TTL, delete).
  Implementations: `ArrayCache`, `ApcuCache`, `EncryptedCache`
  (decorator, takes an inner cache and an application secret).
- `Http\Transport` interface; `CurlTransport`, `StreamTransport`, and an
  in-memory fake transport for tests that records calls and replays
  scripted responses.
- `Clock` interface; `SystemClock` (with offset), `FrozenClock`.
- `ErrorInfo` helper (4.6) and `RetryOnExpired` helper (4.6).
- Exceptions, all extending one `SigV4Exception`:
  `InvalidRequestException`, `CredentialsNotFoundException`,
  `CredentialsException` (provider failure), `ConfigurationException`,
  `TransportException`, `CacheException` (only for construction errors
  such as missing sodium; runtime cache errors are warnings, K11 and F10).
- Warnings go to an optional PSR-3-shaped logger callable (a plain
  callable taking level, message and context), so there is no PSR-3
  dependency.
- Bootstrap: `sigv4.php` at the repository root registers a PSR-4
  autoloader for `src/` and does nothing else, for use without Composer.

## 6. Data

- Stored: only temporary credentials (key, secret, token, expiry, source),
  only when the caller configures a shared cache, only encrypted (K9), for
  at most `expiry - margin`.
- In memory: the resolved credential, the IMDS session token, memoised
  signing keys (S23). All gone at process end.
- Nothing on disk unless the caller's cache adapter writes to disk.
- Retention: TTL-bound by construction. Temporary credentials from AWS
  live hours at most.
- Uninstall: removing the library leaves at most one encrypted cache
  entry in the caller's store, which expires on its own. The README says
  how to delete it by key.

## 7. Configuration and defaults

| Setting | Default | Notes |
|---|---|---|
| Chain order | static, env, container, IMDS | Any list may be passed |
| Refresh margin | 300 s | K3 |
| Minimum shared-cache TTL | 60 s | K4 |
| IMDS endpoint | IPv4 link-local | C11, env overrides honoured |
| IMDS token TTL | 21600 s | C8 |
| IMDS connect / total timeout | 1 s / 2 s | C12 |
| Container connect / total timeout | 1 s / 3 s | |
| IMDS disabled | false | `AWS_EC2_METADATA_DISABLED` |
| Shared cache | none | Opt in; encrypted decorator required |
| Cache key | a fixed, documented, library-prefixed string | Configurable for many identities in one store |
| Clock offset | 0 s | S26 |
| Session token placement | signed header | S19 |
| `x-amz-content-sha256` | S3 only | S18 |
| Presign expiry | 900 s | 1 to 604800 |
| Strict presign expiry | off | P3 |
| Max credential response size | 64 KiB | T5 |

## 8. Security and privacy

- Secrets are never logged, never in exception messages, never in
  `var_dump` or `print_r` output (value objects implement debug info that
  masks them) (F15).
- Shared caches hold only encrypted credentials (K9, K12). A database dump
  or a cache snapshot alone does not yield usable keys; the attacker also
  needs the application secret. Credentials expire within hours anyway.
- Key derivation uses a versioned domain-separation label so the same
  application secret used elsewhere does not produce the same key.
- Metadata and container calls: no proxy, no redirects, no
  `X-Forwarded-For`, response size limit, role name validated before it
  enters a URL (C9, C17, T3, T5).
- Container full URI allowlist (C4) stops an injected environment variable
  from exfiltrating the authorization token.
- No IMDSv1 fallback (C14): IMDSv1 is the SSRF-friendly version.
- TLS verification is always on for https; there is no switch to turn it
  off.
- Signature comparison is never done by this library (it signs, it does
  not verify), so constant-time comparison is not in scope. If a verify
  helper is ever added, it must use `hash_equals`.
- No `eval`, no shell, no `unserialize` (the cache stores JSON).

## 9. Performance budget

- Signing one request with a body under 1 MiB: under 0.2 ms on a modern
  CPU (hashing dominates; the rest is string work). The test suite runs
  all vectors in under one second.
- Signing must not copy the body more than once; a precomputed hash avoids
  even that (S16).
- Credential resolution on a warm memory cache: no I/O.
- On a warm shared cache: one cache read plus one decrypt.
- Cold on EC2: three local HTTP calls (token, role, credentials), each
  usually a few milliseconds; two after the role is known; one when the
  role name is configured and the token is still valid.
- Off EC2 with IMDS in the chain: bounded by the IMDS connect timeout
  (1 second default). The README tells non-EC2 users to disable IMDS or use
  a shorter chain.
- Core signer size: about a hundred lines of logic. The whole library
  (providers, caches, transports) is larger; the claim refers to the
  signer, and the README says so plainly.

## 10. Compatibility

- PHP 8.1, 8.2, 8.3 (CI matrix); 8.4 when available on the CI runner.
- Extensions: `hash` (always present). `json` (always present in 8.x).
  `curl` optional (streams fallback). `sodium` required only for the
  encrypted cache. `apcu` optional.
- Works on EC2 (Nitro and Xen), ECS on EC2 and Fargate, EKS with Pod
  Identity, plain hosts with keys, and S3-compatible stores that implement
  SigV4 (path-style and virtual-hosted-style URLs both sign, since the
  signer takes the URL as given).
- WordPress: usable from a plugin with one `require`; no WordPress code in
  the library. A transient adapter is documented, not shipped.
- No global functions, no global state except optional process-level
  memoisation inside objects the caller owns.

## 11. Observability

- Optional logger callable (section 5). Levels: debug (which provider
  answered, cache hit or miss, refresh), warning (decrypt failure,
  cache write failure, expired credential returned by a provider, presign
  expiry capped by credential expiry).
- Each credential carries its source label, so an operator can log
  "signed with imds credentials expiring at 14:05Z" without secrets.
- The debug products (S25) let an operator diff their canonical request
  against the one AWS returns in a `SignatureDoesNotMatch` body. The README
  has a short "how to debug a 403" section built on this.
- The chain failure message lists every provider and its reason (C18).

## 12. Acceptance tests

PHPUnit 10. No test touches the network: every provider test runs
against the fake transport, every signing test against a frozen clock.

### 12.1 Official vectors

- A1. Every case in the AWS SigV4 test suite (`v4` directory, 38 cases at
  the time of writing) runs as a data-provider case: build the request
  from `request.txt` and `context.json`, then assert the canonical
  request, string to sign, signature, and the signed request, for both the
  header and the query variants where the case provides them. The
  `normalize` flag in `context.json` selects S2 or S3 path rules.
- Licence finding: the suite is published by AWS inside the
  `awslabs/aws-c-auth` repository (`tests/aws-signing-test-suite/v4`),
  which is licensed Apache-2.0 (NOTICE: "Copyright Amazon.com, Inc. or its
  affiliates"). Apache-2.0 files may be redistributed inside an MIT
  project provided the licence text and NOTICE travel with them and
  modified files are marked. The fixtures go in `tests/fixtures/aws-sig-v4/`
  unmodified, with that directory's own `LICENSE` (Apache-2.0) and `NOTICE`
  and a README naming the source commit. The top-level README states that
  the fixtures are Apache-2.0 and the rest is MIT. The `v4a` directory is
  not copied (non-goal). The older zip on the AWS General Reference page
  is no longer the canonical location; cite the repository.

### 12.2 Case map

| Case | Test |
|---|---|
| S1 | lower-case method is signed upper-case; empty method throws |
| S2 | segment with space and `%` double-encodes; `normalize` vectors pass (A1) |
| S3 | S3 key `a b/c~d` encodes once; `a//b`, `a/./b`, `a/../b` signed as written |
| S4 | empty path signs as `/` |
| S5 | every byte 0x00 to 0xFF encodes per the rule; `~` kept; space is `%20`; UTF-8 key byte-encoded (A1 `get-utf8`) |
| S6 | `b=1&B=2&a=3` sorts ordinally; A1 `get-vanilla-query-order-*` |
| S7 | `a=2&a=1` signs as `a=1&a=2`; list-of-pairs input keeps repeats |
| S8 | `?acl` and `?acl=` sign identically; A1 empty key and empty value cases |
| S9 | `%7E` and `~` sign the same; `+` stays a literal plus |
| S10 | A1 header trim, multiline, duplicate key, value order cases |
| S11 | `user-agent` and `connection` requested for signing are not signed |
| S12 | default port omitted; `:9000` kept; conflicting Host header throws |
| S13 | no body, no content type: `content-type` absent from signed headers |
| S14 | GET with no body uses the empty-string hash |
| S15 | body with NUL and invalid UTF-8 signs to a known signature |
| S16 | valid precomputed hash used verbatim; 63-char and upper-case hashes throw |
| S17 | unsigned marker yields `UNSIGNED-PAYLOAD` in canonical request |
| S18 | S3 request gets `x-amz-content-sha256` signed; non-S3 does not unless asked |
| S19 | session token signed by default (A1 `get-vanilla-with-session-token`); after-signing option leaves it out of signed headers |
| S20 | frozen clock at 23:59:59.9 UTC: scope date equals timestamp date |
| S21 | stale caller `x-amz-date` is replaced unless the option is set |
| S22 | upper-case or empty region and service throw |
| S23 | signing key matches the documented example; memo does not change output |
| S24 | Authorization header exact string for a known vector |
| S25 | debug products contain no secret (assert secret substring absent) |
| S26 | clock offset of +120 s moves `x-amz-date` by 120 s |
| S27 | same inputs twice give identical output |
| P1 | presigned URL parameter set exact; signature excluded from canonical query |
| P2 | expiry 0 and 604801 throw; 1 and 604800 pass |
| P3 | temporary credentials expiring in 600 s, expiry 3600: effective expiry 600 returned; strict mode throws |
| P4 | S3 presign uses `UNSIGNED-PAYLOAD`; non-S3 uses empty hash |
| P5 | default signed headers is `host` |
| P6 | URL already carrying `X-Amz-Signature` throws; ordinary query kept and signed |
| P7 | presign of S3 key with `//` not normalised |
| C1 | empty key or secret throws at construction |
| C2 | env pair read from each of the three sources; only key set throws; none set is not found |
| C3 | relative URI wins over full URI; request goes to the container host |
| C4 | full URI with https host, loopback, each documented host allowed; other http host refused |
| C5 | token file read each fetch (two fetches, file changed between); file wins over variable; CRLF token refused |
| C6 | missing `Token` field throws; non-JSON throws |
| C7 | no variables: not found, zero transport calls |
| C8 | PUT carries TTL header; token reused within TTL, re-fetched after |
| C9 | role name with `/` or space rejected; configured role skips listing |
| C10 | `Code` not `Success` throws; good JSON yields credential with parsed expiry |
| C11 | IPv6 mode and endpoint override change the URL; disabled flag means zero calls |
| C12 | transport timeout on PUT: not found, reason recorded |
| C13 | timeout message contains the hop limit hint |
| C14 | PUT 403 and 405: exception; no un-tokened GET is ever made |
| C15 | GET 401 then 200: one new PUT, one retried GET, success |
| C16 | role listing 404 and empty body: "no instance role" exception |
| C17 | fake transport asserts no `X-Forwarded-For`, no-proxy and no-redirect options on every metadata call |
| C18 | chain: not found moves on; configuration error stops; final message lists all providers |
| C19 | unparseable expiry throws; past expiry returns credential flagged for refresh and logs a warning |
| K1 | second resolve in same object makes zero transport calls |
| K2 | ArrayCache and ApcuCache (skipped without APCu) pass a shared contract test |
| K3 | expiry now+301 s is used; now+300 s triggers refresh |
| K4 | TTL written equals expiry minus margin minus now; under 60 s nothing written |
| K5 | static and env credentials never reach the shared cache |
| K6 | shared hit fills memory; next call reads neither |
| K7 | forced refresh bypasses both caches and overwrites them |
| K8 | invalidation writes empty marker when delete fails; empty entry is a miss |
| K9 | stored blob is base64, does not contain key, secret or token; two writes differ (fresh nonce) |
| K10 | different application secrets give different keys; label version is part of derivation |
| K11 | wrong secret, truncated blob, flipped byte, non-base64: each is a miss and a refetch, one warning |
| K12 | without sodium the encrypted cache refuses to construct (simulated) |
| K13 | decrypted payload has exactly the five fields |
| K14 | two providers sharing one cache, both refreshing: both succeed, last write readable |
| T1 | fake transport records method, URL, headers, body, timeouts |
| T2 | curl and stream transports: options set as required (inspected, not networked) |
| T3 | with `HTTP_PROXY` set, metadata calls still use no proxy |
| T4 | frozen clock and offset clock behave as documented |
| T5 | 65 KiB credential response refused |
| F-helper | header, JSON `__type`, XML `<Code>` and bare status each yield the right type; request id from both header names |
| F-retry | expired-token 403 then 200: one refresh, one resend; second 403: no third send; other 403: no retry |
| F1 | each invalid input throws `InvalidRequestException` before hashing |
| F2 | empty chain result throws `CredentialsNotFoundException` |
| F3 | same as C12 inside a chain: next provider used |
| F4 | same as C14 |
| F5 | same as C13 |
| F6 | same as C10 and C16 |
| F7 | container 500 with variables set: exception, chain does not continue |
| F8 | same as C4 refused host |
| F9 | same as K11 |
| F10 | cache write throws: credential still returned, warning logged |
| F11 | same as F-retry |
| F12 | `RequestTimeTooSkewed` surfaced by the helper |
| F13 | same as P2 |
| F14 | no transport available: static provider works; IMDS provider throws on first use |
| F15 | every exception in the suite, and every log line, scanned for the test secret, token and container token: none found |

## 13. Open questions (builder answers in ARCHITECTURE.md)

1. Session token placement: which services need the token added after
   signing rather than signed? Keep the option off by default unless a
   documented case is found.
2. Should `Request` accept a PSR-7 request when the interface is present,
   or should that be a separate optional adapter class?
3. Shared config and credentials files and web identity: confirm they stay
   out of 0.1.0, and note the cost of adding them later.
4. Container full URI allowlist: confirm the exact host list against
   current SDK behaviour (botocore and the Go SDK) and cite it.
5. IMDS token reuse: process-local only, or also in the shared cache? The
   PRD assumes process-local (the token is useless off the instance, but
   it is still a capability).
6. APCu adapter: ship it in 0.1.0 or document it as a recipe only?
7. Precise default timeouts for IMDS on loaded instances: 1 s connect may
   be tight under heavy load; measure and justify.
8. Should the strict presign expiry mode (P3) be the default?

## 14. Lessons from production

Written as rules. Each one cost real time once.

1. Encode raw path segments once for the wire and twice for the canonical
   request, for every service except S3. Take raw segments as input so the
   caller never has to think about it.
2. Never let instance metadata calls go through a proxy or an HTTP filter
   layer. Use the transport directly, with no proxy and no redirects.
3. Ask IMDS for a session token first. Instances that require IMDSv2 give
   nothing to a plain GET, and IMDSv1 should not be used anyway.
4. Keep timeouts on metadata calls short (a few seconds at most). A long
   default turns "not on EC2" into a hung page.
5. Validate the role name from IMDS before putting it in a URL.
6. Refresh five minutes before expiry. Instance-role credentials rotate
   under a long-running process; a margin avoids most expired-token
   answers.
7. When AWS does answer with an expired or unrecognised token, refresh
   once, re-sign, retry once. Never loop.
8. Encrypt any credential you put in shared storage, with a key derived
   from an application secret through a versioned label. A database dump
   alone must not carry usable keys.
9. Invalidate by overwriting with an empty value when delete is not
   trustworthy; an empty value must read as "no cache", never as a
   credential.
10. Run on an instance role with no static key on the machine. The
    library should make that the easy path.
11. Collapse header whitespace and lower-case names before signing, and
    sign `content-type` only when you actually send one.
12. Read the AWS error type from the header first and the body second,
    and strip the namespace and suffix; the raw value is not the name you
    match on.
13. A signer that every request exercises fails loudly. Trust that, and
    keep it small enough to read in one sitting.

## References

- AWS IAM User Guide, "Create a signed AWS API request":
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
- AWS IAM User Guide, "Elements of an AWS API request signature":
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing-elements.html
- Amazon S3 API Reference, "Authenticating requests: using query parameters":
  https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
- Amazon S3 API Reference, "Signature calculations for the Authorization
  header": https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
- Amazon S3 User Guide, "Download and upload objects with presigned URLs"
  (seven-day limit, temporary credentials cap the URL lifetime):
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
- Amazon EC2 User Guide, "Use the Instance Metadata Service" (IMDSv2
  token, TTL 1 to 21600 seconds, hop limit 1, `X-Forwarded-For` refused,
  401 on expired token, IPv6 endpoint):
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Amazon EC2 User Guide, "Retrieve security credentials from instance
  metadata" (JSON fields, rotation at least five minutes before expiry):
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html
- AWS SDKs and Tools Reference Guide, "IMDS credential provider"
  (`AWS_EC2_METADATA_DISABLED`, endpoint and endpoint mode):
  https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html
- AWS SDKs and Tools Reference Guide, "Container credential provider"
  (relative and full URI, authorization token and token file, precedence):
  https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html
- AWS SigV4 test suite, `awslabs/aws-c-auth`, Apache-2.0:
  https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4
