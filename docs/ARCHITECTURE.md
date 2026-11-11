# sigv4-php architecture

This document explains how the library is put together, how data moves
through it, and why each decision was taken. It answers the open questions
in section 13 of [PRD.md](PRD.md) and records every place where the code
departs from the PRD's suggested names, with the reason.

## Modules

```
src/
  Signer.php              Header signing and presigning. Pure: no I/O.
  Request.php             Immutable request: method, wire URL, headers, payload.
  Payload.php             String body, precomputed hash, or UNSIGNED-PAYLOAD.
  SigningOptions.php      Per-call switches (S3 style, extra headers, strict expiry).
  SignedRequest.php       Result of sign(): method, URL, headers, body, details.
  PresignedUrl.php        Result of presign(): URL, effective expiry, headers to send.
  SigningDetails.php      Canonical request, string to sign, scope, signature.
  Credentials.php         Immutable key id, secret, token, expiry, source label.
  ErrorInfo.php           AWS error type and request id from a response.
  RetryOnExpired.php      Refresh credentials and resend exactly once.
  Clock/                  Clock interface, SystemClock (with offset), FrozenClock.
  Credentials/            Provider interfaces and the providers:
                          Static, Environment, Container, InstanceMetadata,
                          Chain, Caching, plus DefaultChain and Environment.
  Cache/                  CredentialCache interface, Array, Apcu, File, Psr16
                          adapters, and the EncryptedCache decorator.
  Http/                   Transport interface, Curl, Stream and Fake
                          transports, HttpRequest, HttpResponse, factory.
  Psr7/Psr7Adapter.php    Optional bridge to PSR-7 requests.
  Internal/               Uri encoding rules, credentials JSON parsing, strict
                          ISO 8601 parsing, the logger wrapper. Not public API.
  Exception/              SigV4Exception and its six subclasses.
bootstrap.php             PSR-4 autoloader for use without Composer.
```

The signer depends on nothing but `Clock`. The providers depend on
`Transport` and `Clock`. Nothing in `src/` depends on a third-party
package; the PSR-7 adapter type-hints PSR-7 interfaces but is only loaded
when called, and checks that they exist first.

## Data flow

### Signing

1. The caller builds a `Request` from a wire URL (already encoded), or with
   `Request::fromRawPath()` from a raw path that the library encodes once.
   The constructor validates method, URL, host, header names and values
   (CR or LF only as line folding), so a bad input fails before any
   hashing (F1).
2. `Signer::sign()` validates region and service, checks a caller `Host`
   header against the URL, then reads the clock exactly once. The
   timestamp and the scope date come from that one reading (S20).
3. It copies the headers, drops any stale `Authorization` and `X-Amz-Date`,
   replaces `X-Amz-Security-Token` and `X-Amz-Content-Sha256` when it sets
   them, and appends its own.
4. It builds the canonical request: method; canonical URI (double encoded
   and normalised, or single encoded for S3); canonical query (decoded,
   re-encoded, sorted by byte); canonical headers (lower-cased, values
   trimmed and whitespace collapsed, repeats joined with commas); signed
   header list; payload hash.
5. It derives the signing key (memoised per secret hash, date, region and
   service, at most 16 entries, in memory only), signs the string to sign,
   and appends the `Authorization` header.

Presigning follows the same steps but puts the algorithm, credential, date,
expiry, signed headers and token in the query, signs `host` plus any
requested headers, and appends `X-Amz-Signature` last.

### Credentials

```
CachingProvider
  memory  -> hit while expiry - margin > now
  shared  -> EncryptedCache -> CredentialCache adapter (APCu, file, PSR-16, ...)
  provider:
    ChainProvider
      StaticProvider       (only when static credentials are given)
      EnvironmentProvider  getenv, then $_ENV, then $_SERVER
      ContainerProvider    relative URI, else allow-listed full URI
      InstanceMetadataProvider  PUT token, GET role, GET credentials
```

Every provider either returns `Credentials`, throws
`CredentialsNotFoundException` (the chain moves on), or throws another
`SigV4Exception` (the chain stops). The chain's final not-found exception
carries one reason per provider.

## Behaviour notes the PRD left to the builder

- **Wire URL versus raw path (S2).** A `Request` always holds the wire URL.
  For non-S3 services the canonical URI is each wire segment encoded once
  more, which is what AWS computes from what it receives; a raw space
  therefore appears as `%2520`. For S3-style services the path is decoded
  and encoded once with `/` kept, so `%7E` and `~` sign the same and an
  encoded `%2F` signs as `/`, matching how S3 sees the key.
- **The `normalize` flag in the official vectors.** It controls path
  normalisation only. The vectors double encode in every case (a raw space
  in `request.txt` signs as `%20` because the wire path is taken as is).
  The test therefore sets `normalizePath` from the flag and keeps double
  encoding on; `SigningOptions` exposes the two switches separately.
- **Signed headers in the vectors.** The suite signs every header present
  in `request.txt`. The library signs `host`, `x-amz-*` and `content-type`
  by default (S11), so the vector test lists the other headers explicitly.
- **Caller headers.** A caller `x-amz-content-sha256` is replaced by the
  payload hash, so the header and the canonical request can never
  disagree. Asking to sign a header the request does not carry is an
  error, because the signature could never verify.
- **Fragments.** A URL fragment is never sent, so it is dropped from the
  signed request and the presigned URL.
- **Debug products and the session token (S25, F15).** The canonical
  request contains the token when one is signed: it is a signed header and
  is on the wire anyway, and the exact text is what you diff against AWS.
  `getCanonicalRequest()` returns it unchanged;
  `getRedactedCanonicalRequest()` and every `__debugInfo()` replace it with
  `[redacted]`. The secret and the signing key never appear anywhere.
- **Expired credentials from a provider (C19).** Returned, with a warning.
  The caching provider keeps them in memory only and fetches again on the
  next call.
- **Retry status codes (F-retry).** The PRD names 403. JSON-protocol
  services (DynamoDB, Kinesis) answer an expired token with 400
  `ExpiredTokenException`, so `ErrorInfo::isExpiredCredentials()` accepts
  400 and 403. It still retries exactly once.
- **Container token file.** One trailing CR or LF is trimmed (common in
  hand-written files); any other line break is refused (C5).
- **IMDS session token reuse (C8).** Reused until 60 seconds before its
  TTL ends (or half the TTL, when the TTL is under two minutes).

## Names that differ from the PRD

| PRD | Code | Reason |
|---|---|---|
| `sigv4.php` bootstrap | `bootstrap.php` | The engineering brief for every Indian Opinion library names it `bootstrap.php`. Same behaviour: registers a PSR-4 autoloader and nothing else. |
| `Clock`, `SystemClock`, `FrozenClock` | `Clock\Clock`, `Clock\SystemClock`, `Clock\FrozenClock` | Grouped like the other modules. |
| `Request` constructor from PSR-7 | `Psr7\Psr7Adapter` | Decision 2 below. |
| Provider "not found" signal | `CredentialsNotFoundException` | A typed exception carries the reason the chain needs, and cannot be ignored by accident the way a null can. |
| Forced refresh on `CachingProvider` | `RefreshableProvider::refresh()` | `RetryOnExpired` needs only the interface. |
| Default chain factory | `Credentials\DefaultChain::create()` | |
| `Cache\ArrayCache`, `ApcuCache`, `EncryptedCache` | plus `FileCache` and `Psr16Cache` | Decision 6 below. |
| S19 "add token after signing" option | not shipped | Decision 1 below. |

## Decisions on the open questions (PRD section 13)

1. **Session token placement.** The token is always signed: as the
   `X-Amz-Security-Token` header, or as a query parameter inside the
   canonical query string when presigning. There is no post-signing append
   in 0.1.0. The IAM guide says some services want the token added after
   signing but names none, and the AWS SDKs sign it for every service. The
   one case we know of, presigned WebSocket URLs for AWS IoT Core, is not a
   supported service here: it needs no AWS call from PHP, only a URL, and
   a caller can append the token to the output of `presign()` signed with
   token-less credentials. The official vector `post-sts-header-after`
   is passed exactly that way in the test suite.
2. **PSR-7.** A separate adapter class inside the package,
   `Psr7\Psr7Adapter`. It works only when the PSR-7 interfaces are present
   at run time (`interface_exists` check, then a typed error) and adds no
   dependency. `fromPsr7()` builds a `Request`; `applyTo()` and
   `applyPresigned()` copy the result back onto a PSR-7 request.
3. **Shared config files and web identity.** Out of 0.1.0, listed under
   "Not yet" in the README and CHANGELOG. The cost of adding them later:
   an INI parser that matches the AWS rules for profiles and `source_profile`
   chains, an STS call (which means the library would start making signed
   requests of its own and parsing XML responses), and a token file reader
   for web identity. They fit as new providers behind the same interface;
   nothing in 0.1.0 has to change.
4. **Container full URI allowlist.** https is allowed to any host. Plain
   http is allowed only to `localhost`, any IPv4 loopback address
   (127.0.0.0/8), the IPv6 loopback `::1`, and the documented container
   hosts `169.254.170.2` (ECS), `169.254.170.23` and `fd00:ec2::23` (EKS Pod
   Identity). This mirrors the AWS SDKs: botocore's
   `ContainerMetadataFetcher._validate_allowed_url` (https, or a loopback
   address, or one of `169.254.170.2`, `169.254.170.23`, `fd00:ec2::23`,
   `localhost`), and the Go SDK v2's `isAllowedHost` in
   `config/resolve_credentials.go` (loopback, or one of the three container
   IPs). IP addresses are compared in binary form, so
   `fd00:ec2:0:0:0:0:0:23` matches too. Unlike the Go SDK we do not resolve
   host names: a name other than `localhost` is refused for http, which is
   stricter and needs no DNS.
5. **IMDS session token.** Process memory only. It is useless off the
   instance but it is still a capability, and fetching a new one costs one
   local request.
6. **APCu.** Shipped in 0.1.0 as `Cache\ApcuCache`, guarded by
   `extension_loaded('apcu')` and `apcu_enabled()`, alongside the in-memory
   `ArrayCache`, a `FileCache` (atomic writes, mode 0600) and a
   `Psr16Cache` that wraps any PSR-16 object by duck typing, with no
   dependency. Every adapter is reached only through `EncryptedCache`:
   `CachingProvider` accepts nothing else for its shared cache.
7. **IMDS timeouts.** Connect 1 second, total 2 seconds, one retry when the
   transport gets no answer at all, then a clear "not on EC2" not-found
   (with the hop-limit hint when it timed out). All three are constructor
   options. Basis: botocore defaults to a 1 second timeout and one attempt
   for instance metadata (`DEFAULT_METADATA_SERVICE_TIMEOUT = 1`); IMDS is a
   link-local service that answers in milliseconds even on a busy
   instance, so 1 second is generous for the connect. The one retry covers
   a dropped packet at the cost of at most one more connect timeout off
   EC2; non-EC2 users should disable IMDS (`AWS_EC2_METADATA_DISABLED=true`
   or `useInstanceMetadata: false`) and pay nothing.
8. **Strict presign expiry.** On by default. The expiry must be 1 to
   604800 seconds whatever the mode (P2, always enforced). Strict mode also
   refuses an expiry that outlives temporary credentials (P3), because
   such a URL silently stops working early. With
   `strictPresignExpiry: false` the URL is signed, the shorter effective
   expiry is returned, and a warning is logged. Credentials that have
   already expired are refused in both modes.

## S3 documentation points checked

The PRD relied on two S3 documentation points that the reviewer could not
confirm. On 11 November 2026 the S3 API Reference SigV4 pages
(`sig-v4-header-based-auth.html`, `sigv4-query-string-auth.html`) redirect
to the API Reference welcome page, so they were read from the Internet
Archive copies of December 2025 and cross-checked against current pages.

1. **S3 paths are encoded once and not normalised.** Confirmed. The
   archived S3 page says: "You do not normalize URI paths for requests to
   Amazon S3. For example, you may have a bucket with an object named
   `my-object//example//photo.user`. Normalizing the path changes the
   object name". The current IAM guide ("Create a signed AWS API request")
   says to encode `/` everywhere except in the object key name. The
   double-encoding rule for other services is shown by the official test
   suite. Tests: `testS3S3PathIsNotNormalised`,
   `testP7S3KeyWithDoubleSlashIsNotNormalised`, and the S3 PUT example
   with key `test$file.text`.
2. **Presign expiry limits and temporary credentials.** Confirmed. The
   archived S3 page says of `X-Amz-Expires`: "The minimum value you can
   set is 1, and the maximum is 604800 (seven days)", and that for S3 the
   payload hash in a presigned canonical request is `UNSIGNED-PAYLOAD` and
   the canonical query includes `X-Amz-Security-Token`. The current S3 User
   Guide ("Download and upload objects with presigned URLs") says a URL
   created with temporary credentials "expires when the credential
   expires ... even if the URL was created with a later expiration time".

The S3 worked examples on those pages (GET object with `Range`, PUT
object, GET bucket lifecycle, list objects, and the presigned GET) are in
`tests/AwsDocumentedExamplesTest.php` and all pass.

## Testing

- 38 official vectors from `awslabs/aws-c-auth` (Apache-2.0, commit
  `bdb7cef`), header and query variants: 76 cases.
- Every case in PRD section 12.2 maps to at least one test; test names
  carry the case id (`testS16...`, `testC14...`, `testK11...`).
- `SecretLeakTest` drives every failure path with marked secrets and scans
  every exception message, log line and debug dump.
- No test reaches the network. The fake transport replays scripted
  responses; the only socket opened is to a closed loopback port.
