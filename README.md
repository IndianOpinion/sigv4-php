# sigv4-php

[![CI](https://github.com/IndianOpinion/sigv4-php/actions/workflows/ci.yml/badge.svg)](https://github.com/IndianOpinion/sigv4-php/actions/workflows/ci.yml)

AWS Signature Version 4 signing, presigned URLs and an instance-role
credential chain for PHP 8.1+, with no runtime dependencies. Use it when
you make a handful of AWS calls (send an email, put an object, read a
parameter) and do not want the AWS SDK, its dependency tree or a `vendor/`
directory.

Measured result: in production on indianopinion.org, a signer and IMDSv2
credential reader like this one has carried every AWS call the site makes,
on an instance role with no static access key on the machine, with no SDK.
This library passes all 38 official AWS SigV4 test vectors, in both the
header and the presigned variants.

This project came out of the work on indianopinion.org and is written from
scratch; it is independent of and not affiliated with any third-party
plugin it integrates with.

## When to use the AWS SDK instead

Use the [AWS SDK for PHP](https://aws.amazon.com/sdk-for-php/) when you
call many services, or need retries with backoff and jitter, paginators,
waiters, streaming or chunked uploads, SigV4A (multi-region access
points), SSO, `credential_process`, or the shared `~/.aws/config` and
`~/.aws/credentials` files. This library will not grow into any of those.

## Install

With Composer:

```sh
composer require indianopinion/sigv4-php
```

Without Composer (a WordPress plugin, a cron script, a host with no
Composer): copy the repository, or just `bootstrap.php` and `src/`, and
require one file.

```php
require __DIR__ . '/sigv4-php/bootstrap.php';
```

PHP 8.1 or later. `hash` and `json` are always present. `curl` is used for
credential fetches when loaded (PHP streams otherwise). `sodium` is needed
only for the encrypted shared cache, `apcu` only for the APCu adapter.

## Quick start: sign a request

```php
use IndianOpinion\SigV4\Credentials\DefaultChain;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;

$credentials = DefaultChain::create()->getCredentials(); // env, container, then instance role

$request = new Request(
    'POST',
    'https://email.eu-west-2.amazonaws.com/v2/email/outbound-emails',
    ['Content-Type' => 'application/json'],
    json_encode($message, JSON_THROW_ON_ERROR),
);

$signed = (new Signer())->sign($request, $credentials, 'eu-west-2', 'ses');

$ch = curl_init($signed->getUrl());
curl_setopt_array($ch, [
    CURLOPT_CUSTOMREQUEST => $signed->getMethod(),
    CURLOPT_HTTPHEADER => $signed->getHeaderLines(),
    CURLOPT_POSTFIELDS => $signed->getBody(),
    CURLOPT_RETURNTRANSFER => true,
]);
$body = curl_exec($ch);
```

The signer never sends anything. It returns the method, URL, headers and
body to send with whatever HTTP client you already use.

For S3, use the service name `s3`: the path is encoded once and not
normalised, and `x-amz-content-sha256` is added for you. When you hold a
raw object key, let the library encode it so nothing is encoded twice:

```php
$request = Request::fromRawPath('PUT', 'https://my-bucket.s3.eu-west-2.amazonaws.com', 'reports/annual report.pdf', [], [
    'Content-Type' => 'application/pdf',
], $pdfBytes);
$signed = $signer->sign($request, $credentials, 'eu-west-2', 's3');
```

For a large file, hash it yourself and pass `Payload::fromHash(hash_file('sha256', $path))`,
or pass `Payload::unsigned()` (S3 only).

## Quick start: presign a URL

```php
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;

$url = (new Signer())->presign(
    Request::fromRawPath('GET', 'https://my-bucket.s3.eu-west-2.amazonaws.com', 'photos/cat.jpg'),
    $credentials,
    'eu-west-2',
    's3',
    3600, // seconds, 1 to 604800
)->getUrl();
```

A presigned URL is a bearer token: anyone who has it can use it until it
expires. With temporary credentials (an instance or container role) a URL
cannot outlive the credentials that signed it, so the signer refuses such
an expiry by default; see `strictPresignExpiry` below.

More: [examples/sign-request.php](examples/sign-request.php) and
[examples/presign-url.php](examples/presign-url.php). Both run offline
against fake endpoints.

## Credentials chain

`DefaultChain::create()` tries these in order. The first that answers wins.

| # | Provider | Reads | "Not found" when | Stops the chain when |
|---|---|---|---|---|
| 1 | `StaticProvider` | credentials you pass in code | (only added when you pass some) | (validated at construction) |
| 2 | `EnvironmentProvider` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` via `getenv()`, `$_ENV`, `$_SERVER` | neither key variable is set | only one of the pair is set |
| 3 | `ContainerProvider` | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, else `AWS_CONTAINER_CREDENTIALS_FULL_URI`; token from `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` or `AWS_CONTAINER_AUTHORIZATION_TOKEN` | neither URI variable is set (no network call) | refused host, bad token, endpoint error or bad JSON |
| 4 | `InstanceMetadataProvider` | EC2 instance metadata, IMDSv2 only | not on EC2 (no answer within the timeout), or `AWS_EC2_METADATA_DISABLED=true` | IMDSv2 refused, no role attached, bad response |

The result is wrapped in a `CachingProvider`: credentials are kept in
memory and refreshed five minutes before they expire. You can build any
other order with `new ChainProvider([...])`.

A "not found" moves on; anything else stops the chain and is raised,
because silently falling through to a different identity is worse than
failing. When nothing is found, the exception lists every provider and why
it declined.

Off EC2, disable instance metadata so a laptop or CI run does not wait for
the metadata timeout: set `AWS_EC2_METADATA_DISABLED=true`, or pass
`useInstanceMetadata: false` to `DefaultChain::create()`.

## Configuration

| Setting | Where | Default | Notes |
|---|---|---|---|
| Extra signed headers | `SigningOptions(signHeaders: [...])` | `host`, `x-amz-*`, `content-type` (presign: `host`) | Hop-by-hop and volatile headers (`connection`, `user-agent`, `expect`, `x-amzn-trace-id`, ...) are never signed |
| S3 rules | `SigningOptions(s3Style: true)` | on for service `s3` | Single encoding, no normalisation, `x-amz-content-sha256` |
| Path normalisation | `SigningOptions(normalizePath: ...)` | off for S3 style, on otherwise | |
| `x-amz-content-sha256` | `SigningOptions(addContentSha256: true)` | S3 style only | |
| Sign with the request's own date | `SigningOptions(useRequestDate: true)` | off | Otherwise a stale `x-amz-date` is replaced |
| Strict presign expiry | `SigningOptions(strictPresignExpiry: false)` | on | Refuse an expiry past the credentials' expiry |
| Session token after signing | `SigningOptions(sessionTokenAfterSigning: true)` | off | Token sent but not signed |
| Presign expiry | `presign(..., $expires)` | 900 s | 1 to 604800 |
| Clock offset | `new SystemClock(offsetSeconds)` | 0 s | For hosts whose clock drifts |
| Refresh margin | `CachingProvider(marginSeconds: ...)` | 300 s | |
| Minimum shared-cache TTL | `CachingProvider(minSharedTtl: ...)` | 60 s | Below this, memory only |
| Shared cache key | `CachingProvider(cacheKey: ...)` | `indianopinion.sigv4.credentials.v1` | One key per identity in a shared store |
| Shared cache | `CachingProvider(sharedCache: new EncryptedCache(...))` | none | Encrypted only |
| IMDS endpoint | `AWS_EC2_METADATA_SERVICE_ENDPOINT`, `AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE=IPv6` | `http://169.254.169.254` | |
| IMDS disabled | `AWS_EC2_METADATA_DISABLED=true` | false | |
| IMDS role | `InstanceMetadataProvider(roleName: ...)` | discovered once, then remembered | Saves the listing request |
| IMDS token TTL | `InstanceMetadataProvider(tokenTtl: ...)` | 21600 s | 1 to 21600 |
| IMDS timeouts and retry | `InstanceMetadataProvider(connectTimeout:, timeout:, retries:)` | 1 s, 2 s, 1 | |
| Container timeouts | `ContainerProvider(connectTimeout:, timeout:)` | 1 s, 3 s | |
| Max credential response | `maxResponseBytes:` on both providers | 64 KiB | |
| Logger | `logger:` on signer, providers and caches | none | Any callable `(level, message, context)`; a PSR-3 logger works as `[$logger, 'log']` |

## Sharing credentials between PHP-FPM workers

Each PHP-FPM request starts with an empty memory cache, so on EC2 each
request would fetch credentials again (two or three local calls of a few
milliseconds). To share them, give the caching provider an encrypted
shared cache. Credentials in shared storage are always encrypted
(libsodium secretbox) with a key derived from an application secret you
supply; a database dump or cache snapshot alone does not yield usable
keys.

```php
use IndianOpinion\SigV4\Cache\ApcuCache;
use IndianOpinion\SigV4\Cache\EncryptedCache;
use IndianOpinion\SigV4\Credentials\DefaultChain;

$provider = DefaultChain::create(
    sharedCache: new EncryptedCache(new ApcuCache(), $appSecret), // at least 16 bytes
);
```

Shipped adapters: `ApcuCache`, `FileCache($directory)`, `Psr16Cache($anyPsr16Cache)`
and `ArrayCache`. Static and environment credentials are never written to
a shared cache.

A WordPress transient adapter is four methods. Implement
`IndianOpinion\SigV4\Cache\CredentialCache`: `get()` returns
`get_transient($key)` when it is a string and null otherwise; `set()` calls
`set_transient($key, $value, $ttl)`; `delete()` returns
`delete_transient($key)`. Wrap it in `EncryptedCache` with a salt such as
`wp_salt('auth')`. The encrypted cache already treats an empty or
unreadable value as a miss, which covers object caches whose delete is not
reliable. For any PSR-16 cache, `new Psr16Cache($cache)` is all you need.

## Retrying once after an expired token

```php
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\RetryOnExpired;
use IndianOpinion\SigV4\SignedRequest;

$retry = new RetryOnExpired(new Signer(), $provider);
$response = $retry->send($request, 'eu-west-2', 'ses', function (SignedRequest $signed): HttpResponse {
    // send it with your client, then:
    return new HttpResponse($status, $headers, $body);
});
```

If AWS answers with `ExpiredToken`, `ExpiredTokenException`,
`InvalidClientTokenId` or `UnrecognizedClientException`, the helper
refreshes the credentials, signs again and sends exactly once more. Never
twice. `ErrorInfo::fromResponse($status, $headers, $body)` gives you the
error type and request id for anything else.

## How to debug a 403

1. Read the error type: `ErrorInfo::fromResponse(...)->getType()`.
2. `RequestTimeTooSkewed` (or `ErrorInfo::isClockSkew()` is true): the
   host clock is more than 15 minutes off.
   Fix NTP, or set an offset with `new SystemClock($seconds)` from the
   response `Date` header.
3. `SignatureDoesNotMatch`: AWS puts its canonical request in the error
   body. Compare it with `$signed->getDetails()->getCanonicalRequest()`.
   The usual causes: a path encoded twice by the caller (use
   `Request::fromRawPath()`), a header changed after signing (a proxy, or
   your client adding `Content-Type`), or a different body.
4. `ExpiredToken` and friends: use `RetryOnExpired`, or refresh.

Log `getRedactedCanonicalRequest()`, not `getCanonicalRequest()`: the
redacted form hides the session token.

## How it works

The signer follows the AWS documentation step by step: canonical request,
string to sign, HMAC key derivation over date, region and service, then
the signature. It reads the clock once, so the timestamp and the scope date
can never disagree across midnight. It is pure: same input, same clock,
same bytes. The core algorithm is about a hundred lines inside `Signer`;
the whole library, with validation, presigning, providers, caches and
transports, is about 2,900 lines of code.

Credential fetches use a small transport with no proxy (even when
`HTTP_PROXY` is set), no redirects, TLS verification always on, short
timeouts and a 64 KiB response cap. Instance metadata is IMDSv2 only: a
token PUT, then the role, then the credentials, with the role name
validated before it goes into a URL. A container full URI over plain http
is allowed only to loopback and the documented container hosts.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the modules, data flow and
every design decision. [docs/PRD.md](docs/PRD.md) has the requirements.

## Limitations

- No shared config or credentials files, SSO, `credential_process` or web
  identity yet (see "Not yet" in the [CHANGELOG](CHANGELOG.md)).
- No chunked (`aws-chunked`) payload signing, no SigV4A, no SigV2.
- No retries other than the single refresh-and-resend helper.
- The session token is signed by default, as every AWS SDK does. For a
  service that documents the unsigned form, pass
  `SigningOptions(sessionTokenAfterSigning: true)`.
- `+` in a query string is a literal plus, as AWS reads it. Encode spaces
  as `%20`.
- Secret parameters are marked `#[\SensitiveParameter]`, which hides
  them from stack traces on PHP 8.2 and later. On PHP 8.1 set
  `zend.exception_ignore_args=On` (the production php.ini default) so a
  trace never prints the start of a secret.
- The stream transport has a single timeout (used for the total); curl
  honours connect and total separately.

## FAQ

**Is "about a hundred lines" true?** For the signing algorithm, yes. The
library as a whole is larger, because a credential chain that fails
loudly, encrypted caching and careful transports take more code than the
signature.

**Why does my S3 key with spaces fail?** You probably encoded it and then
passed it to `fromRawPath()`, or passed a raw key inside a URL string.
Pick one: a wire URL with `new Request()`, or a raw key with
`Request::fromRawPath()`.

**Does it work with S3-compatible stores (MinIO, Ceph and others)?** Yes, for
those that implement SigV4. Use service `s3` and the region the store
expects (often `us-east-1` or `auto`). Path-style and virtual-hosted URLs
both work, since the URL is signed as given.

**Can it fall back to IMDSv1?** No, never. IMDSv1 is the version that
server-side request forgery abuses.

**My container on EC2 cannot reach instance metadata.** The token request
times out when the metadata hop limit is 1. Set it to 2 on the instance;
the error message says so.

**How do I remove the cached credentials?** Call
`$provider->invalidate()`, or delete the key `indianopinion.sigv4.credentials.v1`
(or your own `cacheKey`) from your store. The entry is encrypted and
expires on its own within hours anyway.

**Is it safe to log signed requests?** Log `getHeaderMap()` without
`Authorization` and `X-Amz-Security-Token`, or use `print_r`/`var_dump`,
which redact the token. The secret key and signing key are never in any
output.

## Licence

The library is MIT licensed: see [LICENSE](LICENSE). Copyright (c) 2026
Indian Opinion.

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

The official AWS SigV4 test vectors in `tests/fixtures/aws-sig-v4/` are
copied unmodified from [awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth)
and are licensed under the Apache License 2.0; that folder carries its own
`LICENSE` and `NOTICE`. They are test data only and are not included in the
Composer package.
