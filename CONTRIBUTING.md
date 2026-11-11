# Contributing to sigv4-php

Thank you for helping. This library is small on purpose, and every change
is judged against that: a correct signer that someone can read in one
sitting, and a credential chain that fails loudly.

## Setup

You need PHP 8.1 or later with `curl` and `sodium` (both are bundled with
most PHP builds) and Composer 2.

```sh
git clone https://github.com/IndianOpinion/sigv4-php.git
cd sigv4-php
composer install
```

## Checks

Run all of these before you open a pull request. CI runs the same ones on
PHP 8.1, 8.2, 8.3 and 8.4.

```sh
vendor/bin/phpunit          # tests, including all 38 official AWS vectors
vendor/bin/phpstan analyse  # level 8
vendor/bin/phpcs            # PSR-12
composer check              # all three
```

No test touches the network. Providers are tested against
`Http\FakeTransport`, and every signing test uses `Clock\FrozenClock`.
The only socket a test opens is a connection to a closed loopback port, to
check that transports report failure without throwing.

## Style

- PSR-12, enforced by phpcs. `declare(strict_types=1);` in every file.
- No runtime dependencies. A new `require` entry needs a very good reason.
- Typed exceptions that extend `SigV4Exception`. Never return `false` for
  an error, never use `@`, never swallow an exception silently.
- No secret key, session token, signing key or container token in any
  exception message, log line or debug output. `tests/SecretLeakTest.php`
  checks this; extend it when you add a failure path.
- Prose: short sentences, plain words, British spelling. No em dashes.

## Tests

- A bug fix comes with a test that fails before the fix.
- A behaviour change points to the case number in `docs/PRD.md` (S, P, C,
  K, T or F) and updates `docs/ARCHITECTURE.md` when a decision changes.
- The files under `tests/fixtures/aws-sig-v4/` are the official AWS
  vectors under Apache-2.0. Do not edit them. To update them, copy a newer
  upstream commit unmodified and change the commit id in that folder's
  README.

## Pull requests

- One topic per pull request. Keep it small enough to review in one go.
- Describe what changes and why, and how you tested it.
- Add a line to the `Unreleased` section of `CHANGELOG.md`.
- A sign-off line (DCO) is not required.
- Security problems go to hello@indianopinion.org, not to a pull request.
  See `SECURITY.md`.

By contributing you agree that your contribution is licensed under the MIT
licence of this project.
