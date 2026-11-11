## What and why

## PRD cases

Which cases in `docs/PRD.md` this touches (for example S2, C14, K11).

## Checklist

- [ ] `vendor/bin/phpunit` passes
- [ ] `vendor/bin/phpstan analyse` passes (level 8)
- [ ] `vendor/bin/phpcs` passes (PSR-12)
- [ ] New failure paths are covered by `tests/SecretLeakTest.php`
- [ ] `CHANGELOG.md` has a line under `Unreleased`
- [ ] `docs/ARCHITECTURE.md` updated if a decision changed
- [ ] No real credentials, hostnames or account ids anywhere
