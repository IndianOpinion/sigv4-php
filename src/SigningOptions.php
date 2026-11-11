<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

/**
 * Per-call signing options. Every option has a safe default; pass only what
 * you need, with named arguments.
 *
 * ```php
 * new SigningOptions(signHeaders: ['content-md5'], s3Style: true);
 * ```
 */
final class SigningOptions
{
    /** @var list<string> */
    private readonly array $signHeaders;

    /**
     * @param list<string> $signHeaders extra headers to sign, on top of `host`, every `x-amz-*` header and
     *                                  `content-type` (header signing) or `host` alone (presigning). Hop-by-hop and
     *                                  volatile headers are never signed, even when listed here.
     * @param bool|null $s3Style true for S3 rules (path encoded once, not normalised, `x-amz-content-sha256` added).
     *                           Null means "true when the service is s3".
     * @param bool|null $normalizePath remove `.` and `..` segments and repeated slashes. Null means "not S3-style".
     * @param bool|null $doubleEncodePath encode each wire path segment once more. Null means "not S3-style".
     * @param bool|null $addContentSha256 add and sign `x-amz-content-sha256`. Null means "S3-style only".
     * @param bool $useRequestDate sign with the time in the request's `x-amz-date` (or `date`) header instead of
     *                             the clock. Off by default, so a stale header copied from elsewhere never signs.
     * @param bool $strictPresignExpiry when presigning with temporary credentials, refuse an expiry that outlives
     *                                  the credentials. On by default; when off the URL is signed and the shorter,
     *                                  effective expiry is returned and logged.
     * @param bool $sessionTokenAfterSigning add the session token after signing, so it is sent (as the
     *                                       `X-Amz-Security-Token` header or query parameter) but not signed. Off
     *                                       by default: every AWS SDK signs the token. Only for a service that
     *                                       documents the unsigned form.
     */
    public function __construct(
        array $signHeaders = [],
        private readonly ?bool $s3Style = null,
        private readonly ?bool $normalizePath = null,
        private readonly ?bool $doubleEncodePath = null,
        private readonly ?bool $addContentSha256 = null,
        private readonly bool $useRequestDate = false,
        private readonly bool $strictPresignExpiry = true,
        private readonly bool $sessionTokenAfterSigning = false,
    ) {
        $names = [];
        foreach ($signHeaders as $name) {
            $names[] = strtolower(trim($name));
        }
        $this->signHeaders = $names;
    }

    /**
     * @return list<string> lower-cased
     */
    public function getSignHeaders(): array
    {
        return $this->signHeaders;
    }

    public function isS3Style(string $service): bool
    {
        return $this->s3Style ?? ($service === 's3');
    }

    public function shouldNormalizePath(string $service): bool
    {
        return $this->normalizePath ?? !$this->isS3Style($service);
    }

    public function shouldDoubleEncodePath(string $service): bool
    {
        return $this->doubleEncodePath ?? !$this->isS3Style($service);
    }

    public function shouldAddContentSha256(string $service): bool
    {
        return $this->addContentSha256 ?? $this->isS3Style($service);
    }

    public function useRequestDate(): bool
    {
        return $this->useRequestDate;
    }

    public function isStrictPresignExpiry(): bool
    {
        return $this->strictPresignExpiry;
    }

    public function isSessionTokenAfterSigning(): bool
    {
        return $this->sessionTokenAfterSigning;
    }
}
