<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Credentials;

/**
 * Explicit credentials passed in code. Validation happens when the
 * Credentials object is built, not at signing time.
 */
final class StaticProvider implements Provider
{
    public function __construct(private readonly Credentials $credentials)
    {
    }

    public static function fromKeys(
        string $accessKeyId,
        string $secretAccessKey,
        ?string $sessionToken = null,
        ?\DateTimeImmutable $expiresAt = null,
    ): self {
        return new self(new Credentials($accessKeyId, $secretAccessKey, $sessionToken, $expiresAt, 'static'));
    }

    public function getCredentials(): Credentials
    {
        return $this->credentials;
    }
}
