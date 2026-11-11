<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

use IndianOpinion\SigV4\Exception\ConfigurationException;

/**
 * An immutable set of AWS credentials.
 *
 * Holds the access key id, the secret access key, an optional session token,
 * an optional expiry (absolute, UTC) and a source label for logs (`static`,
 * `env`, `container`, `imds`, or any label you choose). Credentials without
 * an expiry never expire.
 *
 * The string form and debug output never show the secret or the token.
 */
final class Credentials
{
    private readonly ?\DateTimeImmutable $expiresAt;

    /**
     * @throws ConfigurationException when the key id or secret is empty, or a value carries a control character
     */
    public function __construct(
        private readonly string $accessKeyId,
        #[\SensitiveParameter] private readonly string $secretAccessKey,
        #[\SensitiveParameter] private readonly ?string $sessionToken = null,
        ?\DateTimeImmutable $expiresAt = null,
        private readonly string $source = 'static',
    ) {
        if ($accessKeyId === '' || $secretAccessKey === '') {
            throw new ConfigurationException('Credentials need a non-empty access key id and secret access key.');
        }
        if (preg_match('/[\x00-\x20\x7F]/', $accessKeyId) === 1) {
            throw new ConfigurationException('The access key id contains whitespace or a control character.');
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $secretAccessKey) === 1) {
            throw new ConfigurationException('The secret access key contains a control character.');
        }
        if ($sessionToken !== null && ($sessionToken === '' || preg_match('/[\x00-\x1F\x7F]/', $sessionToken) === 1)) {
            throw new ConfigurationException('The session token is empty or contains a control character.');
        }
        $this->expiresAt = $expiresAt?->setTimezone(new \DateTimeZone('UTC'));
    }

    public function getAccessKeyId(): string
    {
        return $this->accessKeyId;
    }

    public function getSecretAccessKey(): string
    {
        return $this->secretAccessKey;
    }

    public function getSessionToken(): ?string
    {
        return $this->sessionToken;
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function getSource(): string
    {
        return $this->source;
    }

    public function isTemporary(): bool
    {
        return $this->sessionToken !== null || $this->expiresAt !== null;
    }

    /**
     * True when the credentials must be refreshed: they have an expiry and
     * `expiry - margin` is not after `now`.
     */
    public function needsRefresh(\DateTimeImmutable $now, int $marginSeconds = 0): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt->getTimestamp() - $marginSeconds <= $now->getTimestamp();
    }

    /**
     * Seconds left before expiry, or null when the credentials never expire.
     * Negative when already expired.
     */
    public function secondsUntilExpiry(\DateTimeImmutable $now): ?int
    {
        return $this->expiresAt === null ? null : $this->expiresAt->getTimestamp() - $now->getTimestamp();
    }

    /**
     * A copy without the session token. Only useful for unusual signing flows.
     */
    public function withoutSessionToken(): self
    {
        return new self($this->accessKeyId, $this->secretAccessKey, null, $this->expiresAt, $this->source);
    }

    public function __toString(): string
    {
        return sprintf(
            'Credentials(%s, source=%s, token=%s, expires=%s)',
            $this->accessKeyId,
            $this->source,
            $this->sessionToken === null ? 'no' : 'yes',
            $this->expiresAt === null ? 'never' : $this->expiresAt->format('Y-m-d\TH:i:s\Z'),
        );
    }

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return [
            'accessKeyId' => $this->accessKeyId,
            'secretAccessKey' => '[redacted]',
            'sessionToken' => $this->sessionToken === null ? null : '[redacted]',
            'expiresAt' => $this->expiresAt?->format('Y-m-d\TH:i:s\Z'),
            'source' => $this->source,
        ];
    }

    /**
     * Credentials are never serialised with PHP's serializer (the cache
     * stores encrypted JSON instead), so a stray serialize() cannot leak them.
     *
     * @return array<string, never>
     */
    public function __serialize(): array
    {
        throw new \LogicException('Credentials cannot be serialised.');
    }

    /**
     * @param array<string, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('Credentials cannot be unserialised.');
    }
}
