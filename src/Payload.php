<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

use IndianOpinion\SigV4\Exception\InvalidRequestException;

/**
 * The body of a request, as the signer sees it.
 *
 * Three kinds:
 * - a string body, hashed as raw bytes (binary safe);
 * - a precomputed SHA-256 hash (64 lower-case hex characters) of a body you
 *   send yourself, for example a large file hashed in a streaming loop;
 * - the unsigned marker, signed as `UNSIGNED-PAYLOAD` (S3; other services
 *   decide for themselves whether they accept it).
 */
final class Payload
{
    public const UNSIGNED = 'UNSIGNED-PAYLOAD';
    public const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    private const KIND_BODY = 'body';
    private const KIND_HASH = 'hash';
    private const KIND_UNSIGNED = 'unsigned';

    private function __construct(
        private readonly string $kind,
        private readonly string $body,
        private readonly string $hash,
    ) {
    }

    public static function fromString(string $body): self
    {
        return new self(self::KIND_BODY, $body, $body === '' ? self::EMPTY_SHA256 : hash('sha256', $body));
    }

    public static function empty(): self
    {
        return new self(self::KIND_BODY, '', self::EMPTY_SHA256);
    }

    /**
     * @throws InvalidRequestException when the hash is not 64 lower-case hex characters
     */
    public static function fromHash(string $sha256Hex): self
    {
        if (preg_match('/^[0-9a-f]{64}$/D', $sha256Hex) !== 1) {
            throw new InvalidRequestException('A precomputed payload hash must be 64 lower-case hex characters.');
        }

        return new self(self::KIND_HASH, '', $sha256Hex);
    }

    public static function unsigned(): self
    {
        return new self(self::KIND_UNSIGNED, '', self::UNSIGNED);
    }

    /**
     * The value used on the last line of the canonical request and in
     * `x-amz-content-sha256`.
     */
    public function getHash(): string
    {
        return $this->hash;
    }

    /**
     * The body to send. Empty for a precomputed hash or the unsigned marker:
     * in those cases the caller sends the body itself.
     */
    public function getBody(): string
    {
        return $this->body;
    }

    public function hasBody(): bool
    {
        return $this->kind === self::KIND_BODY;
    }

    public function isUnsigned(): bool
    {
        return $this->kind === self::KIND_UNSIGNED;
    }

    public function isPrecomputed(): bool
    {
        return $this->kind === self::KIND_HASH;
    }
}
