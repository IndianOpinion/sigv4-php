<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

/**
 * The result of presigning: a URL anyone can use until it expires.
 *
 * Treat it as a bearer token. If you asked for extra headers to be signed,
 * whoever uses the URL must send those headers with exactly those values
 * ({@see PresignedUrl::getHeadersToSend()}).
 */
final class PresignedUrl
{
    /**
     * @param list<array{0: string, 1: string}> $headersToSend
     */
    public function __construct(
        private readonly string $url,
        private readonly string $method,
        private readonly int $requestedExpires,
        private readonly int $effectiveExpires,
        private readonly \DateTimeImmutable $signedAt,
        private readonly array $headersToSend,
        private readonly SigningDetails $details,
        #[\SensitiveParameter] private readonly ?string $sessionToken = null,
    ) {
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * The `X-Amz-Expires` value in the URL.
     */
    public function getRequestedExpires(): int
    {
        return $this->requestedExpires;
    }

    /**
     * Seconds the URL will really work: shorter than the requested expiry
     * when temporary credentials expire first.
     */
    public function getEffectiveExpires(): int
    {
        return $this->effectiveExpires;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->signedAt->modify(sprintf('+%d seconds', $this->effectiveExpires));
    }

    /**
     * Signed headers other than `host` that the user of the URL must send.
     *
     * @return list<array{0: string, 1: string}>
     */
    public function getHeadersToSend(): array
    {
        return $this->headersToSend;
    }

    public function getDetails(): SigningDetails
    {
        return $this->details;
    }

    public function __toString(): string
    {
        return $this->url;
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'url' => SigningDetails::redact($this->url, $this->sessionToken),
            'method' => $this->method,
            'requestedExpires' => $this->requestedExpires,
            'effectiveExpires' => $this->effectiveExpires,
            'headersToSend' => $this->headersToSend,
            'details' => $this->details,
        ];
    }
}
