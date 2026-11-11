<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Http;

/**
 * A credential-endpoint request: what a transport is asked to send.
 *
 * Transports always send it with no proxy, no redirects and TLS
 * verification on. None of that is configurable, on purpose.
 */
final class HttpRequest
{
    public const DEFAULT_MAX_RESPONSE_BYTES = 65536;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly string $method,
        public readonly string $url,
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly float $connectTimeout = 1.0,
        public readonly float $timeout = 2.0,
        public readonly int $maxResponseBytes = self::DEFAULT_MAX_RESPONSE_BYTES,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        $headers = [];
        foreach ($this->headers as $name => $value) {
            $lower = strtolower($name);
            $secret = $lower === 'authorization' || $lower === 'x-aws-ec2-metadata-token';
            $headers[$name] = $secret ? '[redacted]' : $value;
        }

        return [
            'method' => $this->method,
            'url' => $this->url,
            'headers' => $headers,
            'bodyBytes' => strlen($this->body),
            'connectTimeout' => $this->connectTimeout,
            'timeout' => $this->timeout,
            'maxResponseBytes' => $this->maxResponseBytes,
        ];
    }
}
