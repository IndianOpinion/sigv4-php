<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

/**
 * The result of signing: the method, URL, headers and body to send.
 *
 * Headers are the request's own headers in their original order (minus any
 * stale `Authorization` or replaced `x-amz-*` values), followed by the
 * headers the signer added.
 */
final class SignedRequest
{
    /**
     * @param list<array{0: string, 1: string}> $headers
     */
    public function __construct(
        private readonly string $method,
        private readonly string $url,
        private readonly array $headers,
        private readonly string $body,
        private readonly SigningDetails $details,
        private readonly ?string $sessionToken = null,
    ) {
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * @return list<array{0: string, 1: string}>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Headers as `Name: value` lines, ready for CURLOPT_HTTPHEADER or a
     * stream context.
     *
     * @return list<string>
     */
    public function getHeaderLines(): array
    {
        $lines = [];
        foreach ($this->headers as [$name, $value]) {
            $lines[] = $name . ': ' . $value;
        }

        return $lines;
    }

    /**
     * Headers as a map. Repeated headers are joined with `, `. Names keep
     * the case of their first occurrence.
     *
     * @return array<string, string>
     */
    public function getHeaderMap(): array
    {
        $map = [];
        $names = [];
        foreach ($this->headers as [$name, $value]) {
            $lower = strtolower($name);
            if (!isset($names[$lower])) {
                $names[$lower] = $name;
                $map[$name] = $value;
            } else {
                $map[$names[$lower]] .= ', ' . $value;
            }
        }

        return $map;
    }

    /**
     * The first value of a header, matched case-insensitively.
     */
    public function getHeader(string $name): ?string
    {
        $name = strtolower($name);
        foreach ($this->headers as [$n, $v]) {
            if (strtolower($n) === $name) {
                return $v;
            }
        }

        return null;
    }

    public function getBody(): string
    {
        return $this->body;
    }

    public function getAuthorization(): string
    {
        return (string) $this->getHeader('Authorization');
    }

    public function getDetails(): SigningDetails
    {
        return $this->details;
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        $headers = [];
        foreach ($this->headers as [$name, $value]) {
            $headers[] = [$name, SigningDetails::redact($value, $this->sessionToken)];
        }

        return [
            'method' => $this->method,
            'url' => $this->url,
            'headers' => $headers,
            'bodyBytes' => strlen($this->body),
            'details' => $this->details,
        ];
    }
}
