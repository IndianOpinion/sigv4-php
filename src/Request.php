<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

use IndianOpinion\SigV4\Exception\InvalidRequestException;
use IndianOpinion\SigV4\Internal\Uri;

/**
 * An immutable HTTP request to be signed.
 *
 * The URL is the wire form: exactly what the HTTP client will send, already
 * percent-encoded. Use {@see Request::fromRawPath()} when you hold a raw path
 * (an S3 object key with spaces, say) and want the library to encode it, so
 * that nothing is ever encoded twice by accident.
 *
 * Headers are kept as a list of name and value pairs, in order, so repeated
 * headers survive. They can be given either as that list or as a map of
 * name to value (or list of values).
 */
final class Request
{
    private readonly string $method;
    private readonly string $url;
    private readonly string $scheme;
    private readonly string $host;
    private readonly ?int $port;
    private readonly string $path;
    private readonly string $query;
    /** @var list<array{0: string, 1: string}> */
    private readonly array $headers;
    private readonly ?Payload $payload;

    /**
     * @param array<array-key, mixed> $headers list of [name, value] pairs, or a map of name => value|list<value>
     * @param string|Payload|null $payload a string body, a Payload, or null for "no body, use the default"
     *
     * @throws InvalidRequestException
     */
    public function __construct(string $method, string $url, array $headers = [], string|Payload|null $payload = null)
    {
        $method = strtoupper(trim($method));
        if ($method === '') {
            throw new InvalidRequestException('The HTTP method is empty.');
        }
        if (preg_match('/^[!#$%&\'*+.^_`|~0-9A-Z-]+$/D', $method) !== 1) {
            throw new InvalidRequestException('The HTTP method contains characters that are not allowed.');
        }
        $this->method = $method;

        if (preg_match('/[\x00-\x1F\x7F]/', $url) === 1) {
            throw new InvalidRequestException('The URL contains a control character.');
        }
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new InvalidRequestException('The URL must be absolute, with a scheme and a host.');
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new InvalidRequestException('The URL scheme must be http or https.');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidRequestException('The URL must not carry a user name or password.');
        }
        $host = strtolower($parts['host']);
        if ($host === '' || preg_match('/^(\[[0-9a-f:.]+\]|[a-z0-9._~%!$&\'()*+,;=-]+)$/D', $host) !== 1) {
            throw new InvalidRequestException('The URL host is not valid.');
        }
        $port = $parts['port'] ?? null;
        if (($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80)) {
            $port = null;
        }
        $this->scheme = $scheme;
        $this->host = $host;
        $this->port = $port;
        $this->path = $parts['path'] ?? '';
        $this->query = $parts['query'] ?? '';
        $this->url = $scheme . '://' . $this->getHostHeaderValue() . $this->path
            . ($this->query !== '' ? '?' . $this->query : '');

        $this->headers = self::normaliseHeaders($headers);
        $this->payload = is_string($payload) ? Payload::fromString($payload) : $payload;
    }

    /**
     * Builds a request from a raw (not yet encoded) path. Each path segment
     * is encoded once for the wire; `/` separates segments and is kept.
     *
     * @param string $endpoint scheme, host and optional port, for example `https://bucket.s3.eu-west-2.amazonaws.com`
     * @param array<array-key, mixed> $query list of [name, value] pairs (repeats allowed), or a map of name => value
     * @param array<array-key, mixed> $headers
     *
     * @throws InvalidRequestException
     */
    public static function fromRawPath(
        string $method,
        string $endpoint,
        string $rawPath,
        array $query = [],
        array $headers = [],
        string|Payload|null $payload = null,
    ): self {
        $endpointParts = parse_url($endpoint);
        if ($endpointParts === false || isset($endpointParts['query']) || isset($endpointParts['fragment'])) {
            throw new InvalidRequestException('The endpoint must be a scheme, a host and an optional port.');
        }
        if (isset($endpointParts['path']) && $endpointParts['path'] !== '' && $endpointParts['path'] !== '/') {
            throw new InvalidRequestException('The endpoint must not carry a path; pass the path separately.');
        }
        $endpoint = rtrim($endpoint, '/');
        if ($rawPath !== '' && $rawPath[0] !== '/') {
            $rawPath = '/' . $rawPath;
        }
        $url = $endpoint . Uri::encodePath($rawPath);
        $pairs = self::normaliseQuery($query);
        if ($pairs !== []) {
            $url .= '?' . Uri::buildQuery($pairs);
        }

        return new self($method, $url, $headers, $payload);
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * The wire URL (without any fragment).
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    public function getScheme(): string
    {
        return $this->scheme;
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function getPort(): ?int
    {
        return $this->port;
    }

    /**
     * The value of the Host header the transport will send: the host, plus
     * `:port` when the port is not the scheme's default.
     */
    public function getHostHeaderValue(): string
    {
        return $this->port === null ? $this->host : $this->host . ':' . $this->port;
    }

    /**
     * The wire path, as it appears in the URL. Empty when the URL has none.
     */
    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * The wire query string, without the `?`.
     */
    public function getQuery(): string
    {
        return $this->query;
    }

    /**
     * @return list<array{0: string, 1: string}>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * All values of a header, matched case-insensitively, in order.
     *
     * @return list<string>
     */
    public function getHeaderValues(string $name): array
    {
        $name = strtolower($name);
        $values = [];
        foreach ($this->headers as [$n, $v]) {
            if (strtolower($n) === $name) {
                $values[] = $v;
            }
        }

        return $values;
    }

    public function hasHeader(string $name): bool
    {
        return $this->getHeaderValues($name) !== [];
    }

    /**
     * The payload, or null when none was given (the signer then picks the
     * default: the empty-body hash, or `UNSIGNED-PAYLOAD` when presigning
     * for S3).
     */
    public function getPayload(): ?Payload
    {
        return $this->payload;
    }

    /**
     * The body bytes to send ('' when the payload is a hash, unsigned, or absent).
     */
    public function getBody(): string
    {
        return $this->payload === null ? '' : $this->payload->getBody();
    }

    /**
     * @param array<array-key, mixed> $headers
     */
    public function withHeaders(array $headers): self
    {
        return new self($this->method, $this->url, $headers, $this->payload);
    }

    public function withPayload(string|Payload|null $payload): self
    {
        return new self($this->method, $this->url, $this->headers, $payload);
    }

    /**
     * @param array<array-key, mixed> $headers
     *
     * @return list<array{0: string, 1: string}>
     */
    private static function normaliseHeaders(array $headers): array
    {
        $out = [];
        if (array_is_list($headers)) {
            foreach ($headers as $pair) {
                if (!is_array($pair) || count($pair) !== 2 || !isset($pair[0], $pair[1])) {
                    throw new InvalidRequestException('Headers given as a list must be [name, value] pairs.');
                }
                $out[] = self::checkHeader($pair[0], $pair[1]);
            }

            return $out;
        }
        foreach ($headers as $name => $value) {
            $values = is_array($value) ? $value : [$value];
            foreach ($values as $v) {
                $out[] = self::checkHeader((string) $name, $v);
            }
        }

        return $out;
    }

    /**
     * @return array{0: string, 1: string}
     */
    private static function checkHeader(mixed $name, mixed $value): array
    {
        if (!is_string($name) || preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/D', $name) !== 1) {
            throw new InvalidRequestException('A header name is empty or contains characters that are not allowed.');
        }
        if (is_int($value) || is_float($value)) {
            $value = (string) $value;
        }
        if (!is_string($value)) {
            throw new InvalidRequestException(sprintf('The value of header "%s" must be a string.', $name));
        }
        // CR and LF are allowed only as obsolete line folding (a line break
        // followed by a space or tab). Anything else could inject a header.
        if (
            preg_match('/[\x00\x7F]|[\x01-\x08\x0B\x0C\x0E-\x1F]/', $value) === 1
            || preg_match('/\r(?!\n)|\r?\n(?![ \t])/', $value) === 1
        ) {
            throw new InvalidRequestException(sprintf('The value of header "%s" contains a control character.', $name));
        }

        return [$name, $value];
    }

    /**
     * @param array<array-key, mixed> $query
     *
     * @return list<array{0: string, 1: string}>
     */
    private static function normaliseQuery(array $query): array
    {
        $pairs = [];
        if (array_is_list($query)) {
            foreach ($query as $pair) {
                if (!is_array($pair) || !array_key_exists(0, $pair) || !is_scalar($pair[0])) {
                    throw new InvalidRequestException('Query parameters given as a list must be [name, value] pairs.');
                }
                $value = $pair[1] ?? '';
                if (!is_scalar($value)) {
                    throw new InvalidRequestException('Query parameter values must be strings.');
                }
                $pairs[] = [(string) $pair[0], (string) $value];
            }

            return $pairs;
        }
        foreach ($query as $name => $value) {
            if ($value === null) {
                $value = '';
            }
            if (!is_scalar($value)) {
                throw new InvalidRequestException('Query parameter values must be strings.');
            }
            $pairs[] = [(string) $name, (string) $value];
        }

        return $pairs;
    }
}
