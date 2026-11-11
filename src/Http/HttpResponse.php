<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Http;

/**
 * A response: status, headers (lower-case names), body, and for transport
 * failures a status of 0 with an error string.
 */
final class HttpResponse
{
    /** @var array<string, string> */
    public readonly array $headers;

    /**
     * @param array<string, string|list<string>> $headers names in any case; repeated values are joined with ", "
     * @param string $error transport error, empty when the request reached the server
     * @param bool $timedOut the transport gave up waiting (connect or total timeout)
     */
    public function __construct(
        public readonly int $status,
        array $headers = [],
        public readonly string $body = '',
        public readonly string $error = '',
        public readonly bool $timedOut = false,
    ) {
        $normalised = [];
        foreach ($headers as $name => $value) {
            $lower = strtolower((string) $name);
            $value = is_array($value) ? implode(', ', $value) : $value;
            $normalised[$lower] = isset($normalised[$lower]) ? $normalised[$lower] . ', ' . $value : $value;
        }
        $this->headers = $normalised;
    }

    public static function failure(string $error, bool $timedOut = false): self
    {
        return new self(0, [], '', $error, $timedOut);
    }

    /**
     * True when the transport did not get an HTTP answer at all.
     */
    public function isTransportError(): bool
    {
        return $this->status === 0;
    }

    public function getHeader(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
