<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

use IndianOpinion\SigV4\Http\HttpResponse;

/**
 * Extracts the AWS error type and request id from a response you received.
 *
 * The type comes from, in order: the `x-amzn-ErrorType` header (anything
 * after `:` stripped), a JSON `__type` (everything up to `#` stripped), an
 * XML `<Code>` element (S3 and query-protocol services), else `HTTP<status>`.
 * The request id comes from `x-amzn-RequestId` or `x-amz-request-id`.
 */
final class ErrorInfo
{
    public const EXPIRED_CREDENTIAL_TYPES = [
        'ExpiredToken',
        'ExpiredTokenException',
        'InvalidClientTokenId',
        'UnrecognizedClientException',
    ];

    public const CLOCK_SKEW_TYPES = [
        'RequestTimeTooSkewed',
        'RequestExpired',
    ];

    /**
     * Types that some services use both for a bad signature and for a
     * request time out of range. They count as clock skew only when the
     * message says the signature expired or is not yet current.
     */
    public const SIGNATURE_TYPES = [
        'InvalidSignatureException',
        'SignatureDoesNotMatch',
    ];

    private function __construct(
        private readonly int $status,
        private readonly string $type,
        private readonly ?string $requestId,
        private readonly bool $timeMessage = false,
    ) {
    }

    /**
     * @param array<string, string|list<string>> $headers names in any case
     */
    public static function fromResponse(int $status, array $headers, string $body): self
    {
        $lower = [];
        foreach ($headers as $name => $value) {
            $lower[strtolower((string) $name)] = is_array($value) ? (string) ($value[0] ?? '') : $value;
        }

        $type = null;
        $header = trim($lower['x-amzn-errortype'] ?? '');
        if ($header !== '') {
            $type = explode(':', $header, 2)[0];
        }
        if ($type === null || $type === '') {
            $type = self::fromJson($body);
        }
        if ($type === null || $type === '') {
            $type = self::fromXml($body);
        }
        if ($type === null || $type === '') {
            $type = 'HTTP' . $status;
        }

        $requestId = $lower['x-amzn-requestid'] ?? $lower['x-amz-request-id'] ?? null;
        $requestId = $requestId === null || trim($requestId) === '' ? null : trim($requestId);

        $timeMessage = preg_match('/signature (has )?expired|signature not yet current/i', $body) === 1;

        return new self($status, self::clean($type), $requestId, $timeMessage);
    }

    public static function fromHttpResponse(HttpResponse $response): self
    {
        return self::fromResponse($response->status, $response->headers, $response->body);
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getRequestId(): ?string
    {
        return $this->requestId;
    }

    /**
     * True for an expired or unrecognised credential answer (status 400 or 403).
     */
    public function isExpiredCredentials(): bool
    {
        return in_array($this->status, [400, 403], true) && in_array($this->type, self::EXPIRED_CREDENTIAL_TYPES, true);
    }

    /**
     * True when AWS rejected the request time. Correct the clock offset
     * from the response Date header; the library never does that itself.
     */
    public function isClockSkew(): bool
    {
        if (in_array($this->type, self::CLOCK_SKEW_TYPES, true)) {
            return true;
        }

        return $this->timeMessage && in_array($this->type, self::SIGNATURE_TYPES, true);
    }

    private static function fromJson(string $body): ?string
    {
        $trimmed = ltrim($body);
        if ($trimmed === '' || $trimmed[0] !== '{') {
            return null;
        }
        try {
            $data = json_decode($trimmed, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!is_array($data)) {
            return null;
        }
        $type = $data['__type'] ?? $data['code'] ?? null;
        if (!is_string($type) || $type === '') {
            return null;
        }
        $hash = strrpos($type, '#');

        return $hash === false ? $type : substr($type, $hash + 1);
    }

    private static function fromXml(string $body): ?string
    {
        // A regular expression, not an XML parser: no entity expansion, no
        // external entities, nothing to configure.
        if (preg_match('#<Code>\s*([^<]{1,256}?)\s*</Code>#', $body, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    private static function clean(string $type): string
    {
        return substr((string) preg_replace('/[^A-Za-z0-9._-]/', '', $type), 0, 128);
    }
}
