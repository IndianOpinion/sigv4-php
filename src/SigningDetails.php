<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

/**
 * The intermediate products of one signature, for debugging a 403 and for
 * the test suite. None of them contains the secret key or the signing key.
 *
 * The canonical request contains the session token when one was signed,
 * because the token is a signed header (or query parameter) and is sent on
 * the wire anyway. Use {@see SigningDetails::getRedactedCanonicalRequest()}
 * for anything that goes to a log; debug output uses it automatically.
 */
final class SigningDetails
{
    public function __construct(
        private readonly string $canonicalRequest,
        private readonly string $stringToSign,
        private readonly string $signedHeaders,
        private readonly string $credentialScope,
        private readonly string $amzDate,
        private readonly string $payloadHash,
        private readonly string $signature,
        #[\SensitiveParameter] private readonly ?string $sessionToken = null,
    ) {
    }

    public function getCanonicalRequest(): string
    {
        return $this->canonicalRequest;
    }

    /**
     * The canonical request with the session token replaced by `[redacted]`.
     */
    public function getRedactedCanonicalRequest(): string
    {
        return self::redact($this->canonicalRequest, $this->sessionToken);
    }

    public function getStringToSign(): string
    {
        return $this->stringToSign;
    }

    /**
     * Semicolon-separated, lower-case, sorted.
     */
    public function getSignedHeaders(): string
    {
        return $this->signedHeaders;
    }

    public function getCredentialScope(): string
    {
        return $this->credentialScope;
    }

    public function getAmzDate(): string
    {
        return $this->amzDate;
    }

    public function getPayloadHash(): string
    {
        return $this->payloadHash;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'canonicalRequest' => $this->getRedactedCanonicalRequest(),
            'stringToSign' => $this->stringToSign,
            'signedHeaders' => $this->signedHeaders,
            'credentialScope' => $this->credentialScope,
            'amzDate' => $this->amzDate,
            'payloadHash' => $this->payloadHash,
            'signature' => $this->signature,
        ];
    }

    /**
     * @internal
     */
    public static function redact(string $text, #[\SensitiveParameter] ?string $token): string
    {
        if ($token === null || $token === '') {
            return $text;
        }

        return str_replace([$token, rawurlencode($token)], '[redacted]', $text);
    }
}
