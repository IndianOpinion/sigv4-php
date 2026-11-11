<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

use IndianOpinion\SigV4\Clock\Clock;
use IndianOpinion\SigV4\Clock\SystemClock;
use IndianOpinion\SigV4\Exception\InvalidRequestException;
use IndianOpinion\SigV4\Internal\Logger;
use IndianOpinion\SigV4\Internal\Uri;

/**
 * AWS Signature Version 4 (AWS4-HMAC-SHA256).
 *
 * Signs a request with an Authorization header, or presigns it as a URL.
 * The signer is pure: it never sends anything, and the same request,
 * credentials and clock reading always give the same bytes.
 */
final class Signer
{
    public const ALGORITHM = 'AWS4-HMAC-SHA256';
    public const MIN_PRESIGN_EXPIRY = 1;
    public const MAX_PRESIGN_EXPIRY = 604800;
    public const DEFAULT_PRESIGN_EXPIRY = 900;

    /**
     * Hop-by-hop and volatile headers. Proxies and load balancers change
     * them, so signing them breaks signatures; AWS says not to sign them.
     */
    public const NEVER_SIGN = [
        'connection',
        'keep-alive',
        'transfer-encoding',
        'te',
        'trailer',
        'upgrade',
        'proxy-authorization',
        'proxy-authenticate',
        'user-agent',
        'expect',
        'x-amzn-trace-id',
    ];

    private const PRESIGN_PARAMS = [
        'x-amz-algorithm',
        'x-amz-credential',
        'x-amz-date',
        'x-amz-expires',
        'x-amz-signedheaders',
        'x-amz-security-token',
        'x-amz-signature',
    ];

    private const MEMO_LIMIT = 16;

    private readonly Clock $clock;
    private readonly Logger $logger;

    /** @var array<string, string> derived signing keys, keyed by a hash of (secret, date, region, service) */
    private array $keyMemo = [];

    /**
     * @param (callable(string, string, array<string, mixed>): mixed)|null $logger
     *        PSR-3-shaped: (level, message, context)
     */
    public function __construct(?Clock $clock = null, ?callable $logger = null)
    {
        $this->clock = $clock ?? new SystemClock();
        $this->logger = new Logger($logger);
    }

    /**
     * Signs a request with the Authorization header variant.
     *
     * @throws InvalidRequestException before any hashing when an input is not valid
     */
    public function sign(
        Request $request,
        Credentials $credentials,
        string $region,
        string $service,
        ?SigningOptions $options = null,
    ): SignedRequest {
        $options ??= new SigningOptions();
        self::checkScopePart($region, 'region');
        self::checkScopePart($service, 'service');
        $this->checkHostHeader($request);

        $s3Style = $options->isS3Style($service);
        $payload = $request->getPayload() ?? Payload::empty();
        $payloadHash = $payload->getHash();
        $token = $credentials->getSessionToken();

        $now = $options->useRequestDate() ? self::dateFromRequest($request) : $this->clock->now();
        $amzDate = self::formatAmzDate($now);
        $scope = self::credentialScope($amzDate, $region, $service);

        $addContentSha = $options->shouldAddContentSha256($service) || $request->hasHeader('x-amz-content-sha256');
        $replace = ['authorization' => true, 'x-amz-date' => true];
        if ($token !== null) {
            $replace['x-amz-security-token'] = true;
        }
        if ($addContentSha) {
            $replace['x-amz-content-sha256'] = true;
        }

        $headers = [];
        foreach ($request->getHeaders() as [$name, $value]) {
            if (!isset($replace[strtolower($name)])) {
                $headers[] = [$name, $value];
            }
        }
        $headers[] = ['X-Amz-Date', $amzDate];
        if ($token !== null) {
            $headers[] = ['X-Amz-Security-Token', $token];
        }
        if ($addContentSha) {
            $headers[] = ['X-Amz-Content-Sha256', $payloadHash];
        }

        $toSign = ['host' => true];
        foreach ($headers as [$name]) {
            $lower = strtolower($name);
            if (str_starts_with($lower, 'x-amz-') || $lower === 'content-type') {
                $toSign[$lower] = true;
            }
        }
        $toSign = $this->addRequestedHeaders($toSign, $options->getSignHeaders(), $headers);

        [$canonicalHeaders, $signedHeaders] = self::canonicalHeaders($headers, $toSign, $request->getHostHeaderValue());

        $canonicalRequest = implode("\n", [
            $request->getMethod(),
            self::canonicalUri($request, $options, $service),
            Uri::canonicalQuery(Uri::parseQuery($request->getQuery())),
            $canonicalHeaders,
            $signedHeaders,
            $payloadHash,
        ]);
        $stringToSign = self::stringToSign($amzDate, $scope, $canonicalRequest);
        $signature = $this->signature($credentials, $amzDate, $region, $service, $stringToSign);

        $headers[] = [
            'Authorization',
            sprintf(
                '%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
                self::ALGORITHM,
                $credentials->getAccessKeyId(),
                $scope,
                $signedHeaders,
                $signature,
            ),
        ];

        $details = new SigningDetails(
            $canonicalRequest,
            $stringToSign,
            $signedHeaders,
            $scope,
            $amzDate,
            $payloadHash,
            $signature,
            $token,
        );
        $this->logger->debug('Signed request', [
            'method' => $request->getMethod(),
            'host' => $request->getHost(),
            'service' => $service,
            'region' => $region,
            'accessKeyId' => $credentials->getAccessKeyId(),
            'credentialSource' => $credentials->getSource(),
            's3Style' => $s3Style,
        ]);

        return new SignedRequest(
            $request->getMethod(),
            $request->getUrl(),
            $headers,
            $request->getBody(),
            $details,
            $token,
        );
    }

    /**
     * Presigns a request as a URL (the query-string variant).
     *
     * @param int $expires seconds, 1 to 604800 (seven days)
     *
     * @throws InvalidRequestException when an input is not valid, the expiry is out of range, the URL is already
     *                                 presigned, or (strict mode, the default) the credentials expire first
     */
    public function presign(
        Request $request,
        Credentials $credentials,
        string $region,
        string $service,
        int $expires = self::DEFAULT_PRESIGN_EXPIRY,
        ?SigningOptions $options = null,
    ): PresignedUrl {
        $options ??= new SigningOptions();
        self::checkScopePart($region, 'region');
        self::checkScopePart($service, 'service');
        $this->checkHostHeader($request);
        if ($expires < self::MIN_PRESIGN_EXPIRY || $expires > self::MAX_PRESIGN_EXPIRY) {
            throw new InvalidRequestException(sprintf(
                'Presign expiry must be between %d and %d seconds; %d was given.',
                self::MIN_PRESIGN_EXPIRY,
                self::MAX_PRESIGN_EXPIRY,
                $expires,
            ));
        }

        $existing = Uri::parseQuery($request->getQuery());
        foreach ($existing as [$name]) {
            if (in_array(strtolower($name), self::PRESIGN_PARAMS, true)) {
                throw new InvalidRequestException(sprintf(
                    'The URL already carries the signing parameter "%s"; '
                    . 'presigning a presigned URL is always a mistake.',
                    $name,
                ));
            }
        }

        $now = $options->useRequestDate() ? self::dateFromRequest($request) : $this->clock->now();
        $effective = $expires;
        $left = $credentials->secondsUntilExpiry($now);
        if ($left !== null) {
            if ($left <= 0) {
                throw new InvalidRequestException(
                    'The credentials have already expired; refresh them before presigning.'
                );
            }
            if ($left < $expires) {
                if ($options->isStrictPresignExpiry()) {
                    throw new InvalidRequestException(sprintf(
                        'The credentials expire in %d seconds, before the requested expiry of %d seconds. '
                        . 'Ask for a shorter expiry, or turn strict presign expiry off to accept the shorter lifetime.',
                        $left,
                        $expires,
                    ));
                }
                $effective = $left;
                $this->logger->warning('Presigned URL lifetime capped by credential expiry', [
                    'requestedExpires' => $expires,
                    'effectiveExpires' => $effective,
                    'credentialSource' => $credentials->getSource(),
                ]);
            }
        }

        $amzDate = self::formatAmzDate($now);
        $scope = self::credentialScope($amzDate, $region, $service);
        $token = $credentials->getSessionToken();

        $headers = $request->getHeaders();
        $toSign = $this->addRequestedHeaders(['host' => true], $options->getSignHeaders(), $headers);
        [$canonicalHeaders, $signedHeaders] = self::canonicalHeaders($headers, $toSign, $request->getHostHeaderValue());

        $added = [
            ['X-Amz-Algorithm', self::ALGORITHM],
            ['X-Amz-Credential', $credentials->getAccessKeyId() . '/' . $scope],
            ['X-Amz-Date', $amzDate],
            ['X-Amz-Expires', (string) $expires],
            ['X-Amz-SignedHeaders', $signedHeaders],
        ];
        if ($token !== null) {
            $added[] = ['X-Amz-Security-Token', $token];
        }

        $payload = $request->getPayload();
        if ($payload !== null) {
            $payloadHash = $payload->getHash();
        } else {
            $payloadHash = $options->isS3Style($service) ? Payload::UNSIGNED : Payload::EMPTY_SHA256;
        }

        $canonicalRequest = implode("\n", [
            $request->getMethod(),
            self::canonicalUri($request, $options, $service),
            Uri::canonicalQuery(array_merge($existing, $added)),
            $canonicalHeaders,
            $signedHeaders,
            $payloadHash,
        ]);
        $stringToSign = self::stringToSign($amzDate, $scope, $canonicalRequest);
        $signature = $this->signature($credentials, $amzDate, $region, $service, $stringToSign);

        $base = $request->getUrl();
        $query = $request->getQuery();
        if ($query !== '') {
            $base = substr($base, 0, -strlen($query) - 1);
        }
        $url = $base . '?' . ($query !== '' ? $query . '&' : '')
            . Uri::buildQuery($added) . '&X-Amz-Signature=' . $signature;

        $headersToSend = [];
        foreach ($headers as [$name, $value]) {
            $lower = strtolower($name);
            if ($lower !== 'host' && isset($toSign[$lower])) {
                $headersToSend[] = [$name, $value];
            }
        }

        $details = new SigningDetails(
            $canonicalRequest,
            $stringToSign,
            $signedHeaders,
            $scope,
            $amzDate,
            $payloadHash,
            $signature,
            $token,
        );
        $this->logger->debug('Presigned URL', [
            'method' => $request->getMethod(),
            'host' => $request->getHost(),
            'service' => $service,
            'region' => $region,
            'accessKeyId' => $credentials->getAccessKeyId(),
            'credentialSource' => $credentials->getSource(),
            'effectiveExpires' => $effective,
        ]);

        return new PresignedUrl(
            $url,
            $request->getMethod(),
            $expires,
            $effective,
            $now->setTimezone(new \DateTimeZone('UTC')),
            $headersToSend,
            $details,
            $token,
        );
    }

    /**
     * Derives the SigV4 signing key (raw bytes) from a secret, a date
     * (YYYYMMDD), a region and a service.
     */
    public static function deriveSigningKey(
        #[\SensitiveParameter] string $secretAccessKey,
        string $date,
        string $region,
        string $service,
    ): string {
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretAccessKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);

        return hash_hmac('sha256', 'aws4_request', $kService, true);
    }

    private function signature(
        Credentials $credentials,
        string $amzDate,
        string $region,
        string $service,
        string $stringToSign,
    ): string {
        $date = substr($amzDate, 0, 8);
        $memoKey = hash('sha256', $credentials->getSecretAccessKey() . "\0" . $date . "\0" . $region . "\0" . $service);
        if (!isset($this->keyMemo[$memoKey])) {
            if (count($this->keyMemo) >= self::MEMO_LIMIT) {
                $this->keyMemo = [];
            }
            $this->keyMemo[$memoKey] = self::deriveSigningKey(
                $credentials->getSecretAccessKey(),
                $date,
                $region,
                $service,
            );
        }

        return hash_hmac('sha256', $stringToSign, $this->keyMemo[$memoKey]);
    }

    private static function stringToSign(string $amzDate, string $scope, string $canonicalRequest): string
    {
        return implode("\n", [self::ALGORITHM, $amzDate, $scope, hash('sha256', $canonicalRequest)]);
    }

    private static function credentialScope(string $amzDate, string $region, string $service): string
    {
        return substr($amzDate, 0, 8) . '/' . $region . '/' . $service . '/aws4_request';
    }

    /**
     * One clock reading gives both the timestamp and the scope date, so a
     * call that crosses midnight UTC can never disagree with itself.
     */
    private static function formatAmzDate(\DateTimeImmutable $now): string
    {
        return $now->setTimezone(new \DateTimeZone('UTC'))->format('Ymd\THis\Z');
    }

    private static function canonicalUri(Request $request, SigningOptions $options, string $service): string
    {
        $normalize = $options->shouldNormalizePath($service);
        if ($options->shouldDoubleEncodePath($service)) {
            return Uri::canonicalPathDoubleEncoded($request->getPath(), $normalize);
        }

        return Uri::canonicalPathSingleEncoded($request->getPath(), $normalize);
    }

    /**
     * @param array<string, true> $toSign
     * @param list<string> $requested
     * @param list<array{0: string, 1: string}> $headers
     *
     * @return array<string, true>
     */
    private function addRequestedHeaders(array $toSign, array $requested, array $headers): array
    {
        $present = ['host' => true];
        foreach ($headers as [$name]) {
            $present[strtolower($name)] = true;
        }
        foreach ($requested as $name) {
            if (in_array($name, self::NEVER_SIGN, true)) {
                $this->logger->debug('Header not signed: hop-by-hop or volatile headers are never signed', [
                    'header' => $name,
                ]);
                continue;
            }
            if (!isset($present[$name])) {
                throw new InvalidRequestException(sprintf(
                    'Header "%s" was listed for signing but the request does not carry it.',
                    $name,
                ));
            }
            $toSign[$name] = true;
        }
        foreach (self::NEVER_SIGN as $name) {
            unset($toSign[$name]);
        }

        return $toSign;
    }

    /**
     * @param list<array{0: string, 1: string}> $headers
     * @param array<string, true> $toSign
     *
     * @return array{0: string, 1: string} canonical header block (with trailing newline) and signed header list
     */
    private static function canonicalHeaders(array $headers, array $toSign, string $hostValue): array
    {
        $values = ['host' => [$hostValue]];
        foreach ($headers as [$name, $value]) {
            $lower = strtolower($name);
            if ($lower === 'host' || !isset($toSign[$lower])) {
                continue;
            }
            $values[$lower][] = trim((string) preg_replace('/\s+/', ' ', $value));
        }
        ksort($values, SORT_STRING);
        $lines = '';
        foreach ($values as $name => $list) {
            $lines .= $name . ':' . implode(',', $list) . "\n";
        }

        return [$lines, implode(';', array_keys($values))];
    }

    private function checkHostHeader(Request $request): void
    {
        $expected = $request->getHostHeaderValue();
        $defaultPort = $request->getScheme() === 'https' ? 443 : 80;
        foreach ($request->getHeaderValues('host') as $value) {
            $value = strtolower(trim($value));
            if ($value !== $expected && $value !== $expected . ':' . $defaultPort) {
                throw new InvalidRequestException(sprintf(
                    'The Host header "%s" disagrees with the URL host "%s"; the transport sends the URL host.',
                    $value,
                    $expected,
                ));
            }
        }
    }

    private static function checkScopePart(string $value, string $what): void
    {
        if (preg_match('/^[a-z0-9-]+$/D', $value) !== 1) {
            throw new InvalidRequestException(sprintf(
                'The %s must be lower-case letters, digits and hyphens, and not empty.',
                $what,
            ));
        }
    }

    private static function dateFromRequest(Request $request): \DateTimeImmutable
    {
        $utc = new \DateTimeZone('UTC');
        $amz = $request->getHeaderValues('x-amz-date');
        if ($amz !== []) {
            $parsed = \DateTimeImmutable::createFromFormat('Ymd\THis\Z', trim($amz[0]), $utc);
            if ($parsed === false) {
                throw new InvalidRequestException('The x-amz-date header is not in the YYYYMMDDTHHMMSSZ format.');
            }

            return $parsed;
        }
        $date = $request->getHeaderValues('date');
        if ($date !== []) {
            $parsed = \DateTimeImmutable::createFromFormat(\DateTimeInterface::RFC7231, trim($date[0]), $utc);
            if ($parsed === false) {
                throw new InvalidRequestException('The Date header is not an RFC 7231 date.');
            }

            return $parsed;
        }
        throw new InvalidRequestException('useRequestDate is set but the request has no x-amz-date or Date header.');
    }
}
