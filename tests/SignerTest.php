<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Clock\Clock;
use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Clock\SystemClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\InvalidRequestException;
use IndianOpinion\SigV4\Payload;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;
use IndianOpinion\SigV4\SigningOptions;
use IndianOpinion\SigV4\Tests\Support\RecordingLogger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Header-variant signing: cases S1 to S27 and F1.
 */
final class SignerTest extends TestCase
{
    private const SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    private const TIME = '2015-08-30T12:36:00Z';

    private function signer(?Clock $clock = null): Signer
    {
        return new Signer($clock ?? new FrozenClock(self::TIME));
    }

    private function credentials(?string $token = null): Credentials
    {
        return new Credentials('AKIDEXAMPLE', self::SECRET, $token);
    }

    private function canonical(Request $request, string $service = 'service', ?SigningOptions $options = null): string
    {
        return $this->signer()->sign($request, $this->credentials(), 'us-east-1', $service, $options)
            ->getDetails()->getCanonicalRequest();
    }

    /**
     * @return list<string>
     */
    private static function lines(string $canonical): array
    {
        return explode("\n", $canonical);
    }

    public function testS1MethodIsUpperCased(): void
    {
        $canonical = $this->canonical(new Request('get', 'https://example.amazonaws.com/'));
        self::assertSame('GET', self::lines($canonical)[0]);
    }

    public function testS1EmptyMethodThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        new Request('', 'https://example.amazonaws.com/');
    }

    public function testS2SegmentWithSpaceAndPercentIsDoubleEncoded(): void
    {
        $request = Request::fromRawPath('GET', 'https://example.amazonaws.com', '/a b/100%/c');
        self::assertSame('https://example.amazonaws.com/a%20b/100%25/c', $request->getUrl());
        self::assertSame('/a%2520b/100%2525/c', self::lines($this->canonical($request))[1]);
    }

    public function testS2WirePathIsNormalised(): void
    {
        $request = new Request('GET', 'https://example.amazonaws.com//a/./b/../c//');
        self::assertSame('/a/c/', self::lines($this->canonical($request))[1]);
    }

    public function testS3S3KeyIsEncodedOnce(): void
    {
        $request = Request::fromRawPath('PUT', 'https://bucket.s3.amazonaws.com', '/a b/c~d', [], [], 'x');
        self::assertSame('https://bucket.s3.amazonaws.com/a%20b/c~d', $request->getUrl());
        self::assertSame('/a%20b/c~d', self::lines($this->canonical($request, 's3'))[1]);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function s3Keys(): iterable
    {
        yield 'double slash' => ['/a//b'];
        yield 'dot segment' => ['/a/./b'];
        yield 'dot dot segment' => ['/a/../b'];
    }

    #[DataProvider('s3Keys')]
    public function testS3S3PathIsNotNormalised(string $path): void
    {
        $request = new Request('GET', 'https://bucket.s3.amazonaws.com' . $path);
        self::assertSame($path, self::lines($this->canonical($request, 's3'))[1]);
    }

    public function testS3S3StyleCanBeForcedForOtherServices(): void
    {
        $request = new Request('GET', 'https://store.example.com/a//b%20c');
        $canonical = $this->canonical($request, 'custom', new SigningOptions(s3Style: true));
        self::assertSame('/a//b%20c', self::lines($canonical)[1]);
    }

    public function testS3EncodedSlashInKeyIsDecodedLikeS3Does(): void
    {
        $request = new Request('GET', 'https://bucket.s3.amazonaws.com/photos%2FJan/a%7Eb');
        self::assertSame('/photos/Jan/a~b', self::lines($this->canonical($request, 's3'))[1]);
    }

    public function testS4EmptyPathSignsAsSlash(): void
    {
        self::assertSame('/', self::lines($this->canonical(new Request('GET', 'https://example.amazonaws.com')))[1]);
        self::assertSame('/', self::lines($this->canonical(new Request('GET', 'https://b.s3.amazonaws.com'), 's3'))[1]);
    }

    public function testS5EveryByteIsEncodedPerTheRule(): void
    {
        for ($byte = 0; $byte <= 0xFF; $byte++) {
            $char = chr($byte);
            $expected = preg_match('/^[A-Za-z0-9\-._~]$/', $char) === 1 ? $char : sprintf('%%%02X', $byte);
            $request = Request::fromRawPath('GET', 'https://example.amazonaws.com', '/', [['k', $char]]);
            $query = self::lines($this->canonical($request))[2];
            self::assertSame('k=' . $expected, $query, sprintf('byte 0x%02X', $byte));
        }
    }

    public function testS5SpaceTildeAndUtf8(): void
    {
        $request = Request::fromRawPath('GET', 'https://example.amazonaws.com', '/', [['a b', "~\u{1234}"]]);
        self::assertSame('a%20b=~%E1%88%B4', self::lines($this->canonical($request))[2]);
    }

    public function testS6QueryIsSortedOrdinallyAndCaseSensitively(): void
    {
        $request = new Request('GET', 'https://example.amazonaws.com/?b=1&B=2&a=3');
        self::assertSame('B=2&a=3&b=1', self::lines($this->canonical($request))[2]);
    }

    public function testS7RepeatedKeysAreKeptAndSortedByValue(): void
    {
        $request = new Request('GET', 'https://example.amazonaws.com/?a=2&a=1');
        self::assertSame('a=1&a=2', self::lines($this->canonical($request))[2]);

        $fromPairs = Request::fromRawPath('GET', 'https://example.amazonaws.com', '/', [['a', '2'], ['a', '1']]);
        self::assertSame('https://example.amazonaws.com/?a=2&a=1', $fromPairs->getUrl());
        self::assertSame('a=1&a=2', self::lines($this->canonical($fromPairs))[2]);
    }

    public function testS8EmptyValuesAndEmptyKeys(): void
    {
        $bare = $this->canonical(new Request('GET', 'https://b.s3.amazonaws.com/?acl'), 's3');
        $empty = $this->canonical(new Request('GET', 'https://b.s3.amazonaws.com/?acl='), 's3');
        self::assertSame('acl=', self::lines($bare)[2]);
        self::assertSame($bare, $empty);

        $emptyKey = $this->canonical(new Request('GET', 'https://example.amazonaws.com/?=value&a=1'));
        self::assertSame('=value&a=1', self::lines($emptyKey)[2]);
    }

    public function testS9EncodedAndLiteralTildeSignTheSameAndPlusStaysPlus(): void
    {
        $encoded = $this->canonical(new Request('GET', 'https://example.amazonaws.com/?k=%7Ea'));
        $literal = $this->canonical(new Request('GET', 'https://example.amazonaws.com/?k=~a'));
        self::assertSame($encoded, $literal);

        $plus = $this->canonical(new Request('GET', 'https://example.amazonaws.com/?k=a+b'));
        self::assertSame('k=a%2Bb', self::lines($plus)[2]);
    }

    public function testS10HeaderValuesAreTrimmedCollapsedFoldedAndJoined(): void
    {
        $request = new Request('GET', 'https://example.amazonaws.com/', [
            ['X-Amz-Meta-A', "  one   two  "],
            ['X-Amz-Meta-B', "first\r\n   second"],
            ['x-amz-meta-c', 'z'],
            ['X-Amz-Meta-C', 'y'],
        ]);
        $canonical = $this->canonical($request);
        self::assertStringContainsString("x-amz-meta-a:one two\n", $canonical);
        self::assertStringContainsString("x-amz-meta-b:first second\n", $canonical);
        self::assertStringContainsString("x-amz-meta-c:z,y\n", $canonical);
    }

    public function testS10HeaderInjectionIsRefused(): void
    {
        $this->expectException(InvalidRequestException::class);
        new Request('GET', 'https://example.amazonaws.com/', [['X-Amz-Meta-A', "a\r\nInjected: yes"]]);
    }

    public function testS11DefaultSignedHeaders(): void
    {
        $request = new Request('POST', 'https://example.amazonaws.com/', [
            'Content-Type' => 'application/json',
            'X-Amz-Target' => 'Service.Action',
            'Accept' => 'application/json',
        ], '{}');
        $signed = $this->signer()->sign($request, $this->credentials(), 'us-east-1', 'service');
        self::assertSame('content-type;host;x-amz-date;x-amz-target', $signed->getDetails()->getSignedHeaders());
    }

    public function testS11CallerMayAddHeadersButNeverHopByHopOnes(): void
    {
        $logger = new RecordingLogger();
        $signer = new Signer(new FrozenClock(self::TIME), $logger);
        $request = new Request('GET', 'https://example.amazonaws.com/', [
            'User-Agent' => 'test/1.0',
            'Connection' => 'keep-alive',
            'Range' => 'bytes=0-9',
        ]);
        $options = new SigningOptions(signHeaders: ['User-Agent', 'connection', 'range']);
        $signed = $signer->sign($request, $this->credentials(), 'us-east-1', 'service', $options);
        self::assertSame('host;range;x-amz-date', $signed->getDetails()->getSignedHeaders());
        self::assertCount(2, array_filter(
            $logger->level('debug'),
            static fn (array $r): bool => str_contains($r['message'], 'never signed'),
        ));
    }

    public function testS11AskingToSignAMissingHeaderThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->signer()->sign(
            new Request('GET', 'https://example.amazonaws.com/'),
            $this->credentials(),
            'us-east-1',
            'service',
            new SigningOptions(signHeaders: ['content-md5']),
        );
    }

    public function testS12DefaultPortOmittedOtherPortKept(): void
    {
        self::assertStringContainsString(
            "host:example.amazonaws.com\n",
            $this->canonical(new Request('GET', 'https://example.amazonaws.com:443/')),
        );
        self::assertStringContainsString(
            "host:example.amazonaws.com\n",
            $this->canonical(new Request('GET', 'http://example.amazonaws.com:80/')),
        );
        self::assertStringContainsString(
            "host:localhost:9000\n",
            $this->canonical(new Request('GET', 'http://localhost:9000/bucket/key'), 's3'),
        );
    }

    public function testS12MatchingHostHeaderIsAccepted(): void
    {
        $request = new Request('GET', 'https://example.amazonaws.com/', ['Host' => 'Example.amazonaws.com:443']);
        self::assertStringContainsString("host:example.amazonaws.com\n", $this->canonical($request));
    }

    public function testS12ConflictingHostHeaderThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->canonical(new Request('GET', 'https://example.amazonaws.com/', ['Host' => 'other.example.com']));
    }

    public function testS13NoContentTypeIsInvented(): void
    {
        $signed = $this->signer()->sign(
            new Request('POST', 'https://example.amazonaws.com/', [], 'Action=Send'),
            $this->credentials(),
            'us-east-1',
            'service',
        );
        self::assertStringNotContainsString('content-type', $signed->getDetails()->getSignedHeaders());
        self::assertNull($signed->getHeader('Content-Type'));
    }

    public function testS14EmptyBodyUsesTheEmptyStringHash(): void
    {
        foreach (['GET', 'HEAD', 'DELETE', 'POST'] as $method) {
            $canonical = $this->canonical(new Request($method, 'https://example.amazonaws.com/'));
            self::assertSame(Payload::EMPTY_SHA256, self::lines($canonical)[7]);
        }
    }

    public function testS15BinaryBodySignsAsRawBytes(): void
    {
        $body = "a\x00b\xff\xfe\xc3(\r\n";
        $signed = $this->signer()->sign(
            new Request('PUT', 'https://example.amazonaws.com/upload', [], $body),
            $this->credentials(),
            'us-east-1',
            'service',
        );
        // Reference values computed independently (Python hashlib and hmac).
        self::assertSame('35f8f6be4d1d3680ccddd815a03616f0e4c2e06dbf62f33db39fa9bc365e38c7', $signed->getDetails()->getPayloadHash());
        self::assertSame('7291e656219a1693fe017eaec1a4a71ab5d74ff15eb6620768027b21b761851b', $signed->getDetails()->getSignature());
        self::assertSame($body, $signed->getBody());
    }

    public function testS16PrecomputedHashIsUsedVerbatim(): void
    {
        $hash = hash('sha256', 'large file');
        $request = new Request('PUT', 'https://b.s3.amazonaws.com/k', [], Payload::fromHash($hash));
        $signed = $this->signer()->sign($request, $this->credentials(), 'us-east-1', 's3');
        self::assertSame($hash, self::lines($signed->getDetails()->getCanonicalRequest())[8]);
        self::assertSame($hash, $signed->getHeader('x-amz-content-sha256'));
        self::assertSame('', $signed->getBody());
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function badHashes(): iterable
    {
        yield '63 characters' => [substr(hash('sha256', 'x'), 0, 63)];
        yield 'upper case' => [strtoupper(hash('sha256', 'x'))];
        yield 'not hex' => [str_repeat('g', 64)];
        yield 'trailing newline' => [hash('sha256', 'x') . "\n"];
    }

    #[DataProvider('badHashes')]
    public function testS16BadHashesThrow(string $hash): void
    {
        $this->expectException(InvalidRequestException::class);
        Payload::fromHash($hash);
    }

    public function testS17UnsignedPayload(): void
    {
        $request = new Request('PUT', 'https://b.s3.amazonaws.com/k', [], Payload::unsigned());
        $signed = $this->signer()->sign($request, $this->credentials(), 'us-east-1', 's3');
        $lines = self::lines($signed->getDetails()->getCanonicalRequest());
        self::assertSame('UNSIGNED-PAYLOAD', end($lines));
        self::assertSame('UNSIGNED-PAYLOAD', $signed->getHeader('X-Amz-Content-Sha256'));
    }

    public function testS18ContentSha256AddedForS3Only(): void
    {
        $s3 = $this->signer()->sign(new Request('GET', 'https://b.s3.amazonaws.com/k'), $this->credentials(), 'us-east-1', 's3');
        self::assertSame('host;x-amz-content-sha256;x-amz-date', $s3->getDetails()->getSignedHeaders());
        self::assertSame(Payload::EMPTY_SHA256, $s3->getHeader('x-amz-content-sha256'));

        $other = $this->signer()->sign(new Request('GET', 'https://example.amazonaws.com/'), $this->credentials(), 'us-east-1', 'sqs');
        self::assertSame('host;x-amz-date', $other->getDetails()->getSignedHeaders());
        self::assertNull($other->getHeader('x-amz-content-sha256'));

        $asked = $this->signer()->sign(
            new Request('GET', 'https://example.amazonaws.com/'),
            $this->credentials(),
            'us-east-1',
            'sqs',
            new SigningOptions(addContentSha256: true),
        );
        self::assertSame('host;x-amz-content-sha256;x-amz-date', $asked->getDetails()->getSignedHeaders());
    }

    public function testS18CallerContentSha256IsReplacedByThePayloadHash(): void
    {
        $request = new Request('PUT', 'https://b.s3.amazonaws.com/k', ['x-amz-content-sha256' => 'stale'], 'body');
        $signed = $this->signer()->sign($request, $this->credentials(), 'us-east-1', 's3');
        self::assertSame(hash('sha256', 'body'), $signed->getHeader('x-amz-content-sha256'));
        self::assertCount(1, array_filter(
            $signed->getHeaders(),
            static fn (array $h): bool => strtolower($h[0]) === 'x-amz-content-sha256',
        ));
    }

    public function testS19SessionTokenIsAlwaysSigned(): void
    {
        $signed = $this->signer()->sign(
            new Request('GET', 'https://example.amazonaws.com/', ['X-Amz-Security-Token' => 'old']),
            $this->credentials('the-token'),
            'us-east-1',
            'service',
        );
        self::assertSame('host;x-amz-date;x-amz-security-token', $signed->getDetails()->getSignedHeaders());
        self::assertSame('the-token', $signed->getHeader('x-amz-security-token'));
        self::assertCount(1, array_filter(
            $signed->getHeaders(),
            static fn (array $h): bool => strtolower($h[0]) === 'x-amz-security-token',
        ));
    }

    public function testS20OneClockReadGivesTimestampAndScope(): void
    {
        $clock = new class implements Clock {
            public int $reads = 0;

            public function now(): \DateTimeImmutable
            {
                $this->reads++;

                return new \DateTimeImmutable(
                    $this->reads === 1 ? '2026-11-11T23:59:59.900000Z' : '2026-11-12T00:00:00Z',
                );
            }
        };
        $signed = (new Signer($clock))->sign(
            new Request('GET', 'https://example.amazonaws.com/'),
            $this->credentials(),
            'us-east-1',
            'service',
        );
        self::assertSame(1, $clock->reads);
        self::assertSame('20261111T235959Z', $signed->getHeader('X-Amz-Date'));
        self::assertStringStartsWith('20261111/', $signed->getDetails()->getCredentialScope());
    }

    public function testS21StaleDateHeaderIsReplacedUnlessAsked(): void
    {
        $request = new Request('GET', 'https://example.amazonaws.com/', ['X-Amz-Date' => '20200101T000000Z']);
        $signed = $this->signer()->sign($request, $this->credentials(), 'us-east-1', 'service');
        self::assertSame('20150830T123600Z', $signed->getHeader('x-amz-date'));
        self::assertCount(1, array_filter($signed->getHeaders(), static fn (array $h): bool => strtolower($h[0]) === 'x-amz-date'));

        $honoured = $this->signer()->sign(
            $request,
            $this->credentials(),
            'us-east-1',
            'service',
            new SigningOptions(useRequestDate: true),
        );
        self::assertSame('20200101T000000Z', $honoured->getHeader('x-amz-date'));
        self::assertStringStartsWith('20200101/', $honoured->getDetails()->getCredentialScope());

        $fromDate = $this->signer()->sign(
            new Request('GET', 'https://example.amazonaws.com/', ['Date' => 'Fri, 24 May 2013 00:00:00 GMT']),
            $this->credentials(),
            'us-east-1',
            'service',
            new SigningOptions(useRequestDate: true),
        );
        self::assertSame('20130524T000000Z', $fromDate->getHeader('x-amz-date'));
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function badScopes(): iterable
    {
        yield 'upper-case region' => ['US-EAST-1', 'sqs'];
        yield 'empty region' => ['', 'sqs'];
        yield 'upper-case service' => ['us-east-1', 'SQS'];
        yield 'empty service' => ['us-east-1', ''];
        yield 'slash in service' => ['us-east-1', 's3/x'];
        yield 'newline in region' => ["us-east-1\n", 'sqs'];
    }

    #[DataProvider('badScopes')]
    public function testS22BadRegionOrServiceThrows(string $region, string $service): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->signer()->sign(new Request('GET', 'https://example.amazonaws.com/'), $this->credentials(), $region, $service);
    }

    public function testS22AnyValidRegionCodeIsAccepted(): void
    {
        $signed = $this->signer()->sign(new Request('GET', 'https://example.com/'), $this->credentials(), 'auto', 's3');
        self::assertSame('20150830/auto/s3/aws4_request', $signed->getDetails()->getCredentialScope());
    }

    public function testS23SigningKeyMatchesTheDocumentedExample(): void
    {
        // AWS General Reference, "Examples of how to derive a signing key for Signature Version 4".
        self::assertSame(
            'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d',
            bin2hex(Signer::deriveSigningKey(self::SECRET, '20120215', 'us-east-1', 'iam')),
        );
    }

    public function testS23MemoDoesNotChangeOutput(): void
    {
        $signer = $this->signer();
        $request = new Request('GET', 'https://example.amazonaws.com/');
        $first = $signer->sign($request, $this->credentials(), 'us-east-1', 'service');
        for ($i = 0; $i < 40; $i++) {
            $signer->sign($request, $this->credentials(), 'region-' . $i, 'service');
        }
        $again = $signer->sign($request, $this->credentials(), 'us-east-1', 'service');
        $fresh = $this->signer()->sign($request, $this->credentials(), 'us-east-1', 'service');
        self::assertSame($first->getAuthorization(), $again->getAuthorization());
        self::assertSame($first->getAuthorization(), $fresh->getAuthorization());
    }

    public function testS24AuthorizationHeaderExactString(): void
    {
        $signed = $this->signer()->sign(
            new Request('GET', 'https://example.amazonaws.com/'),
            $this->credentials(),
            'us-east-1',
            'service',
        );
        // get-vanilla from the official suite.
        self::assertSame(
            'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, '
            . 'SignedHeaders=host;x-amz-date, '
            . 'Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
            $signed->getAuthorization(),
        );
    }

    public function testS25DebugProductsContainNoSecret(): void
    {
        $signed = $this->signer()->sign(
            new Request('POST', 'https://example.amazonaws.com/', [], 'body'),
            $this->credentials('session-token-value'),
            'us-east-1',
            'service',
        );
        $details = $signed->getDetails();
        $key = Signer::deriveSigningKey(self::SECRET, '20150830', 'us-east-1', 'service');
        $products = $details->getCanonicalRequest() . $details->getStringToSign() . $details->getSignedHeaders()
            . print_r($details, true) . print_r($signed, true) . var_export($details->__debugInfo(), true);
        self::assertStringNotContainsString(self::SECRET, $products);
        self::assertStringNotContainsString($key, $products);
        self::assertStringNotContainsString(bin2hex($key), $products);
        self::assertStringNotContainsString('session-token-value', print_r($details, true) . print_r($signed, true));
        self::assertStringNotContainsString('session-token-value', $details->getRedactedCanonicalRequest());
    }

    public function testS26ClockOffsetMovesTheDate(): void
    {
        $base = new SystemClock();
        $shifted = new SystemClock(120);
        $request = new Request('GET', 'https://example.amazonaws.com/');
        $before = $base->now()->getTimestamp();
        $signed = (new Signer($shifted))->sign($request, $this->credentials(), 'us-east-1', 'service');
        $after = $base->now()->getTimestamp();
        $signedAt = \DateTimeImmutable::createFromFormat('Ymd\THis\Z', (string) $signed->getHeader('x-amz-date'), new \DateTimeZone('UTC'));
        self::assertNotFalse($signedAt);
        self::assertGreaterThanOrEqual($before + 120, $signedAt->getTimestamp());
        self::assertLessThanOrEqual($after + 120, $signedAt->getTimestamp());
    }

    public function testS27SigningIsPure(): void
    {
        $request = new Request('PUT', 'https://b.s3.amazonaws.com/a b?x=1', ['Content-Type' => 'text/plain'], 'hello');
        $one = $this->signer()->sign($request, $this->credentials('t'), 'eu-west-2', 's3');
        $two = $this->signer()->sign($request, $this->credentials('t'), 'eu-west-2', 's3');
        self::assertSame($one->getHeaders(), $two->getHeaders());
        self::assertSame($one->getUrl(), $two->getUrl());
    }

    /**
     * @return iterable<string, array{0: callable(): mixed}>
     */
    public static function invalidInputs(): iterable
    {
        yield 'relative URL' => [static fn () => new Request('GET', '/path')];
        yield 'no host' => [static fn () => new Request('GET', 'https:///path')];
        yield 'ftp scheme' => [static fn () => new Request('GET', 'ftp://example.com/')];
        yield 'user info' => [static fn () => new Request('GET', 'https://user:pass@example.com/')];
        yield 'control character' => [static fn () => new Request('GET', "https://example.com/\n")];
        yield 'bad method' => [static fn () => new Request('GE T', 'https://example.com/')];
        yield 'bad header name' => [static fn () => new Request('GET', 'https://example.com/', [['Bad Name', 'v']])];
        yield 'bad header shape' => [static fn () => new Request('GET', 'https://example.com/', [['only-one']])];
        yield 'endpoint with path' => [static fn () => Request::fromRawPath('GET', 'https://example.com/x', '/k')];
        yield 'bad payload hash' => [static fn () => Payload::fromHash('abc')];
    }

    /**
     * @param callable(): mixed $build
     */
    #[DataProvider('invalidInputs')]
    public function testF1InvalidInputThrowsBeforeHashing(callable $build): void
    {
        $this->expectException(InvalidRequestException::class);
        $build();
    }

    public function testSignedRequestHelpers(): void
    {
        $signed = $this->signer()->sign(
            new Request('POST', 'https://example.amazonaws.com/?a=1', [['X-Amz-Meta', 'a'], ['x-amz-meta', 'b']], 'x'),
            $this->credentials(),
            'us-east-1',
            'service',
        );
        self::assertSame('a, b', $signed->getHeaderMap()['X-Amz-Meta']);
        self::assertContains('X-Amz-Date: 20150830T123600Z', $signed->getHeaderLines());
        self::assertSame('https://example.amazonaws.com/?a=1', $signed->getUrl());
        self::assertSame('POST', $signed->getMethod());
    }
}
