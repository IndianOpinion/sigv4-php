<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Clock\FrozenClock;
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
 * Presigned URLs: cases P1 to P7 and F13.
 */
final class PresignTest extends TestCase
{
    private const NOW = '2026-11-11T12:00:00Z';

    private function signer(?RecordingLogger $logger = null): Signer
    {
        return new Signer(new FrozenClock(self::NOW), $logger);
    }

    private function credentials(?string $token = null, ?string $expires = null): Credentials
    {
        return new Credentials(
            'AKIDEXAMPLE',
            'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            $token,
            $expires === null ? null : new \DateTimeImmutable($expires),
            $token === null ? 'static' : 'imds',
        );
    }

    /**
     * @return list<string>
     */
    private static function queryNames(string $url): array
    {
        $names = [];
        foreach (explode('&', (string) parse_url($url, PHP_URL_QUERY)) as $piece) {
            $names[] = explode('=', $piece, 2)[0];
        }

        return $names;
    }

    public function testP1ParameterSetAndSignatureOutsideTheCanonicalQuery(): void
    {
        $presigned = $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k'),
            $this->credentials('tok'),
            'eu-west-2',
            's3',
        );
        self::assertSame([
            'X-Amz-Algorithm',
            'X-Amz-Credential',
            'X-Amz-Date',
            'X-Amz-Expires',
            'X-Amz-SignedHeaders',
            'X-Amz-Security-Token',
            'X-Amz-Signature',
        ], self::queryNames($presigned->getUrl()));
        $canonicalQuery = explode("\n", $presigned->getDetails()->getCanonicalRequest())[2];
        self::assertStringContainsString('X-Amz-Security-Token=tok', $canonicalQuery);
        self::assertStringNotContainsString('X-Amz-Signature', $canonicalQuery);
        self::assertStringEndsWith('&X-Amz-Signature=' . $presigned->getDetails()->getSignature(), $presigned->getUrl());
    }

    /**
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function expiries(): iterable
    {
        yield 'zero' => [0, false];
        yield 'negative' => [-5, false];
        yield 'one' => [1, true];
        yield 'seven days' => [604800, true];
        yield 'seven days and a second' => [604801, false];
    }

    #[DataProvider('expiries')]
    public function testP2ExpiryRange(int $expires, bool $valid): void
    {
        if (!$valid) {
            $this->expectException(InvalidRequestException::class);
        }
        $presigned = $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k'),
            $this->credentials(),
            'us-east-1',
            's3',
            $expires,
        );
        self::assertStringContainsString('X-Amz-Expires=' . $expires . '&', $presigned->getUrl());
    }

    public function testP3StrictByDefaultRefusesAnExpiryPastTheCredentials(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('expire in 600 seconds');
        $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k'),
            $this->credentials('tok', '2026-11-11T12:10:00Z'),
            'us-east-1',
            's3',
            3600,
        );
    }

    public function testP3NonStrictReturnsTheEffectiveExpiryAndWarns(): void
    {
        $logger = new RecordingLogger();
        $presigned = $this->signer($logger)->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k'),
            $this->credentials('tok', '2026-11-11T12:10:00Z'),
            'us-east-1',
            's3',
            3600,
            new SigningOptions(strictPresignExpiry: false),
        );
        self::assertSame(3600, $presigned->getRequestedExpires());
        self::assertSame(600, $presigned->getEffectiveExpires());
        self::assertSame('2026-11-11T12:10:00+00:00', $presigned->getExpiresAt()->format(DATE_ATOM));
        self::assertCount(1, $logger->level('warning'));
    }

    public function testP3ExpiredCredentialsAlwaysThrow(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k'),
            $this->credentials('tok', '2026-11-11T11:00:00Z'),
            'us-east-1',
            's3',
            60,
            new SigningOptions(strictPresignExpiry: false),
        );
    }

    public function testP3ExpiryWithinTheCredentialLifetimeIsKept(): void
    {
        $presigned = $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k'),
            $this->credentials('tok', '2026-11-11T18:00:00Z'),
            'us-east-1',
            's3',
            3600,
        );
        self::assertSame(3600, $presigned->getEffectiveExpires());
    }

    public function testP4PayloadHashDefaults(): void
    {
        $request = new Request('PUT', 'https://b.s3.amazonaws.com/k');
        $s3 = $this->signer()->presign($request, $this->credentials(), 'us-east-1', 's3');
        $lines = explode("\n", $s3->getDetails()->getCanonicalRequest());
        self::assertSame('UNSIGNED-PAYLOAD', end($lines));

        $other = $this->signer()->presign(new Request('GET', 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15'), $this->credentials(), 'us-east-1', 'sts');
        $lines = explode("\n", $other->getDetails()->getCanonicalRequest());
        self::assertSame(Payload::EMPTY_SHA256, end($lines));

        $override = $this->signer()->presign($request->withPayload(Payload::fromHash(hash('sha256', 'x'))), $this->credentials(), 'us-east-1', 's3');
        $lines = explode("\n", $override->getDetails()->getCanonicalRequest());
        self::assertSame(hash('sha256', 'x'), end($lines));
    }

    public function testP5DefaultSignedHeadersIsHostAndExtrasMustBeSent(): void
    {
        $request = new Request('PUT', 'https://b.s3.amazonaws.com/k', [
            'Content-Type' => 'image/png',
            'x-amz-meta-owner' => 'me',
        ]);
        $default = $this->signer()->presign($request, $this->credentials(), 'us-east-1', 's3');
        self::assertSame('host', $default->getDetails()->getSignedHeaders());
        self::assertSame([], $default->getHeadersToSend());

        $extra = $this->signer()->presign($request, $this->credentials(), 'us-east-1', 's3', 900, new SigningOptions(signHeaders: ['content-type']));
        self::assertSame('content-type;host', $extra->getDetails()->getSignedHeaders());
        self::assertSame([['Content-Type', 'image/png']], $extra->getHeadersToSend());
        self::assertStringContainsString('X-Amz-SignedHeaders=content-type%3Bhost', $extra->getUrl());
    }

    public function testP6PresignedUrlCannotBePresignedAgain(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k?X-Amz-Signature=abc'),
            $this->credentials(),
            'us-east-1',
            's3',
        );
    }

    public function testP6OrdinaryQueryIsKeptAndSigned(): void
    {
        $presigned = $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k?response-content-disposition=attachment%3B%20filename%3Da.txt&versionId=3'),
            $this->credentials(),
            'us-east-1',
            's3',
        );
        self::assertStringStartsWith(
            'https://b.s3.amazonaws.com/k?response-content-disposition=attachment%3B%20filename%3Da.txt&versionId=3&X-Amz-Algorithm=',
            $presigned->getUrl(),
        );
        $canonicalQuery = explode("\n", $presigned->getDetails()->getCanonicalRequest())[2];
        self::assertStringContainsString('response-content-disposition=attachment%3B%20filename%3Da.txt', $canonicalQuery);
        self::assertStringContainsString('versionId=3', $canonicalQuery);
    }

    public function testP7S3KeyWithDoubleSlashIsNotNormalised(): void
    {
        $presigned = $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/my-object//example//photo.user'),
            $this->credentials(),
            'us-east-1',
            's3',
        );
        self::assertSame('/my-object//example//photo.user', explode("\n", $presigned->getDetails()->getCanonicalRequest())[1]);
        self::assertStringStartsWith('https://b.s3.amazonaws.com/my-object//example//photo.user?', $presigned->getUrl());
    }

    public function testPresignedDebugOutputHidesTheToken(): void
    {
        $presigned = $this->signer()->presign(
            new Request('GET', 'https://b.s3.amazonaws.com/k'),
            $this->credentials('secret/token+value=='),
            'us-east-1',
            's3',
        );
        $dump = print_r($presigned, true);
        self::assertStringNotContainsString('secret/token+value==', $dump);
        self::assertStringNotContainsString(rawurlencode('secret/token+value=='), $dump);
        self::assertStringContainsString(rawurlencode('secret/token+value=='), (string) $presigned);
    }
}
