<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\InvalidRequestException;
use IndianOpinion\SigV4\Payload;
use IndianOpinion\SigV4\Psr7\Psr7Adapter;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;
use Nyholm\Psr7\Request as PsrRequest;
use PHPUnit\Framework\TestCase;

/**
 * The optional PSR-7 adapter (decision 2 in ARCHITECTURE.md).
 */
final class Psr7AdapterTest extends TestCase
{
    private function signer(): Signer
    {
        return new Signer(new FrozenClock('2015-08-30T12:36:00Z'));
    }

    private function credentials(): Credentials
    {
        return new Credentials('AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');
    }

    public function testSignsAPsr7RequestLikeANativeOne(): void
    {
        $psr = new PsrRequest('POST', 'https://example.amazonaws.com/?Param1=value1', ['Content-Type' => 'application/json', 'X-Amz-Target' => 'A.B'], '{"a":1}');
        $native = new Request('POST', 'https://example.amazonaws.com/?Param1=value1', ['Content-Type' => 'application/json', 'X-Amz-Target' => 'A.B'], '{"a":1}');

        $fromPsr = $this->signer()->sign(Psr7Adapter::fromPsr7($psr), $this->credentials(), 'us-east-1', 'service');
        $fromNative = $this->signer()->sign($native, $this->credentials(), 'us-east-1', 'service');
        self::assertSame($fromNative->getAuthorization(), $fromPsr->getAuthorization());

        $applied = Psr7Adapter::applyTo($psr, $fromPsr);
        self::assertSame($fromPsr->getAuthorization(), $applied->getHeaderLine('Authorization'));
        self::assertSame('20150830T123600Z', $applied->getHeaderLine('X-Amz-Date'));
        self::assertSame('{"a":1}', (string) $applied->getBody());
    }

    public function testPayloadOverrideSkipsReadingTheBody(): void
    {
        $psr = new PsrRequest('PUT', 'https://b.s3.amazonaws.com/k', [], 'ignored');
        $request = Psr7Adapter::fromPsr7($psr, Payload::unsigned());
        self::assertTrue($request->getPayload()?->isUnsigned());
    }

    public function testApplyPresigned(): void
    {
        $psr = new PsrRequest('GET', 'https://b.s3.amazonaws.com/k?versionId=2');
        $presigned = $this->signer()->presign(Psr7Adapter::fromPsr7($psr), $this->credentials(), 'us-east-1', 's3');
        $applied = Psr7Adapter::applyPresigned($psr, $presigned);
        self::assertSame($presigned->getUrl(), (string) $applied->getUri());
    }

    public function testRejectsOtherObjects(): void
    {
        $this->expectException(InvalidRequestException::class);
        Psr7Adapter::fromPsr7(new \stdClass());
    }
}
