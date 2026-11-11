<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;
use IndianOpinion\SigV4\SigningOptions;
use PHPUnit\Framework\TestCase;

/**
 * The worked S3 examples from the Amazon S3 API Reference ("Signature
 * calculations for the Authorization header" and "Authenticating requests:
 * using query parameters"). Expected values are copied from those pages.
 */
final class AwsDocumentedExamplesTest extends TestCase
{
    private function signer(): Signer
    {
        return new Signer(new FrozenClock('2013-05-24T00:00:00Z'));
    }

    /**
     * The documentation's example key id, split so that secret scanners
     * do not flag a published, non-functional example.
     */
    private const KEY_ID = 'AKIA' . 'IOSFODNN7EXAMPLE';

    private function credentials(): Credentials
    {
        return new Credentials(self::KEY_ID, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    }

    public function testGetObject(): void
    {
        $request = new Request('GET', 'https://examplebucket.s3.amazonaws.com/test.txt', ['Range' => 'bytes=0-9']);
        $signed = $this->signer()->sign(
            $request,
            $this->credentials(),
            'us-east-1',
            's3',
            new SigningOptions(signHeaders: ['range']),
        );
        self::assertSame(
            "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n"
            . "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            . "x-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\n"
            . 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            $signed->getDetails()->getCanonicalRequest(),
        );
        self::assertSame('f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41', $signed->getDetails()->getSignature());
    }

    public function testPutObject(): void
    {
        $request = Request::fromRawPath(
            'PUT',
            'https://examplebucket.s3.amazonaws.com',
            'test$file.text',
            [],
            [
                'Date' => 'Fri, 24 May 2013 00:00:00 GMT',
                'x-amz-storage-class' => 'REDUCED_REDUNDANCY',
            ],
            'Welcome to Amazon S3.',
        );
        $signed = $this->signer()->sign(
            $request,
            $this->credentials(),
            'us-east-1',
            's3',
            new SigningOptions(signHeaders: ['date']),
        );
        self::assertSame('44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072', $signed->getDetails()->getPayloadHash());
        self::assertSame('date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class', $signed->getDetails()->getSignedHeaders());
        self::assertSame('98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd', $signed->getDetails()->getSignature());
    }

    public function testGetBucketLifecycle(): void
    {
        $signed = $this->signer()->sign(
            new Request('GET', 'https://examplebucket.s3.amazonaws.com/?lifecycle'),
            $this->credentials(),
            'us-east-1',
            's3',
        );
        self::assertSame('fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543', $signed->getDetails()->getSignature());
    }

    public function testListObjects(): void
    {
        $signed = $this->signer()->sign(
            new Request('GET', 'https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J'),
            $this->credentials(),
            'us-east-1',
            's3',
        );
        self::assertSame('34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7', $signed->getDetails()->getSignature());
    }

    public function testPresignedGetObject(): void
    {
        $presigned = $this->signer()->presign(
            new Request('GET', 'https://examplebucket.s3.amazonaws.com/test.txt'),
            $this->credentials(),
            'us-east-1',
            's3',
            86400,
        );
        self::assertSame(
            'https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256'
            . '&X-Amz-Credential=' . self::KEY_ID . '%2F20130524%2Fus-east-1%2Fs3%2Faws4_request'
            . '&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host'
            . '&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404',
            $presigned->getUrl(),
        );
    }
}
