<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\ErrorInfo;
use IndianOpinion\SigV4\Http\HttpResponse;
use PHPUnit\Framework\TestCase;

/**
 * F-helper and F12.
 */
final class ErrorInfoTest extends TestCase
{
    public function testTypeFromHeaderStripsTheSuffix(): void
    {
        $info = ErrorInfo::fromResponse(400, [
            'X-Amzn-ErrorType' => 'ExpiredTokenException:http://internal.amazon.com/coral/com.amazon.coral.service/',
            'x-amzn-RequestId' => 'req-1',
        ], '{"__type":"Other"}');
        self::assertSame('ExpiredTokenException', $info->getType());
        self::assertSame('req-1', $info->getRequestId());
        self::assertTrue($info->isExpiredCredentials());
    }

    public function testTypeFromJsonStripsTheNamespace(): void
    {
        $info = ErrorInfo::fromResponse(400, [], '{"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException","message":"x"}');
        self::assertSame('ResourceNotFoundException', $info->getType());
        self::assertNull($info->getRequestId());
    }

    public function testTypeFromXmlCode(): void
    {
        $body = '<?xml version="1.0" encoding="UTF-8"?><Error><Code>SignatureDoesNotMatch</Code>'
            . '<Message>The request signature we calculated does not match</Message></Error>';
        $info = ErrorInfo::fromResponse(403, ['x-amz-request-id' => 'S3REQ'], $body);
        self::assertSame('SignatureDoesNotMatch', $info->getType());
        self::assertSame('S3REQ', $info->getRequestId());
        self::assertFalse($info->isExpiredCredentials());
    }

    public function testQueryProtocolErrorResponse(): void
    {
        $body = '<ErrorResponse><Error><Type>Sender</Type><Code>ExpiredToken</Code>'
            . '<Message>The security token included in the request is expired</Message></Error>'
            . '<RequestId>abc</RequestId></ErrorResponse>';
        $info = ErrorInfo::fromResponse(403, [], $body);
        self::assertSame('ExpiredToken', $info->getType());
        self::assertTrue($info->isExpiredCredentials());
    }

    public function testBareStatus(): void
    {
        self::assertSame('HTTP503', ErrorInfo::fromResponse(503, [], '')->getType());
        self::assertSame('HTTP500', ErrorInfo::fromResponse(500, [], 'not json, not xml')->getType());
    }

    public function testF12ClockSkewIsSurfaced(): void
    {
        $body = '<Error><Code>RequestTimeTooSkewed</Code><Message>The difference between the request time '
            . 'and the current time is too large.</Message></Error>';
        $info = ErrorInfo::fromHttpResponse(new HttpResponse(403, [], $body));
        self::assertSame('RequestTimeTooSkewed', $info->getType());
        self::assertTrue($info->isClockSkew());
        self::assertFalse($info->isExpiredCredentials());
    }

    public function testExpiredCredentialTypesNeedAClientErrorStatus(): void
    {
        self::assertFalse(ErrorInfo::fromResponse(500, ['x-amzn-errortype' => 'ExpiredToken'], '')->isExpiredCredentials());
        foreach (ErrorInfo::EXPIRED_CREDENTIAL_TYPES as $type) {
            self::assertTrue(ErrorInfo::fromResponse(403, ['x-amzn-errortype' => $type], '')->isExpiredCredentials());
        }
    }

    public function testTypeIsSanitised(): void
    {
        $info = ErrorInfo::fromResponse(400, ['x-amzn-errortype' => "Bad<script>\r\nType"], '');
        self::assertSame('BadscriptType', $info->getType());
    }
}
