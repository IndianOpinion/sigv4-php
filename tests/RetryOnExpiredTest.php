<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials\CachingProvider;
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\RetryOnExpired;
use IndianOpinion\SigV4\SignedRequest;
use IndianOpinion\SigV4\Signer;
use IndianOpinion\SigV4\Tests\Support\CountingProvider;
use PHPUnit\Framework\TestCase;

/**
 * F-retry and F11.
 */
final class RetryOnExpiredTest extends TestCase
{
    private FrozenClock $clock;
    private CountingProvider $inner;
    private RetryOnExpired $retry;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-11-11T12:00:00Z');
        $this->inner = new CountingProvider($this->clock, 3600);
        $this->retry = new RetryOnExpired(new Signer($this->clock), new CachingProvider($this->inner, null, $this->clock));
    }

    /**
     * @param list<HttpResponse> $responses
     * @param list<SignedRequest> $sent
     *
     * @return callable(SignedRequest): HttpResponse
     */
    private static function sender(array &$responses, array &$sent): callable
    {
        return static function (SignedRequest $signed) use (&$responses, &$sent): HttpResponse {
            $sent[] = $signed;
            $next = array_shift($responses);
            if ($next === null) {
                throw new \LogicException('No more responses.');
            }

            return $next;
        };
    }

    private static function expired(): HttpResponse
    {
        return new HttpResponse(403, ['x-amzn-ErrorType' => 'ExpiredTokenException:http://x/'], '');
    }

    public function testExpiredThenOkRefreshesOnceAndResendsOnce(): void
    {
        $responses = [self::expired(), new HttpResponse(200, [], 'ok')];
        $sent = [];
        $response = $this->retry->send(new Request('POST', 'https://sts.amazonaws.com/'), 'us-east-1', 'sts', self::sender($responses, $sent));
        self::assertSame(200, $response->status);
        self::assertCount(2, $sent);
        self::assertSame(2, $this->inner->calls);
        self::assertStringContainsString('AKIDCOUNT1/', $sent[0]->getAuthorization());
        self::assertStringContainsString('AKIDCOUNT2/', $sent[1]->getAuthorization());
    }

    public function testSecondExpiredAnswerIsReturnedWithoutAThirdSend(): void
    {
        $responses = [self::expired(), self::expired()];
        $sent = [];
        $response = $this->retry->send(new Request('GET', 'https://sqs.amazonaws.com/'), 'us-east-1', 'sqs', self::sender($responses, $sent));
        self::assertSame(403, $response->status);
        self::assertCount(2, $sent);
    }

    public function testOtherForbiddenIsNotRetried(): void
    {
        $responses = [new HttpResponse(403, [], '<Error><Code>AccessDenied</Code></Error>')];
        $sent = [];
        $response = $this->retry->send(new Request('GET', 'https://b.s3.amazonaws.com/k'), 'us-east-1', 's3', self::sender($responses, $sent));
        self::assertSame(403, $response->status);
        self::assertCount(1, $sent);
        self::assertSame(1, $this->inner->calls);
    }

    public function testF11CredentialsNearExpiryAreRefreshedBeforeSigning(): void
    {
        $responses = [new HttpResponse(200), new HttpResponse(200)];
        $sent = [];
        $request = new Request('GET', 'https://sqs.amazonaws.com/');
        $this->retry->send($request, 'us-east-1', 'sqs', self::sender($responses, $sent));
        $this->clock->advance(3600 - 300);
        $this->retry->send($request, 'us-east-1', 'sqs', self::sender($responses, $sent));
        self::assertSame(2, $this->inner->calls);
    }
}
