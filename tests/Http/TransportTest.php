<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Http;

use IndianOpinion\SigV4\Credentials\Environment;
use IndianOpinion\SigV4\Credentials\InstanceMetadataProvider;
use IndianOpinion\SigV4\Credentials\StaticProvider;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;
use IndianOpinion\SigV4\Exception\TransportException;
use IndianOpinion\SigV4\Http\CurlTransport;
use IndianOpinion\SigV4\Http\FakeTransport;
use IndianOpinion\SigV4\Http\HttpRequest;
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\Http\StreamTransport;
use IndianOpinion\SigV4\Http\Transport;
use IndianOpinion\SigV4\Http\TransportFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Transports: T1, T2, T3, F14. Options are inspected, not sent; the only
 * socket opened is to a closed loopback port, to check failure mapping.
 */
final class TransportTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('HTTP_PROXY');
        putenv('http_proxy');
        putenv('HTTPS_PROXY');
    }

    private static function request(string $method = 'PUT'): HttpRequest
    {
        return new HttpRequest(
            $method,
            'http://169.254.169.254/latest/api/token',
            ['X-aws-ec2-metadata-token-ttl-seconds' => '21600'],
            '',
            1.0,
            2.0,
        );
    }

    public function testT1FakeTransportRecordsAndReplays(): void
    {
        $fake = new FakeTransport([new HttpResponse(200, ['X-Thing' => 'a'], 'body')]);
        $fake->push(static fn (HttpRequest $r): HttpResponse => new HttpResponse(201, [], $r->url));
        $first = $fake->send(self::request());
        $second = $fake->send(new HttpRequest('GET', 'http://example.test/x', [], 'payload', 0.5, 1.5));

        self::assertSame(200, $first->status);
        self::assertSame('a', $first->getHeader('x-thing'));
        self::assertSame('http://example.test/x', $second->body);
        $recorded = $fake->getRequests()[1];
        self::assertSame('GET', $recorded->method);
        self::assertSame('payload', $recorded->body);
        self::assertSame(0.5, $recorded->connectTimeout);
        self::assertSame(1.5, $recorded->timeout);
        self::assertSame(2, $fake->count());

        $this->expectException(\LogicException::class);
        $fake->send(self::request());
    }

    public function testT1ResponseHeaderNamesAreLowerCased(): void
    {
        $response = new HttpResponse(200, ['Content-Type' => 'a', 'X-Multi' => ['1', '2']]);
        self::assertSame(['content-type' => 'a', 'x-multi' => '1, 2'], $response->headers);
    }

    public function testT2CurlOptions(): void
    {
        if (!extension_loaded('curl')) {
            self::markTestSkipped('curl is not loaded.');
        }
        $options = (new CurlTransport())->buildOptions(self::request());
        self::assertFalse($options[CURLOPT_FOLLOWLOCATION]);
        self::assertSame(0, $options[CURLOPT_MAXREDIRS]);
        self::assertSame('', $options[CURLOPT_PROXY]);
        self::assertSame('*', $options[CURLOPT_NOPROXY]);
        self::assertTrue($options[CURLOPT_SSL_VERIFYPEER]);
        self::assertSame(2, $options[CURLOPT_SSL_VERIFYHOST]);
        self::assertSame(1000, $options[CURLOPT_CONNECTTIMEOUT_MS]);
        self::assertSame(2000, $options[CURLOPT_TIMEOUT_MS]);
        self::assertSame('PUT', $options[CURLOPT_CUSTOMREQUEST]);
        self::assertContains('X-aws-ec2-metadata-token-ttl-seconds: 21600', $options[CURLOPT_HTTPHEADER]);
        self::assertSame(CURLPROTO_HTTP | CURLPROTO_HTTPS, $options[CURLOPT_PROTOCOLS]);
    }

    public function testT2StreamOptions(): void
    {
        $options = (new StreamTransport())->buildContextOptions(self::request());
        self::assertSame(0, $options['http']['follow_location']);
        self::assertArrayNotHasKey('proxy', $options['http']);
        self::assertTrue($options['http']['ignore_errors']);
        self::assertSame(2.0, $options['http']['timeout']);
        self::assertTrue($options['ssl']['verify_peer']);
        self::assertTrue($options['ssl']['verify_peer_name']);
        self::assertFalse($options['ssl']['allow_self_signed']);
    }

    public function testT3ProxyEnvironmentIsIgnored(): void
    {
        putenv('HTTP_PROXY=http://proxy.invalid:3128');
        putenv('http_proxy=http://proxy.invalid:3128');
        putenv('HTTPS_PROXY=http://proxy.invalid:3128');
        if (extension_loaded('curl')) {
            $options = (new CurlTransport())->buildOptions(self::request());
            self::assertSame('*', $options[CURLOPT_NOPROXY]);
            self::assertSame('', $options[CURLOPT_PROXY]);
        }
        $stream = (new StreamTransport())->buildContextOptions(self::request());
        self::assertArrayNotHasKey('proxy', $stream['http']);
    }

    /**
     * @return iterable<string, array{0: Transport}>
     */
    public static function realTransports(): iterable
    {
        if (extension_loaded('curl')) {
            yield 'curl' => [new CurlTransport()];
        }
        yield 'streams' => [new StreamTransport()];
    }

    #[DataProvider('realTransports')]
    public function testClosedLoopbackPortIsATransportErrorNotAnException(Transport $transport): void
    {
        $response = $transport->send(new HttpRequest('GET', 'http://127.0.0.1:1/', [], '', 0.5, 0.5));
        self::assertTrue($response->isTransportError());
        self::assertNotSame('', $response->error);
    }

    public function testFactoryPrefersCurlThenStreams(): void
    {
        if (extension_loaded('curl')) {
            self::assertInstanceOf(CurlTransport::class, TransportFactory::create());
        }
        self::assertInstanceOf(StreamTransport::class, TransportFactory::create(false, true));
    }

    public function testF14NoTransportFailsOnFirstNetworkUseOnly(): void
    {
        $this->expectException(TransportException::class);
        TransportFactory::create(false, false);
    }

    public function testF14StaticProviderNeedsNoTransport(): void
    {
        self::assertSame('AKID', StaticProvider::fromKeys('AKID', 'secret')->getCredentials()->getAccessKeyId());
        // Building a network provider does not need a transport either; only using it does.
        $provider = new InstanceMetadataProvider(new Environment(['AWS_EC2_METADATA_DISABLED' => 'true']));
        $this->expectException(CredentialsNotFoundException::class);
        $provider->getCredentials();
    }

    public function testHttpRequestDebugOutputHidesTokens(): void
    {
        $request = new HttpRequest('GET', 'http://x/', ['X-aws-ec2-metadata-token' => 'tok-value', 'Authorization' => 'auth-value']);
        $dump = print_r($request, true);
        self::assertStringNotContainsString('tok-value', $dump);
        self::assertStringNotContainsString('auth-value', $dump);
    }
}
