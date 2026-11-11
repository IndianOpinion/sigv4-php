<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Credentials;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials\ContainerProvider;
use IndianOpinion\SigV4\Credentials\Environment;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;
use IndianOpinion\SigV4\Http\FakeTransport;
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\Tests\Support\Imds;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cases C3 to C7, F7 and F8.
 */
final class ContainerProviderTest extends TestCase
{
    private ?string $tokenFile = null;

    protected function tearDown(): void
    {
        if ($this->tokenFile !== null && is_file($this->tokenFile)) {
            unlink($this->tokenFile);
        }
    }

    /**
     * @param array<string, string> $env
     */
    private function provider(array $env, FakeTransport $transport): ContainerProvider
    {
        return new ContainerProvider(new Environment($env), $transport, new FrozenClock('2026-11-11T12:00:00Z'));
    }

    public function testC3RelativeUriWinsAndGoesToTheContainerHost(): void
    {
        $transport = new FakeTransport([Imds::containerCredentials()]);
        $credentials = $this->provider([
            'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/v2/credentials/abc',
            'AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'https://elsewhere.example.com/creds',
        ], $transport)->getCredentials();

        self::assertSame('http://169.254.170.2/v2/credentials/abc', $transport->getRequests()[0]->url);
        self::assertSame('GET', $transport->getRequests()[0]->method);
        self::assertSame('ASIAEXAMPLECONTAINER', $credentials->getAccessKeyId());
        self::assertSame('container', $credentials->getSource());
        self::assertSame('2026-11-11T18:00:00+00:00', $credentials->getExpiresAt()?->format(DATE_ATOM));
    }

    public function testC3RelativeUriMustBeAPath(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->provider(['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '@evil.example.com/x'], new FakeTransport())->getCredentials();
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function allowedFullUris(): iterable
    {
        yield 'https anywhere' => ['https://creds.example.com/v1'];
        yield 'localhost' => ['http://localhost:8080/creds'];
        yield '127.0.0.1' => ['http://127.0.0.1/creds'];
        yield 'other IPv4 loopback' => ['http://127.0.0.53/creds'];
        yield 'IPv6 loopback' => ['http://[::1]:8080/creds'];
        yield 'ECS host' => ['http://169.254.170.2/creds'];
        yield 'EKS host' => ['http://169.254.170.23/v1/credentials'];
        yield 'EKS IPv6 host' => ['http://[fd00:ec2::23]/v1/credentials'];
        yield 'EKS IPv6 host, long form' => ['http://[fd00:ec2:0:0:0:0:0:23]/v1/credentials'];
    }

    #[DataProvider('allowedFullUris')]
    public function testC4AllowedFullUris(string $uri): void
    {
        $transport = new FakeTransport([Imds::containerCredentials()]);
        $this->provider(['AWS_CONTAINER_CREDENTIALS_FULL_URI' => $uri], $transport)->getCredentials();
        self::assertSame($uri, $transport->getRequests()[0]->url);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function refusedFullUris(): iterable
    {
        yield 'plain http elsewhere' => ['http://creds.example.com/v1'];
        yield 'localhost lookalike' => ['http://localhost.example.com/v1'];
        yield 'instance metadata' => ['http://169.254.169.254/latest/meta-data/'];
        yield 'other link-local' => ['http://169.254.170.3/creds'];
        yield 'file scheme' => ['file:///etc/passwd'];
        yield 'user info' => ['http://user:pass@127.0.0.1/creds'];
        yield 'not a URL' => ['creds'];
    }

    #[DataProvider('refusedFullUris')]
    public function testC4RefusedFullUrisStopWithoutANetworkCall(string $uri): void
    {
        $transport = new FakeTransport();
        try {
            $this->provider(['AWS_CONTAINER_CREDENTIALS_FULL_URI' => $uri], $transport)->getCredentials();
            self::fail('Expected a configuration exception.');
        } catch (ConfigurationException) {
            self::assertSame(0, $transport->count());
        }
    }

    public function testC5TokenFileIsReadOnEveryFetchAndWinsOverTheVariable(): void
    {
        $this->tokenFile = (string) tempnam(sys_get_temp_dir(), 'sigv4-token');
        file_put_contents($this->tokenFile, "first-token\n");
        $transport = new FakeTransport([Imds::containerCredentials(), Imds::containerCredentials()]);
        $provider = $this->provider([
            'AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://169.254.170.23/v1/credentials',
            'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE' => $this->tokenFile,
            'AWS_CONTAINER_AUTHORIZATION_TOKEN' => 'variable-token',
        ], $transport);

        $provider->getCredentials();
        file_put_contents($this->tokenFile, 'second-token');
        $provider->getCredentials();

        self::assertSame('first-token', $transport->getRequests()[0]->headers['Authorization']);
        self::assertSame('second-token', $transport->getRequests()[1]->headers['Authorization']);
    }

    public function testC5TokenVariableIsUsedWithoutAFile(): void
    {
        $transport = new FakeTransport([Imds::containerCredentials()]);
        $this->provider([
            'AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://localhost/creds',
            'AWS_CONTAINER_AUTHORIZATION_TOKEN' => 'Basic abcd',
        ], $transport)->getCredentials();
        self::assertSame('Basic abcd', $transport->getRequests()[0]->headers['Authorization']);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function badTokens(): iterable
    {
        yield 'CRLF injection' => ["abc\r\nX-Injected: 1"];
        yield 'LF inside' => ["abc\ndef"];
    }

    #[DataProvider('badTokens')]
    public function testC5TokenWithLineBreakIsRefused(string $token): void
    {
        $transport = new FakeTransport([Imds::containerCredentials()]);
        $this->expectException(ConfigurationException::class);
        $this->provider([
            'AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://localhost/creds',
            'AWS_CONTAINER_AUTHORIZATION_TOKEN' => $token,
        ], $transport)->getCredentials();
    }

    public function testC5UnreadableTokenFileIsAConfigurationError(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->provider([
            'AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://localhost/creds',
            'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE' => '/nonexistent/sigv4/token',
        ], new FakeTransport())->getCredentials();
    }

    public function testC6MissingTokenFieldThrows(): void
    {
        $this->expectException(CredentialsException::class);
        $this->expectExceptionMessage('"Token"');
        $this->provider(
            ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/creds'],
            new FakeTransport([Imds::containerCredentials([], 'Token')]),
        )->getCredentials();
    }

    public function testC6NonJsonThrows(): void
    {
        $this->expectException(CredentialsException::class);
        $this->provider(
            ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/creds'],
            new FakeTransport([new HttpResponse(200, [], '<html>not json</html>')]),
        )->getCredentials();
    }

    public function testC7NoVariablesIsNotFoundWithZeroCalls(): void
    {
        $transport = new FakeTransport();
        try {
            $this->provider([], $transport)->getCredentials();
            self::fail('Expected not found.');
        } catch (CredentialsNotFoundException) {
            self::assertSame(0, $transport->count());
        }
    }

    public function testF7ServerErrorRaises(): void
    {
        $this->expectException(CredentialsException::class);
        $this->expectExceptionMessage('HTTP 500');
        $this->provider(
            ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/creds'],
            new FakeTransport([new HttpResponse(500, [], 'oops')]),
        )->getCredentials();
    }

    public function testF7TransportFailureRaises(): void
    {
        $this->expectException(CredentialsException::class);
        $this->provider(
            ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/creds'],
            new FakeTransport([HttpResponse::failure('connection refused')]),
        )->getCredentials();
    }

    public function testT5OversizedResponseIsRefused(): void
    {
        $this->expectException(CredentialsException::class);
        $this->expectExceptionMessage('larger than 65536 bytes');
        $this->provider(
            ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/creds'],
            new FakeTransport([new HttpResponse(200, [], str_repeat('x', 65 * 1024))]),
        )->getCredentials();
    }

    public function testRequestCarriesTheContainerTimeouts(): void
    {
        $transport = new FakeTransport([Imds::containerCredentials()]);
        $this->provider(['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/creds'], $transport)->getCredentials();
        self::assertSame(1.0, $transport->getRequests()[0]->connectTimeout);
        self::assertSame(3.0, $transport->getRequests()[0]->timeout);
    }
}
