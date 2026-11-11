<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Credentials;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials\Environment;
use IndianOpinion\SigV4\Credentials\InstanceMetadataProvider;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;
use IndianOpinion\SigV4\Http\CurlTransport;
use IndianOpinion\SigV4\Http\FakeTransport;
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\Tests\Support\Imds;
use IndianOpinion\SigV4\Tests\Support\RecordingLogger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * IMDSv2: cases C8 to C17, C19, F3 to F6 and T5.
 */
final class InstanceMetadataProviderTest extends TestCase
{
    private FrozenClock $clock;
    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-11-11T12:00:00Z');
        $this->logger = new RecordingLogger();
    }

    /**
     * @param array<string, string> $env
     */
    private function provider(
        FakeTransport $transport,
        array $env = [],
        ?string $roleName = null,
        int $tokenTtl = 21600,
        float $connectTimeout = 1.0,
        float $timeout = 2.0,
        int $retries = 1,
    ): InstanceMetadataProvider {
        return new InstanceMetadataProvider(
            new Environment($env),
            $transport,
            $this->clock,
            $this->logger,
            roleName: $roleName,
            tokenTtl: $tokenTtl,
            connectTimeout: $connectTimeout,
            timeout: $timeout,
            retries: $retries,
        );
    }

    private static function happy(): FakeTransport
    {
        return new FakeTransport([Imds::token(), Imds::role(), Imds::credentials()]);
    }

    public function testC8C9C10TheFullFlow(): void
    {
        $transport = self::happy();
        $credentials = $this->provider($transport)->getCredentials();

        $requests = $transport->getRequests();
        self::assertCount(3, $requests);
        self::assertSame('PUT', $requests[0]->method);
        self::assertSame('http://169.254.169.254/latest/api/token', $requests[0]->url);
        self::assertSame('21600', $requests[0]->headers['X-aws-ec2-metadata-token-ttl-seconds']);
        self::assertSame('GET', $requests[1]->method);
        self::assertSame('http://169.254.169.254/latest/meta-data/iam/security-credentials/', $requests[1]->url);
        self::assertSame('imds-api-token-0001', $requests[1]->headers['X-aws-ec2-metadata-token']);
        self::assertSame('http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role', $requests[2]->url);
        self::assertSame('imds-api-token-0001', $requests[2]->headers['X-aws-ec2-metadata-token']);

        self::assertSame(Imds::KEY, $credentials->getAccessKeyId());
        self::assertSame(Imds::TOKEN, $credentials->getSessionToken());
        self::assertSame('imds', $credentials->getSource());
        self::assertSame('2026-11-11T18:00:00+00:00', $credentials->getExpiresAt()?->format(DATE_ATOM));
    }

    public function testC8TokenIsReusedWithinItsTtlAndFetchedAgainAfter(): void
    {
        $transport = new FakeTransport([
            Imds::token('t1'), Imds::role(), Imds::credentials(),
            Imds::credentials(),
            Imds::token('t2'), Imds::credentials(),
        ]);
        $provider = $this->provider($transport, [], tokenTtl: 600);
        $provider->getCredentials();
        $this->clock->advance(500);
        $provider->getCredentials();
        $this->clock->advance(100);
        $provider->getCredentials();

        $methods = array_map(static fn ($r): string => $r->method, $transport->getRequests());
        // The role is listed once and remembered: later fetches are one GET.
        self::assertSame(['PUT', 'GET', 'GET', 'GET', 'PUT', 'GET'], $methods);
        self::assertSame('600', $transport->getRequests()[0]->headers['X-aws-ec2-metadata-token-ttl-seconds']);
        self::assertSame('t2', $transport->getRequests()[5]->headers['X-aws-ec2-metadata-token']);
    }

    public function testDiscoveredRoleIsListedAgainAfterA404(): void
    {
        $transport = new FakeTransport([
            Imds::token(), Imds::role('old-role'), new HttpResponse(404),
            Imds::role('new-role'), Imds::credentials(),
        ]);
        $provider = $this->provider($transport, []);
        try {
            $provider->getCredentials();
            self::fail('A 404 for the role credentials must throw.');
        } catch (CredentialsException) {
        }
        $provider->getCredentials();
        self::assertStringEndsWith('/security-credentials/new-role', $transport->getRequests()[4]->url);
    }

    /**
     * @return iterable<string, array{0: int}>
     */
    public static function badTtls(): iterable
    {
        yield 'zero' => [0];
        yield 'above maximum' => [21601];
    }

    #[DataProvider('badTtls')]
    public function testC8TokenTtlIsValidated(int $ttl): void
    {
        $this->expectException(ConfigurationException::class);
        $this->provider(new FakeTransport(), [], tokenTtl: $ttl);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function badRoleNames(): iterable
    {
        yield 'slash' => ['role/../../latest'];
        yield 'space' => ['my role'];
        yield 'too long' => [str_repeat('a', 65)];
        yield 'query' => ['role?x=1'];
    }

    #[DataProvider('badRoleNames')]
    public function testC9BadRoleNameFromImdsIsRejected(string $role): void
    {
        $transport = new FakeTransport([Imds::token(), Imds::role($role)]);
        try {
            $this->provider($transport)->getCredentials();
            self::fail('Expected an exception.');
        } catch (CredentialsException $e) {
            self::assertStringContainsString('not a valid IAM role name', $e->getMessage());
            self::assertSame(2, $transport->count());
        }
    }

    public function testC9ConfiguredRoleSkipsTheListing(): void
    {
        $transport = new FakeTransport([Imds::token(), Imds::credentials()]);
        $this->provider($transport, [], roleName: 'configured-role')->getCredentials();
        self::assertSame(2, $transport->count());
        self::assertStringEndsWith('/security-credentials/configured-role', $transport->getRequests()[1]->url);
    }

    public function testC9ConfiguredRoleIsValidated(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->provider(new FakeTransport(), [], roleName: 'bad/role');
    }

    public function testC9FirstNonEmptyLineIsTheRole(): void
    {
        $transport = new FakeTransport([Imds::token(), new HttpResponse(200, [], "\n  first-role \nsecond-role\n"), Imds::credentials()]);
        $this->provider($transport)->getCredentials();
        self::assertStringEndsWith('/security-credentials/first-role', $transport->getRequests()[2]->url);
    }

    public function testC10CodeOtherThanSuccessThrows(): void
    {
        $this->expectException(CredentialsException::class);
        $this->expectExceptionMessage('not "Success"');
        $this->provider(new FakeTransport([Imds::token(), Imds::role(), Imds::credentials(code: 'Failure')]))->getCredentials();
    }

    public function testC11Ipv6Mode(): void
    {
        $transport = self::happy();
        $this->provider($transport, ['AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE' => 'IPv6'])->getCredentials();
        self::assertSame('http://[fd00:ec2::254]/latest/api/token', $transport->getRequests()[0]->url);
    }

    public function testC11EndpointOverrideWins(): void
    {
        $transport = self::happy();
        $this->provider($transport, [
            'AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE' => 'IPv6',
            'AWS_EC2_METADATA_SERVICE_ENDPOINT' => 'http://127.0.0.1:1338/',
        ])->getCredentials();
        self::assertSame('http://127.0.0.1:1338/latest/api/token', $transport->getRequests()[0]->url);
    }

    public function testC11BadModeIsAConfigurationError(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->provider(new FakeTransport(), ['AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE' => 'IPv5'])->getCredentials();
    }

    public function testC11DisabledMeansZeroCalls(): void
    {
        $transport = new FakeTransport();
        try {
            $this->provider($transport, ['AWS_EC2_METADATA_DISABLED' => 'TRUE'])->getCredentials();
            self::fail('Expected not found.');
        } catch (CredentialsNotFoundException $e) {
            self::assertStringContainsString('AWS_EC2_METADATA_DISABLED', $e->getMessage());
            self::assertSame(0, $transport->count());
        }
    }

    public function testC12ConnectFailureIsNotFoundAfterOneRetry(): void
    {
        $transport = new FakeTransport([
            HttpResponse::failure('Failed to connect: No route to host'),
            HttpResponse::failure('Failed to connect: No route to host'),
        ]);
        try {
            $this->provider($transport)->getCredentials();
            self::fail('Expected not found.');
        } catch (CredentialsNotFoundException $e) {
            self::assertStringContainsString('not on EC2', $e->getMessage());
            self::assertSame(2, $transport->count());
            self::assertSame(1.0, $transport->getRequests()[0]->connectTimeout);
            self::assertSame(2.0, $transport->getRequests()[0]->timeout);
        }
    }

    public function testC12RetryRecoversFromOneLostRequest(): void
    {
        $transport = new FakeTransport([HttpResponse::failure('timed out', true), Imds::token(), Imds::role(), Imds::credentials()]);
        self::assertSame(Imds::KEY, $this->provider($transport)->getCredentials()->getAccessKeyId());
    }

    public function testC12RetriesAndTimeoutsAreConfigurable(): void
    {
        $transport = new FakeTransport([HttpResponse::failure('timed out', true)]);
        try {
            $this->provider($transport, [], retries: 0, connectTimeout: 0.25, timeout: 0.5)->getCredentials();
            self::fail('Expected not found.');
        } catch (CredentialsNotFoundException) {
            self::assertSame(1, $transport->count());
            self::assertSame(0.25, $transport->getRequests()[0]->connectTimeout);
            self::assertSame(0.5, $transport->getRequests()[0]->timeout);
        }
    }

    public function testC13TimeoutMessageNamesTheHopLimit(): void
    {
        $transport = new FakeTransport([HttpResponse::failure('timed out', true), HttpResponse::failure('timed out', true)]);
        $this->expectException(CredentialsNotFoundException::class);
        $this->expectExceptionMessage('token request timed out (not on EC2?); if running in a container, the instance metadata hop limit may need to be 2');
        $this->provider($transport)->getCredentials();
    }

    /**
     * @return iterable<string, array{0: int}>
     */
    public static function refusedTokenStatuses(): iterable
    {
        yield '403' => [403];
        yield '404' => [404];
        yield '405' => [405];
    }

    #[DataProvider('refusedTokenStatuses')]
    public function testC14RefusedTokenNeverFallsBackToImdsV1(int $status): void
    {
        $transport = new FakeTransport([new HttpResponse($status)]);
        try {
            $this->provider($transport)->getCredentials();
            self::fail('Expected an exception.');
        } catch (CredentialsException $e) {
            self::assertStringContainsString('IMDSv2', $e->getMessage());
            self::assertSame(1, $transport->count());
            foreach ($transport->getRequests() as $request) {
                self::assertNotSame('GET', $request->method);
            }
        }
    }

    public function testC15ExpiredTokenIsRefreshedOnceAndTheGetRetriedOnce(): void
    {
        $transport = new FakeTransport([
            Imds::token('old'),
            new HttpResponse(401),
            Imds::token('new'),
            Imds::role(),
            Imds::credentials(),
        ]);
        $this->provider($transport)->getCredentials();
        $requests = $transport->getRequests();
        self::assertSame(['PUT', 'GET', 'PUT', 'GET', 'GET'], array_map(static fn ($r): string => $r->method, $requests));
        self::assertSame('new', $requests[3]->headers['X-aws-ec2-metadata-token']);
    }

    public function testC15SecondUnauthorisedIsAnError(): void
    {
        $transport = new FakeTransport([Imds::token(), new HttpResponse(401), Imds::token(), new HttpResponse(401)]);
        $this->expectException(CredentialsException::class);
        $this->expectExceptionMessage('HTTP 401');
        $this->provider($transport)->getCredentials();
    }

    /**
     * @return iterable<string, array{0: HttpResponse}>
     */
    public static function noRole(): iterable
    {
        yield '404' => [new HttpResponse(404)];
        yield 'empty body' => [new HttpResponse(200, [], "\n")];
    }

    #[DataProvider('noRole')]
    public function testC16NoInstanceRole(HttpResponse $listing): void
    {
        $this->expectException(CredentialsException::class);
        $this->expectExceptionMessage('no instance role attached');
        $this->provider(new FakeTransport([Imds::token(), $listing]))->getCredentials();
    }

    public function testC17NoForwardedForAndTheTransportDisablesProxyAndRedirects(): void
    {
        $transport = self::happy();
        $this->provider($transport)->getCredentials();
        $curl = extension_loaded('curl') ? new CurlTransport() : null;
        foreach ($transport->getRequests() as $request) {
            foreach (array_keys($request->headers) as $name) {
                self::assertNotSame('x-forwarded-for', strtolower($name));
            }
            if ($curl !== null) {
                $options = $curl->buildOptions($request);
                self::assertSame('*', $options[CURLOPT_NOPROXY]);
                self::assertSame('', $options[CURLOPT_PROXY]);
                self::assertFalse($options[CURLOPT_FOLLOWLOCATION]);
            }
        }
    }

    public function testC19UnparseableExpiryThrows(): void
    {
        $this->expectException(CredentialsException::class);
        $this->expectExceptionMessage('not an ISO 8601');
        $this->provider(new FakeTransport([Imds::token(), Imds::role(), Imds::credentials('tomorrow')]))->getCredentials();
    }

    public function testC19PastExpiryIsReturnedFlaggedAndWarned(): void
    {
        $credentials = $this->provider(
            new FakeTransport([Imds::token(), Imds::role(), Imds::credentials('2026-11-11T11:00:00Z')]),
        )->getCredentials();
        self::assertTrue($credentials->needsRefresh($this->clock->now()));
        self::assertCount(1, $this->logger->level('warning'));
    }

    public function testExpiryWithOffsetAndFractionIsParsedAsUtc(): void
    {
        $credentials = $this->provider(
            new FakeTransport([Imds::token(), Imds::role(), Imds::credentials('2026-11-11T23:30:00.123+05:30')]),
        )->getCredentials();
        self::assertSame('2026-11-11T18:00:00+00:00', $credentials->getExpiresAt()?->format(DATE_ATOM));
    }

    public function testF6CredentialsServerErrorThrows(): void
    {
        $this->expectException(CredentialsException::class);
        $this->provider(new FakeTransport([Imds::token(), Imds::role(), new HttpResponse(500)]))->getCredentials();
    }

    public function testT5OversizedCredentialsResponseIsRefused(): void
    {
        $this->expectException(CredentialsException::class);
        $this->provider(new FakeTransport([
            Imds::token(),
            Imds::role(),
            new HttpResponse(200, [], str_repeat(' ', 65 * 1024)),
        ]))->getCredentials();
    }
}
