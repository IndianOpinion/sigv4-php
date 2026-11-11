<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Cache\ArrayCache;
use IndianOpinion\SigV4\Cache\EncryptedCache;
use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Credentials\CachingProvider;
use IndianOpinion\SigV4\Credentials\ChainProvider;
use IndianOpinion\SigV4\Credentials\ContainerProvider;
use IndianOpinion\SigV4\Credentials\Environment;
use IndianOpinion\SigV4\Credentials\EnvironmentProvider;
use IndianOpinion\SigV4\Credentials\InstanceMetadataProvider;
use IndianOpinion\SigV4\Exception\SigV4Exception;
use IndianOpinion\SigV4\Http\FakeTransport;
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;
use IndianOpinion\SigV4\SigningOptions;
use IndianOpinion\SigV4\Tests\Support\Imds;
use IndianOpinion\SigV4\Tests\Support\RecordingLogger;
use PHPUnit\Framework\TestCase;

/**
 * F15: no exception message, log line or debug output carries a secret
 * key, session token, signing key or container authorization token.
 */
final class SecretLeakTest extends TestCase
{
    private const SECRET = 'LEAKCHECK-secret-access-key-000000001';
    private const TOKEN = 'LEAKCHECK-session-token-0000000000001';
    private const CONTAINER_TOKEN = 'LEAKCHECK-container-authorization-01';

    /** @var list<string> */
    private array $texts = [];
    private RecordingLogger $logger;
    private FrozenClock $clock;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->clock = new FrozenClock('2026-11-11T12:00:00Z');
    }

    private function capture(callable $call): void
    {
        try {
            $result = $call();
            $this->texts[] = print_r($result, true);
        } catch (SigV4Exception $e) {
            for ($x = $e; $x !== null; $x = $x->getPrevious()) {
                $this->texts[] = $x->getMessage();
            }
        }
    }

    private static function body(string $code = 'Success', string $expiration = '2026-11-11T18:00:00Z'): string
    {
        return (string) json_encode([
            'Code' => $code,
            'AccessKeyId' => 'ASIALEAKCHECK',
            'SecretAccessKey' => self::SECRET,
            'Token' => self::TOKEN,
            'Expiration' => $expiration,
        ]);
    }

    public function testNothingLeaks(): void
    {
        $credentials = new Credentials('AKIDLEAKCHECK', self::SECRET, self::TOKEN, new \DateTimeImmutable('2026-11-11T12:10:00Z'), 'imds');
        $signer = new Signer($this->clock, $this->logger);
        $request = new Request('GET', 'https://b.s3.amazonaws.com/k');

        // Signing and presigning, including their failures.
        $this->capture(fn () => $signer->sign($request, $credentials, 'us-east-1', 's3'));
        $this->capture(fn () => $signer->sign($request, $credentials, 'BAD', 's3'));
        $this->capture(fn () => $signer->presign($request, $credentials, 'us-east-1', 's3', 3600));
        $this->capture(fn () => $signer->presign($request, $credentials, 'us-east-1', 's3', 3600, new SigningOptions(strictPresignExpiry: false)));
        $this->capture(fn () => (string) $credentials);
        $this->capture(fn () => new Credentials('AKID', self::SECRET . "\n"));
        $this->capture(fn () => new Credentials('AKID', 'x', self::TOKEN . "\r\n"));

        // Instance metadata answers that carry secrets in a failing body.
        $imds = fn (HttpResponse $credentialsResponse) => new InstanceMetadataProvider(
            new Environment([]),
            new FakeTransport([Imds::token(), Imds::role(), $credentialsResponse]),
            $this->clock,
            $this->logger,
        );
        $this->capture(fn () => $imds(new HttpResponse(200, [], self::body('Failure ' . self::SECRET)))->getCredentials());
        $this->capture(fn () => $imds(new HttpResponse(200, [], self::body('Success', self::TOKEN)))->getCredentials());
        $this->capture(fn () => $imds(new HttpResponse(200, [], self::body('Success', '2026-11-11T11:00:00Z')))->getCredentials());
        $this->capture(fn () => $imds(new HttpResponse(500, [], self::body()))->getCredentials());
        $this->capture(fn () => $imds(new HttpResponse(200, [], '{"broken": "' . self::SECRET))->getCredentials());

        // Container endpoint, with the authorization token in play.
        $container = fn (array $env, HttpResponse $response) => new ContainerProvider(
            new Environment($env),
            new FakeTransport([$response]),
            $this->clock,
            $this->logger,
        );
        $full = ['AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://localhost/c', 'AWS_CONTAINER_AUTHORIZATION_TOKEN' => self::CONTAINER_TOKEN];
        $this->capture(fn () => $container($full, new HttpResponse(401, [], 'denied ' . self::CONTAINER_TOKEN))->getCredentials());
        $this->capture(fn () => $container($full, new HttpResponse(200, [], '{"Token":"' . self::TOKEN . '"}'))->getCredentials());
        $this->capture(fn () => $container($full, HttpResponse::failure('refused'))->getCredentials());
        $this->capture(fn () => $container(
            ['AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://localhost/c', 'AWS_CONTAINER_AUTHORIZATION_TOKEN' => self::CONTAINER_TOKEN . "\r\nX: y"],
            new HttpResponse(200),
        )->getCredentials());
        $this->capture(fn () => $container(
            ['AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://evil.example.com/' . self::CONTAINER_TOKEN],
            new HttpResponse(200),
        )->getCredentials());

        // Environment and chain.
        $this->capture(fn () => (new EnvironmentProvider(new Environment(['AWS_SECRET_ACCESS_KEY' => self::SECRET])))->getCredentials());
        $this->capture(fn () => (new ChainProvider([new EnvironmentProvider(new Environment([]))], $this->logger))->getCredentials());

        // Caches: decrypt failures and write failures are warnings.
        $store = new ArrayCache($this->clock);
        $encrypted = new EncryptedCache($store, 'leak-check-application-secret', $this->logger);
        $caching = new CachingProvider(
            new InstanceMetadataProvider(new Environment([]), new FakeTransport([Imds::token(), Imds::role(), new HttpResponse(200, [], self::body())]), $this->clock, $this->logger),
            $encrypted,
            $this->clock,
            $this->logger,
        );
        $store->set(CachingProvider::DEFAULT_CACHE_KEY, base64_encode(self::SECRET . str_repeat('x', 64)), 600);
        $this->capture(fn () => $caching->getCredentials());

        self::assertNotEmpty($this->texts);
        $haystack = implode("\n", $this->texts) . "\n" . $this->logger->dump();
        $signingKey = Signer::deriveSigningKey(self::SECRET, '20261111', 'us-east-1', 's3');
        foreach ([self::SECRET, self::TOKEN, self::CONTAINER_TOKEN, rawurlencode(self::TOKEN), bin2hex($signingKey)] as $needle) {
            self::assertStringNotContainsString($needle, $haystack);
        }
        self::assertStringNotContainsString($signingKey, $haystack);
    }
}
