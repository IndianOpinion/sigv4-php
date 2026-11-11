<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Credentials;

use IndianOpinion\SigV4\Cache\ArrayCache;
use IndianOpinion\SigV4\Cache\CredentialCache;
use IndianOpinion\SigV4\Cache\EncryptedCache;
use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Credentials\CachingProvider;
use IndianOpinion\SigV4\Credentials\Environment;
use IndianOpinion\SigV4\Credentials\EnvironmentProvider;
use IndianOpinion\SigV4\Credentials\Provider;
use IndianOpinion\SigV4\Credentials\StaticProvider;
use IndianOpinion\SigV4\Tests\Support\CountingProvider;
use IndianOpinion\SigV4\Tests\Support\RecordingCache;
use IndianOpinion\SigV4\Tests\Support\RecordingLogger;
use PHPUnit\Framework\TestCase;

/**
 * Caching and refresh: K1, K3 to K8, K14, F9, F10.
 */
final class CachingProviderTest extends TestCase
{
    private const APP_SECRET = 'application-secret-at-least-16-bytes';

    private FrozenClock $clock;
    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-11-11T12:00:00Z');
        $this->logger = new RecordingLogger();
    }

    /**
     * A provider that hands out numbered temporary credentials expiring
     * $lifetime seconds after the clock's current time.
     */
    private function counting(int $lifetime = 3600): CountingProvider
    {
        return new CountingProvider($this->clock, $lifetime);
    }

    private function shared(?CredentialCache $inner = null): EncryptedCache
    {
        return new EncryptedCache($inner ?? new ArrayCache($this->clock), self::APP_SECRET, $this->logger);
    }

    private function caching(Provider $provider, ?EncryptedCache $shared = null): CachingProvider
    {
        return new CachingProvider($provider, $shared, $this->clock, $this->logger);
    }

    public function testK1SecondResolveUsesMemory(): void
    {
        $inner = $this->counting();
        $provider = $this->caching($inner);
        $first = $provider->getCredentials();
        self::assertSame($first, $provider->getCredentials());
        self::assertSame(1, $inner->calls);
    }

    public function testK3MarginBoundary(): void
    {
        $inner = $this->counting(601);
        $provider = $this->caching($inner);
        $provider->getCredentials();

        $this->clock->advance(300); // expiry is now+301
        $provider->getCredentials();
        self::assertSame(1, $inner->calls);

        $this->clock->advance(1); // expiry is now+300
        $provider->getCredentials();
        self::assertSame(2, $inner->calls);
    }

    public function testK3MarginIsConfigurable(): void
    {
        $inner = $this->counting(100);
        $provider = new CachingProvider($inner, null, $this->clock, null, marginSeconds: 10);
        $provider->getCredentials();
        $this->clock->advance(89);
        $provider->getCredentials();
        self::assertSame(1, $inner->calls);
    }

    public function testK4SharedTtlIsExpiryMinusMarginMinusNow(): void
    {
        $inner = new RecordingCache($this->clock);
        $this->caching($this->counting(3600), $this->shared($inner))->getCredentials();
        self::assertSame([3300], $inner->ttls);
    }

    public function testK4UnderSixtySecondsIsNotWritten(): void
    {
        $inner = new RecordingCache($this->clock);
        $this->caching($this->counting(359), $this->shared($inner))->getCredentials();
        self::assertSame([], $inner->ttls);
    }

    public function testK5StaticAndEnvironmentCredentialsNeverReachTheSharedCache(): void
    {
        $inner = new RecordingCache($this->clock);
        $this->caching(
            StaticProvider::fromKeys('AKID', 'secret', 'token', new \DateTimeImmutable('2026-11-12T00:00:00Z')),
            $this->shared($inner),
        )->getCredentials();
        $this->caching(
            new EnvironmentProvider(new Environment(['AWS_ACCESS_KEY_ID' => 'AKID', 'AWS_SECRET_ACCESS_KEY' => 's'])),
            $this->shared($inner),
        )->getCredentials();
        self::assertSame([], $inner->ttls);
    }

    public function testK6SharedHitFillsMemory(): void
    {
        $inner = new RecordingCache($this->clock);
        $this->caching($this->counting(), $this->shared($inner))->getCredentials();

        $second = $this->counting();
        $provider = $this->caching($second, $this->shared($inner));
        $readsBefore = $inner->reads;
        $provider->getCredentials();
        $afterFirst = $inner->reads;
        $provider->getCredentials();
        $afterSecond = $inner->reads;
        self::assertSame($readsBefore + 1, $afterFirst);
        self::assertSame($afterFirst, $afterSecond);
        self::assertSame(0, $second->calls);
    }

    public function testK7ForcedRefreshBypassesAndOverwritesBothCaches(): void
    {
        $inner = new RecordingCache($this->clock);
        $counting = $this->counting();
        $provider = $this->caching($counting, $this->shared($inner));
        $first = $provider->getCredentials();
        $refreshed = $provider->refresh();
        self::assertSame(2, $counting->calls);
        self::assertNotSame($first->getAccessKeyId(), $refreshed->getAccessKeyId());
        self::assertSame($refreshed, $provider->getCredentials());

        $other = $this->caching($this->counting(), $this->shared($inner));
        self::assertSame($refreshed->getAccessKeyId(), $other->getCredentials()->getAccessKeyId());
    }

    public function testK8InvalidationWritesAnEmptyMarkerWhenDeleteFails(): void
    {
        $inner = new RecordingCache($this->clock);
        $inner->deleteWorks = false;
        $counting = $this->counting();
        $provider = $this->caching($counting, $this->shared($inner));
        $provider->getCredentials();
        $provider->invalidate();
        self::assertSame('', $inner->get(CachingProvider::DEFAULT_CACHE_KEY));

        $provider->getCredentials();
        self::assertSame(2, $counting->calls);
    }

    public function testK8InvalidationFailureIsReported(): void
    {
        $inner = new RecordingCache($this->clock);
        $inner->deleteWorks = false;
        $inner->failWrites = true;
        $this->shared($inner)->invalidate('key');
        self::assertCount(1, $this->logger->level('warning'));
    }

    public function testK14TwoProvidersRefreshingAtOnceBothSucceed(): void
    {
        $inner = new RecordingCache($this->clock);
        $a = $this->caching($this->counting(), $this->shared($inner));
        $b = $this->caching(new CountingProvider($this->clock, 3600, 'AKIDB'), $this->shared($inner));
        $a->refresh();
        $last = $b->refresh();
        $reader = $this->caching($this->counting(), $this->shared($inner));
        self::assertSame($last->getAccessKeyId(), $reader->getCredentials()->getAccessKeyId());
    }

    public function testF9UnreadableEntryIsAMissAndIsOverwritten(): void
    {
        $inner = new RecordingCache($this->clock);
        $inner->set(CachingProvider::DEFAULT_CACHE_KEY, 'garbage', 3000);
        $counting = $this->counting();
        $this->caching($counting, $this->shared($inner))->getCredentials();
        self::assertSame(1, $counting->calls);
        self::assertNotSame('garbage', $inner->get(CachingProvider::DEFAULT_CACHE_KEY));
        self::assertCount(1, $this->logger->level('warning'));
    }

    public function testF9ReadErrorIsAMiss(): void
    {
        $inner = new RecordingCache($this->clock);
        $inner->failReads = true;
        $counting = $this->counting();
        $this->caching($counting, $this->shared($inner))->getCredentials();
        self::assertSame(1, $counting->calls);
        self::assertCount(1, $this->logger->level('warning'));
    }

    public function testF10WriteErrorStillReturnsCredentialsAndWarns(): void
    {
        $inner = new RecordingCache($this->clock);
        $inner->failWrites = true;
        $credentials = $this->caching($this->counting(), $this->shared($inner))->getCredentials();
        self::assertSame('AKIDCOUNT1', $credentials->getAccessKeyId());
        self::assertCount(1, $this->logger->level('warning'));
    }
}
