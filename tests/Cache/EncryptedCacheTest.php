<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Cache;

use IndianOpinion\SigV4\Cache\ArrayCache;
use IndianOpinion\SigV4\Cache\EncryptedCache;
use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\CacheException;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Tests\Support\RecordingLogger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Encryption at rest: K9 to K13.
 */
final class EncryptedCacheTest extends TestCase
{
    private const SECRET_A = 'first-application-secret-0123456789';
    private const SECRET_B = 'second-application-secret-987654321';

    private ArrayCache $store;
    private RecordingLogger $logger;

    protected function setUp(): void
    {
        if (!EncryptedCache::sodiumAvailable()) {
            self::markTestSkipped('sodium is not available.');
        }
        $this->store = new ArrayCache(new FrozenClock('2026-11-11T12:00:00Z'));
        $this->logger = new RecordingLogger();
    }

    private function credentials(): Credentials
    {
        return new Credentials(
            'ASIAEXAMPLEKEYID0001',
            'very-secret-access-key-value-0001',
            'very-secret-session-token-value-0001',
            new \DateTimeImmutable('2026-11-11T18:00:00Z'),
            'imds',
        );
    }

    private function cache(string $secret = self::SECRET_A): EncryptedCache
    {
        return new EncryptedCache($this->store, $secret, $this->logger);
    }

    public function testK9StoredBlobIsBase64AndHidesEveryCredentialPart(): void
    {
        $cache = $this->cache();
        $cache->putCredentials('k', $this->credentials(), 300);
        $blob = (string) $this->store->get('k');
        self::assertMatchesRegularExpression('#^[A-Za-z0-9+/]+=*$#', $blob);
        self::assertNotFalse(base64_decode($blob, true));
        $decoded = (string) base64_decode($blob, true);
        foreach ([$blob, $decoded] as $text) {
            self::assertStringNotContainsString('ASIAEXAMPLEKEYID0001', $text);
            self::assertStringNotContainsString('very-secret-access-key-value-0001', $text);
            self::assertStringNotContainsString('very-secret-session-token-value-0001', $text);
        }
        $cache->putCredentials('k', $this->credentials(), 300);
        self::assertNotSame($blob, $this->store->get('k'), 'a fresh nonce makes each write different');
        self::assertSame('ASIAEXAMPLEKEYID0001', $cache->getCredentials('k')?->getAccessKeyId());
    }

    public function testK10KeysDependOnSecretAndLabelVersion(): void
    {
        self::assertNotSame(EncryptedCache::deriveKey(self::SECRET_A), EncryptedCache::deriveKey(self::SECRET_B));
        self::assertNotSame(
            EncryptedCache::deriveKey(self::SECRET_A),
            EncryptedCache::deriveKey(self::SECRET_A, 'indianopinion/sigv4-php credential-cache v2'),
        );
        self::assertSame(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, strlen(EncryptedCache::deriveKey(self::SECRET_A)));
        self::assertStringContainsString('v1', EncryptedCache::KEY_LABEL);
    }

    public function testK10ShortSecretIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->cache('short');
    }

    /**
     * @return iterable<string, array{0: callable(string): string}>
     */
    public static function corruptions(): iterable
    {
        yield 'truncated' => [static fn (string $blob): string => substr($blob, 0, 40)];
        yield 'flipped byte' => [static function (string $blob): string {
            $raw = (string) base64_decode($blob, true);
            $raw[30] = chr(ord($raw[30]) ^ 0x01);

            return base64_encode($raw);
        }];
        yield 'not base64' => [static fn (string $blob): string => '!!not base64!!'];
        yield 'empty marker' => [static fn (string $blob): string => ''];
    }

    /**
     * @param callable(string): string $corrupt
     */
    #[DataProvider('corruptions')]
    public function testK11CorruptEntriesAreMissesWithOneWarning(callable $corrupt): void
    {
        $cache = $this->cache();
        $cache->putCredentials('k', $this->credentials(), 300);
        $this->store->set('k', $corrupt((string) $this->store->get('k')), 300);
        self::assertNull($cache->getCredentials('k'));
        $expected = $this->store->get('k') === '' ? 0 : 1;
        self::assertCount($expected, $this->logger->level('warning'));
    }

    public function testK11WrongSecretAfterRotationIsAMiss(): void
    {
        $this->cache(self::SECRET_A)->putCredentials('k', $this->credentials(), 300);
        self::assertNull($this->cache(self::SECRET_B)->getCredentials('k'));
        self::assertCount(1, $this->logger->level('warning'));
    }

    public function testK12WithoutSodiumTheCacheRefusesToConstruct(): void
    {
        $this->expectException(CacheException::class);
        new EncryptedCache($this->store, self::SECRET_A, null, static fn (): bool => false);
    }

    public function testK13PayloadHasExactlyFiveFields(): void
    {
        $cache = $this->cache();
        $payload = $cache->decryptPayload($cache->encrypt($this->credentials()));
        self::assertIsArray($payload);
        self::assertSame(['accessKeyId', 'secretAccessKey', 'sessionToken', 'expiresAt', 'source'], array_keys($payload));
    }

    public function testRoundTripKeepsEveryField(): void
    {
        $cache = $this->cache();
        $cache->putCredentials('k', $this->credentials(), 300);
        $back = $cache->getCredentials('k');
        self::assertNotNull($back);
        self::assertSame('very-secret-access-key-value-0001', $back->getSecretAccessKey());
        self::assertSame('very-secret-session-token-value-0001', $back->getSessionToken());
        self::assertSame('2026-11-11T18:00:00+00:00', $back->getExpiresAt()?->format(DATE_ATOM));
        self::assertSame('imds', $back->getSource());
    }
}
