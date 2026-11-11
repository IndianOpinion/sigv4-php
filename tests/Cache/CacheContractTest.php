<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Cache;

use IndianOpinion\SigV4\Cache\ApcuCache;
use IndianOpinion\SigV4\Cache\ArrayCache;
use IndianOpinion\SigV4\Cache\CredentialCache;
use IndianOpinion\SigV4\Cache\FileCache;
use IndianOpinion\SigV4\Cache\Psr16Cache;
use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Exception\CacheException;
use IndianOpinion\SigV4\Tests\Support\ArrayPsr16;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * K2: every shipped adapter passes the same contract.
 */
final class CacheContractTest extends TestCase
{
    private static ?string $dir = null;

    public static function tearDownAfterClass(): void
    {
        if (self::$dir !== null && is_dir(self::$dir)) {
            foreach (glob(self::$dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir(self::$dir);
        }
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function adapters(): iterable
    {
        yield 'array' => ['array'];
        yield 'file' => ['file'];
        yield 'psr16' => ['psr16'];
        yield 'apcu' => ['apcu'];
    }

    private function make(string $name, FrozenClock $clock): CredentialCache
    {
        switch ($name) {
            case 'array':
                return new ArrayCache($clock);
            case 'file':
                self::$dir ??= sys_get_temp_dir() . '/sigv4-cache-' . bin2hex(random_bytes(4));

                return new FileCache(self::$dir, $clock);
            case 'psr16':
                return new Psr16Cache(new ArrayPsr16());
            default:
                if (!extension_loaded('apcu') || !function_exists('apcu_enabled') || !apcu_enabled()) {
                    self::markTestSkipped('APCu is not loaded or not enabled for the CLI.');
                }

                return new ApcuCache('sigv4-test-');
        }
    }

    #[DataProvider('adapters')]
    public function testContract(string $name): void
    {
        $clock = new FrozenClock('2026-11-11T12:00:00Z');
        $cache = $this->make($name, $clock);
        $key = 'contract-' . bin2hex(random_bytes(4));

        self::assertNull($cache->get($key));
        $cache->set($key, "value with\nnewline and \x00 byte", 120);
        self::assertSame("value with\nnewline and \x00 byte", $cache->get($key));
        $cache->set($key, 'second', 120);
        self::assertSame('second', $cache->get($key));
        self::assertTrue($cache->delete($key));
        self::assertNull($cache->get($key));
        self::assertTrue($cache->delete($key));
        $cache->set($key, '', 60);
        self::assertContains($cache->get($key), ['', null]);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function clockedAdapters(): iterable
    {
        yield 'array' => ['array'];
        yield 'file' => ['file'];
    }

    #[DataProvider('clockedAdapters')]
    public function testEntriesExpire(string $name): void
    {
        $clock = new FrozenClock('2026-11-11T12:00:00Z');
        $cache = $this->make($name, $clock);
        $cache->set('expiring', 'v', 10);
        $clock->advance(9);
        self::assertSame('v', $cache->get('expiring'));
        $clock->advance(1);
        self::assertNull($cache->get('expiring'));
    }

    public function testFileCacheWritesPrivateFiles(): void
    {
        $clock = new FrozenClock('2026-11-11T12:00:00Z');
        $cache = $this->make('file', $clock);
        $cache->set('mode', 'v', 10);
        $files = glob((string) self::$dir . '/sigv4-*.cache') ?: [];
        self::assertNotEmpty($files);
        self::assertSame(0600, fileperms($files[0]) & 0777);
    }

    public function testFileCacheRefusesAnUnwritableDirectory(): void
    {
        $this->expectException(CacheException::class);
        new FileCache('/proc/sigv4-cannot-exist');
    }

    public function testPsr16AdapterHashesKeysAndPassesTtl(): void
    {
        $backend = new ArrayPsr16();
        (new Psr16Cache($backend))->set('a key {with} reserved/chars:@', 'v', 300);
        self::assertSame([300], $backend->ttls);
        foreach (array_keys($backend->data) as $key) {
            self::assertMatchesRegularExpression('/^sigv4_[0-9a-f]{64}$/', $key);
        }
    }

    public function testPsr16AdapterRefusesAnObjectWithoutTheMethods(): void
    {
        $this->expectException(CacheException::class);
        new Psr16Cache(new \stdClass());
    }

    public function testApcuAdapterRefusesToBuildWithoutApcu(): void
    {
        if (extension_loaded('apcu') && function_exists('apcu_enabled') && apcu_enabled()) {
            self::markTestSkipped('APCu is available here.');
        }
        $this->expectException(CacheException::class);
        new ApcuCache();
    }
}
