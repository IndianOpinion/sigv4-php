<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Support;

use IndianOpinion\SigV4\Cache\ArrayCache;
use IndianOpinion\SigV4\Cache\CredentialCache;
use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Exception\CacheException;

/**
 * An array cache that records TTLs and reads, and can be told to fail.
 */
final class RecordingCache implements CredentialCache
{
    /** @var list<int> */
    public array $ttls = [];
    public int $reads = 0;
    public bool $deleteWorks = true;
    public bool $failWrites = false;
    public bool $failReads = false;
    private ArrayCache $store;

    public function __construct(FrozenClock $clock)
    {
        $this->store = new ArrayCache($clock);
    }

    public function get(string $key): ?string
    {
        $this->reads++;
        if ($this->failReads) {
            throw new CacheException('read failed');
        }

        return $this->store->get($key);
    }

    public function set(string $key, string $value, int $ttl): void
    {
        if ($this->failWrites) {
            throw new CacheException('write failed');
        }
        if ($value !== '' && $value !== 'garbage') {
            $this->ttls[] = $ttl;
        }
        $this->store->set($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        if (!$this->deleteWorks) {
            return false;
        }

        return $this->store->delete($key);
    }
}
