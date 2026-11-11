<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Cache;

use IndianOpinion\SigV4\Exception\CacheException;

/**
 * Adapter for any PSR-16 (simple cache) implementation, without depending
 * on psr/simple-cache: the object only needs get, set and delete methods
 * with the PSR-16 signatures. Wrap it in {@see EncryptedCache}.
 *
 * Keys are hashed so they always satisfy PSR-16 key rules.
 */
final class Psr16Cache implements CredentialCache
{
    private readonly \Closure $get;
    private readonly \Closure $set;
    private readonly \Closure $delete;

    /**
     * @param object $cache a Psr\SimpleCache\CacheInterface implementation
     *
     * @throws CacheException when the object lacks get, set or delete
     */
    public function __construct(object $cache)
    {
        foreach (['get', 'set', 'delete'] as $method) {
            if (!method_exists($cache, $method)) {
                throw new CacheException(sprintf('The PSR-16 cache object has no %s() method.', $method));
            }
        }
        $this->get = \Closure::fromCallable([$cache, 'get']);
        $this->set = \Closure::fromCallable([$cache, 'set']);
        $this->delete = \Closure::fromCallable([$cache, 'delete']);
    }

    public function get(string $key): ?string
    {
        try {
            $value = ($this->get)($this->key($key), null);
        } catch (\Throwable $e) {
            throw new CacheException('The PSR-16 cache failed to read.', 0, $e);
        }

        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, int $ttl): void
    {
        try {
            $ok = ($this->set)($this->key($key), $value, max(1, $ttl));
        } catch (\Throwable $e) {
            throw new CacheException('The PSR-16 cache failed to write.', 0, $e);
        }
        if ($ok === false) {
            throw new CacheException('The PSR-16 cache refused to write.');
        }
    }

    public function delete(string $key): bool
    {
        try {
            return ($this->delete)($this->key($key)) !== false;
        } catch (\Throwable $e) {
            throw new CacheException('The PSR-16 cache failed to delete.', 0, $e);
        }
    }

    private function key(string $key): string
    {
        return 'sigv4_' . hash('sha256', $key);
    }
}
