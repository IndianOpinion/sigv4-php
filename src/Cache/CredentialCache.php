<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Cache;

use IndianOpinion\SigV4\Exception\CacheException;

/**
 * A string key-value store with TTLs. Adapters store opaque strings; the
 * {@see EncryptedCache} decorator turns credentials into encrypted strings
 * before they reach an adapter.
 *
 * Adapters may throw CacheException on a run-time failure; the encrypted
 * cache catches it and logs a warning, so the failure never reaches code
 * that asked for credentials.
 */
interface CredentialCache
{
    /**
     * The stored value, or null on a miss or after expiry.
     *
     * @throws CacheException
     */
    public function get(string $key): ?string;

    /**
     * @param int $ttl seconds, at least 1
     *
     * @throws CacheException
     */
    public function set(string $key, string $value, int $ttl): void;

    /**
     * True when the entry is gone (or never existed), false when the backend
     * could not confirm the delete.
     *
     * @throws CacheException
     */
    public function delete(string $key): bool;
}
