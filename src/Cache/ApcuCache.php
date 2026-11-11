<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Cache;

use IndianOpinion\SigV4\Exception\CacheException;

/**
 * APCu adapter: shared by every PHP-FPM worker of one pool on one machine.
 * Wrap it in {@see EncryptedCache}; the caching provider accepts nothing else.
 */
final class ApcuCache implements CredentialCache
{
    /**
     * @throws CacheException when APCu is not loaded or not enabled (apc.enable_cli for the CLI)
     */
    public function __construct(private readonly string $prefix = '')
    {
        if (!extension_loaded('apcu') || !function_exists('apcu_enabled') || !apcu_enabled()) {
            throw new CacheException('The APCu extension is not loaded or not enabled.');
        }
    }

    public function get(string $key): ?string
    {
        $success = false;
        $value = apcu_fetch($this->prefix . $key, $success);

        return $success && is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, int $ttl): void
    {
        if (!apcu_store($this->prefix . $key, $value, max(1, $ttl))) {
            throw new CacheException('APCu refused to store the entry.');
        }
    }

    public function delete(string $key): bool
    {
        apcu_delete($this->prefix . $key);

        return !apcu_exists($this->prefix . $key);
    }
}
