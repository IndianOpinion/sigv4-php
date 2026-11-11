<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Cache\EncryptedCache;
use IndianOpinion\SigV4\Clock\Clock;
use IndianOpinion\SigV4\Clock\SystemClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Internal\Logger;

/**
 * Caches another provider's credentials in memory and, optionally, in an
 * encrypted shared cache.
 *
 * Read order: memory, shared cache, provider. A cached credential is used
 * only while `expiry - margin > now`. Credentials without an expiry, and
 * static or environment credentials, are never written to shared storage.
 * Shared cache failures are logged as warnings and never reach the caller.
 */
final class CachingProvider implements RefreshableProvider
{
    public const DEFAULT_CACHE_KEY = 'indianopinion.sigv4.credentials.v1';
    public const DEFAULT_MARGIN = 300;
    public const DEFAULT_MIN_SHARED_TTL = 60;

    private readonly Clock $clock;
    private readonly Logger $logger;
    private ?Credentials $memory = null;

    /**
     * @param (callable(string, string, array<string, mixed>): mixed)|null $logger
     */
    public function __construct(
        private readonly Provider $provider,
        private readonly ?EncryptedCache $sharedCache = null,
        ?Clock $clock = null,
        ?callable $logger = null,
        private readonly int $marginSeconds = self::DEFAULT_MARGIN,
        private readonly int $minSharedTtl = self::DEFAULT_MIN_SHARED_TTL,
        private readonly string $cacheKey = self::DEFAULT_CACHE_KEY,
    ) {
        if ($marginSeconds < 0 || $minSharedTtl < 0) {
            throw new ConfigurationException('The refresh margin and minimum shared TTL must not be negative.');
        }
        if ($cacheKey === '' || strlen($cacheKey) > 200) {
            throw new ConfigurationException('The cache key must be 1 to 200 characters.');
        }
        $this->clock = $clock ?? new SystemClock();
        $this->logger = new Logger($logger);
    }

    public function getCredentials(): Credentials
    {
        $now = $this->clock->now();
        if ($this->memory !== null && !$this->memory->needsRefresh($now, $this->marginSeconds)) {
            return $this->memory;
        }
        $this->memory = null;

        if ($this->sharedCache !== null) {
            $cached = $this->sharedCache->getCredentials($this->cacheKey);
            if ($cached !== null && !$cached->needsRefresh($now, $this->marginSeconds)) {
                $this->logger->debug('Credential cache hit (shared)', ['source' => $cached->getSource()]);
                $this->memory = $cached;

                return $cached;
            }
            $this->logger->debug('Credential cache miss (shared)', []);
        }

        return $this->fetchAndStore();
    }

    public function refresh(): Credentials
    {
        $this->memory = null;
        $this->logger->debug('Forced credential refresh', []);

        return $this->fetchAndStore();
    }

    /**
     * Forgets the credentials in memory and in the shared cache.
     */
    public function invalidate(): void
    {
        $this->memory = null;
        $this->sharedCache?->invalidate($this->cacheKey);
    }

    private function fetchAndStore(): Credentials
    {
        $credentials = $this->provider->getCredentials();
        $now = $this->clock->now();
        $this->memory = $credentials;

        if ($this->sharedCache === null) {
            return $credentials;
        }
        $expiresAt = $credentials->getExpiresAt();
        if ($expiresAt === null || in_array($credentials->getSource(), ['static', 'env'], true)) {
            return $credentials;
        }
        $ttl = $expiresAt->getTimestamp() - $this->marginSeconds - $now->getTimestamp();
        if ($ttl < $this->minSharedTtl) {
            $this->logger->debug('Credentials not written to the shared cache: too close to expiry', ['ttl' => $ttl]);

            return $credentials;
        }
        $this->sharedCache->putCredentials($this->cacheKey, $credentials, $ttl);

        return $credentials;
    }
}
