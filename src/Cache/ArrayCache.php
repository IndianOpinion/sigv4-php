<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Cache;

use IndianOpinion\SigV4\Clock\Clock;
use IndianOpinion\SigV4\Clock\SystemClock;

/**
 * In-process cache. Lives as long as the object. Useful in tests and in
 * long-running workers that share one cache between several providers.
 */
final class ArrayCache implements CredentialCache
{
    /** @var array<string, array{0: string, 1: int}> value and expiry timestamp */
    private array $entries = [];
    private readonly Clock $clock;

    public function __construct(?Clock $clock = null)
    {
        $this->clock = $clock ?? new SystemClock();
    }

    public function get(string $key): ?string
    {
        if (!isset($this->entries[$key])) {
            return null;
        }
        [$value, $expiresAt] = $this->entries[$key];
        if ($expiresAt <= $this->clock->now()->getTimestamp()) {
            unset($this->entries[$key]);

            return null;
        }

        return $value;
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $this->entries[$key] = [$value, $this->clock->now()->getTimestamp() + max(1, $ttl)];
    }

    public function delete(string $key): bool
    {
        unset($this->entries[$key]);

        return true;
    }
}
