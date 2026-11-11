<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Support;

/**
 * A minimal object with the PSR-16 get, set and delete signatures, to test
 * the duck-typed adapter without installing psr/simple-cache.
 */
final class ArrayPsr16
{
    /** @var array<string, mixed> */
    public array $data = [];

    /** @var list<int|null> */
    public array $ttls = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->data[$key] = $value;
        $this->ttls[] = is_int($ttl) ? $ttl : null;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);

        return true;
    }
}
