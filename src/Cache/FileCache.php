<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Cache;

use IndianOpinion\SigV4\Clock\Clock;
use IndianOpinion\SigV4\Clock\SystemClock;
use IndianOpinion\SigV4\Exception\CacheException;

/**
 * One file per key in a directory you own. Files are written atomically
 * (temporary file, then rename) with mode 0600. Wrap it in
 * {@see EncryptedCache}; the caching provider accepts nothing else.
 */
final class FileCache implements CredentialCache
{
    private readonly string $directory;
    private readonly Clock $clock;

    /**
     * @throws CacheException when the directory cannot be created or written
     */
    public function __construct(string $directory, ?Clock $clock = null)
    {
        $directory = rtrim($directory, '/\\');
        if ($directory === '') {
            throw new CacheException('The cache directory is empty.');
        }
        if (!is_dir($directory)) {
            self::quietly(static fn (): bool => mkdir($directory, 0700, true));
        }
        if (!is_dir($directory) || !is_writable($directory)) {
            throw new CacheException('The cache directory does not exist or is not writable.');
        }
        $this->directory = $directory;
        $this->clock = $clock ?? new SystemClock();
    }

    public function get(string $key): ?string
    {
        $file = $this->path($key);
        if (!is_file($file)) {
            return null;
        }
        $raw = self::quietly(static fn (): string|false => file_get_contents($file));
        if (!is_string($raw)) {
            throw new CacheException('The cache file could not be read.');
        }
        $newline = strpos($raw, "\n");
        if ($newline === false || !ctype_digit(substr($raw, 0, $newline))) {
            return null;
        }
        if ((int) substr($raw, 0, $newline) <= $this->clock->now()->getTimestamp()) {
            return null;
        }

        return substr($raw, $newline + 1);
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $expiresAt = $this->clock->now()->getTimestamp() + max(1, $ttl);
        $file = $this->path($key);
        $temp = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $written = self::quietly(static function () use ($temp, $expiresAt, $value): bool {
            $handle = fopen($temp, 'xb');
            if ($handle === false) {
                return false;
            }
            chmod($temp, 0600);
            $ok = fwrite($handle, $expiresAt . "\n" . $value) !== false;

            return fclose($handle) && $ok;
        });
        if ($written !== true || self::quietly(static fn (): bool => rename($temp, $file)) !== true) {
            if (is_file($temp)) {
                self::quietly(static fn (): bool => unlink($temp));
            }
            throw new CacheException('The cache file could not be written.');
        }
    }

    public function delete(string $key): bool
    {
        $file = $this->path($key);
        if (!is_file($file)) {
            return true;
        }
        $removed = self::quietly(static fn (): bool => unlink($file));
        clearstatcache(true, $file);

        return $removed === true || !file_exists($file);
    }

    private function path(string $key): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . 'sigv4-' . hash('sha256', $key) . '.cache';
    }

    /**
     * Runs a filesystem call with warnings turned into a return value, so
     * failures are reported through exceptions and not PHP warnings.
     *
     * @template T
     *
     * @param callable(): T $call
     *
     * @return T|false
     */
    private static function quietly(callable $call): mixed
    {
        set_error_handler(static fn (): bool => true);
        try {
            return $call();
        } finally {
            restore_error_handler();
        }
    }
}
