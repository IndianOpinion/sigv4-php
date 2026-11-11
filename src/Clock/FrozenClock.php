<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Clock;

/**
 * A clock that returns the same instant until told to move. For tests.
 */
final class FrozenClock implements Clock
{
    private \DateTimeImmutable $now;

    public function __construct(\DateTimeImmutable|string $now = 'now')
    {
        $this->now = self::toUtc($now);
    }

    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }

    /**
     * Moves the clock forward (or back, with a negative value) by whole seconds.
     */
    public function advance(int $seconds): void
    {
        $this->now = $this->now->modify(sprintf('%+d seconds', $seconds));
    }

    public function set(\DateTimeImmutable|string $now): void
    {
        $this->now = self::toUtc($now);
    }

    private static function toUtc(\DateTimeImmutable|string $now): \DateTimeImmutable
    {
        $utc = new \DateTimeZone('UTC');
        if (is_string($now)) {
            $now = new \DateTimeImmutable($now, $utc);
        }

        return $now->setTimezone($utc);
    }
}
