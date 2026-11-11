<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Clock;

/**
 * The machine clock, in UTC, with an optional fixed offset in seconds.
 *
 * Use the offset to correct a host clock that drifts: AWS rejects requests
 * more than 15 minutes away from its own time. A positive offset moves the
 * signing time forward.
 */
final class SystemClock implements Clock
{
    public function __construct(private readonly int $offsetSeconds = 0)
    {
    }

    public function now(): \DateTimeImmutable
    {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        if ($this->offsetSeconds !== 0) {
            $now = $now->modify(sprintf('%+d seconds', $this->offsetSeconds));
        }

        return $now;
    }

    public function getOffsetSeconds(): int
    {
        return $this->offsetSeconds;
    }
}
