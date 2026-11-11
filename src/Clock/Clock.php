<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Clock;

/**
 * Source of the current time. Every time-dependent part of the library reads
 * the time through this interface, so tests can freeze it.
 */
interface Clock
{
    /**
     * The current time. Implementations should return UTC; callers convert
     * to UTC anyway before formatting.
     */
    public function now(): \DateTimeImmutable;
}
