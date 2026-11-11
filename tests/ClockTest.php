<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Clock\SystemClock;
use PHPUnit\Framework\TestCase;

/**
 * T4: frozen and offset clocks.
 */
final class ClockTest extends TestCase
{
    public function testFrozenClockStaysPutUntilMoved(): void
    {
        $clock = new FrozenClock('2026-11-11T12:00:00+05:30');
        self::assertSame('2026-11-11T06:30:00+00:00', $clock->now()->format(DATE_ATOM));
        self::assertSame($clock->now(), $clock->now());
        $clock->advance(90);
        self::assertSame('2026-11-11T06:31:30+00:00', $clock->now()->format(DATE_ATOM));
        $clock->advance(-30);
        self::assertSame('2026-11-11T06:31:00+00:00', $clock->now()->format(DATE_ATOM));
        $clock->set(new \DateTimeImmutable('2030-01-01T00:00:00Z'));
        self::assertSame('2030-01-01T00:00:00+00:00', $clock->now()->format(DATE_ATOM));
    }

    public function testSystemClockIsUtcAndAppliesTheOffset(): void
    {
        $plain = new SystemClock();
        $ahead = new SystemClock(120);
        $behind = new SystemClock(-60);
        $base = $plain->now()->getTimestamp();
        self::assertSame('+00:00', $plain->now()->format('P'));
        self::assertEqualsWithDelta($base + 120, $ahead->now()->getTimestamp(), 2);
        self::assertEqualsWithDelta($base - 60, $behind->now()->getTimestamp(), 2);
        self::assertSame(120, $ahead->getOffsetSeconds());
    }
}
