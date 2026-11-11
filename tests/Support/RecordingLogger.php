<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Support;

/**
 * Collects log lines for assertions. Invoke it as the logger callable.
 */
final class RecordingLogger
{
    /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
    public array $records = [];

    /**
     * @param array<string, mixed> $context
     */
    public function __invoke(string $level, string $message, array $context = []): void
    {
        $this->records[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }

    /**
     * @return list<array{level: string, message: string, context: array<string, mixed>}>
     */
    public function level(string $level): array
    {
        return array_values(array_filter($this->records, static fn (array $r): bool => $r['level'] === $level));
    }

    public function dump(): string
    {
        return (string) json_encode($this->records, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }
}
