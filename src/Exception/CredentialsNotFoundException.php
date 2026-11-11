<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Exception;

/**
 * A provider found nothing to use, or a whole chain found nothing.
 *
 * A chain moves on to its next provider when it catches this. When the whole
 * chain finds nothing it throws one of these whose reasons list every
 * provider tried and why each declined.
 */
final class CredentialsNotFoundException extends SigV4Exception
{
    /** @var list<string> */
    private array $reasons;

    /**
     * @param list<string> $reasons
     */
    public function __construct(string $message, array $reasons = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->reasons = $reasons === [] ? [$message] : $reasons;
    }

    /**
     * Why each provider declined, one line per provider.
     *
     * @return list<string>
     */
    public function getReasons(): array
    {
        return $this->reasons;
    }
}
