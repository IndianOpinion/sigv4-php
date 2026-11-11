<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

/**
 * Reads environment variables the way PHP-FPM needs: getenv(), then $_ENV,
 * then $_SERVER, because FPM pools often expose a variable in only one of
 * them. An empty value counts as unset.
 *
 * Pass an array to the constructor to use a fixed set instead (tests,
 * or configuration that does not live in the environment).
 */
final class Environment
{
    /**
     * @param array<string, string>|null $values null reads the real environment
     */
    public function __construct(private readonly ?array $values = null)
    {
    }

    public static function fromGlobals(): self
    {
        return new self();
    }

    public function get(string $name): ?string
    {
        if ($this->values !== null) {
            $value = $this->values[$name] ?? null;

            return $value === '' ? null : $value;
        }
        $value = getenv($name);
        if (is_string($value) && $value !== '') {
            return $value;
        }
        foreach ([$_ENV, $_SERVER] as $source) {
            if (isset($source[$name]) && is_string($source[$name]) && $source[$name] !== '') {
                return $source[$name];
            }
        }

        return null;
    }
}
