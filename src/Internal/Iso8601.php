<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Internal;

/**
 * Strict ISO 8601 parsing for credential expiry times.
 *
 * @internal
 */
final class Iso8601
{
    private const PATTERN = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$/';

    /**
     * Returns the instant in UTC, or null when the text is not a full ISO
     * 8601 date and time with a zone. Words such as "now" are never accepted.
     */
    public static function parse(string $value): ?\DateTimeImmutable
    {
        if (preg_match(self::PATTERN, $value, $m) !== 1) {
            return null;
        }
        // Drop fractional seconds: PHP accepts at most six digits.
        $clean = $m[1] !== '' ? str_replace($m[1], '', $value) : $value;
        $parsed = \DateTimeImmutable::createFromFormat('Y-m-d\TH:i:sP', $clean);
        if ($parsed === false) {
            return null;
        }
        $errors = \DateTimeImmutable::getLastErrors();
        if (is_array($errors) && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) {
            return null;
        }

        return $parsed->setTimezone(new \DateTimeZone('UTC'));
    }
}
