<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Internal;

/**
 * URI encoding and canonicalisation rules of Signature Version 4.
 *
 * @internal
 */
final class Uri
{
    /**
     * Encodes every byte except A-Z a-z 0-9 - . _ ~ as %XX with upper-case
     * hex. Space is %20. Multi-byte UTF-8 is encoded byte by byte.
     * PHP's rawurlencode() implements exactly RFC 3986 unreserved, which is
     * the SigV4 rule.
     */
    public static function encode(string $value): string
    {
        return rawurlencode($value);
    }

    /**
     * Decodes %XX sequences. A plus sign stays a plus sign.
     */
    public static function decode(string $value): string
    {
        return rawurldecode($value);
    }

    /**
     * Encodes a raw path for the wire: each segment once, slashes kept.
     */
    public static function encodePath(string $rawPath): string
    {
        return implode('/', array_map([self::class, 'encode'], explode('/', $rawPath)));
    }

    /**
     * Canonical URI for every service except S3: the wire path, optionally
     * normalised, with each segment encoded once more (so a raw space ends
     * up as %2520 when the wire carries %20).
     */
    public static function canonicalPathDoubleEncoded(string $wirePath, bool $normalize): string
    {
        if ($normalize) {
            $wirePath = self::normalize($wirePath);
        }
        if ($wirePath === '') {
            return '/';
        }

        return self::encodePath($wirePath);
    }

    /**
     * Canonical URI for S3-style services: the path is decoded and encoded
     * once, slashes are kept, and nothing is normalised (a//b, a/./b and
     * a/../b are distinct object keys).
     */
    public static function canonicalPathSingleEncoded(string $wirePath, bool $normalize): string
    {
        $raw = self::decode($wirePath);
        if ($normalize) {
            $raw = self::normalize($raw);
        }
        if ($raw === '') {
            return '/';
        }

        return self::encodePath($raw);
    }

    /**
     * Removes `.` segments, resolves `..` and collapses repeated slashes.
     * A trailing slash is kept, as are the trailing slashes implied by a
     * final `.` or `..` segment (RFC 3986 section 5.2.4).
     */
    public static function normalize(string $path): string
    {
        if ($path === '') {
            return '/';
        }
        $segments = explode('/', $path);
        $out = [];
        $last = end($segments);
        $trailing = $last === '' || $last === '.' || $last === '..';
        foreach ($segments as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($out);
                continue;
            }
            $out[] = $segment;
        }
        if ($out === []) {
            return '/';
        }

        return '/' . implode('/', $out) . ($trailing ? '/' : '');
    }

    /**
     * Splits a wire query string into decoded name and value pairs.
     * `?acl` and `?acl=` both give ['acl', '']. Empty pieces (`a&&b`) are
     * skipped. A plus sign is a literal plus, never a space.
     *
     * @return list<array{0: string, 1: string}>
     */
    public static function parseQuery(string $query): array
    {
        $pairs = [];
        if ($query === '') {
            return $pairs;
        }
        foreach (explode('&', $query) as $piece) {
            if ($piece === '') {
                continue;
            }
            $eq = strpos($piece, '=');
            if ($eq === false) {
                $pairs[] = [self::decode($piece), ''];
            } else {
                $pairs[] = [self::decode(substr($piece, 0, $eq)), self::decode(substr($piece, $eq + 1))];
            }
        }

        return $pairs;
    }

    /**
     * Canonical query string: each name and value encoded, then sorted by
     * encoded name and then encoded value, in byte order.
     *
     * @param list<array{0: string, 1: string}> $pairs decoded pairs
     */
    public static function canonicalQuery(array $pairs): string
    {
        $encoded = [];
        foreach ($pairs as [$name, $value]) {
            $encoded[] = [self::encode($name), self::encode($value)];
        }
        usort($encoded, static function (array $a, array $b): int {
            return strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1]);
        });
        $parts = [];
        foreach ($encoded as [$name, $value]) {
            $parts[] = $name . '=' . $value;
        }

        return implode('&', $parts);
    }

    /**
     * Builds a wire query string from decoded pairs, in the order given.
     *
     * @param list<array{0: string, 1: string}> $pairs
     */
    public static function buildQuery(array $pairs): string
    {
        $parts = [];
        foreach ($pairs as [$name, $value]) {
            $parts[] = self::encode($name) . '=' . self::encode($value);
        }

        return implode('&', $parts);
    }
}
