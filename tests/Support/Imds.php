<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Support;

use IndianOpinion\SigV4\Http\HttpResponse;

/**
 * Scripted responses for credential endpoints.
 */
final class Imds
{
    public const KEY = 'ASIAEXAMPLEIMDSKEY01';
    public const SECRET = 'imds-secret-value-should-never-leak-0001';
    public const TOKEN = 'imds-session-token-should-never-leak-0001';

    public static function token(string $token = 'imds-api-token-0001'): HttpResponse
    {
        return new HttpResponse(200, [], $token);
    }

    public static function role(string $role = 'web-role'): HttpResponse
    {
        return new HttpResponse(200, [], $role . "\n");
    }

    public static function credentials(string $expiration = '2026-11-11T18:00:00Z', string $code = 'Success'): HttpResponse
    {
        return new HttpResponse(200, ['Content-Type' => 'application/json'], (string) json_encode([
            'Code' => $code,
            'LastUpdated' => '2026-11-11T12:00:00Z',
            'Type' => 'AWS-HMAC',
            'AccessKeyId' => self::KEY,
            'SecretAccessKey' => self::SECRET,
            'Token' => self::TOKEN,
            'Expiration' => $expiration,
        ]));
    }

    /**
     * @param array<string, string> $override
     */
    public static function containerCredentials(array $override = [], ?string $drop = null): HttpResponse
    {
        $data = array_merge([
            'AccessKeyId' => 'ASIAEXAMPLECONTAINER',
            'SecretAccessKey' => 'container-secret-should-never-leak-0001',
            'Token' => 'container-token-should-never-leak-0001',
            'Expiration' => '2026-11-11T18:00:00Z',
        ], $override);
        if ($drop !== null) {
            unset($data[$drop]);
        }

        return new HttpResponse(200, [], (string) json_encode($data));
    }
}
