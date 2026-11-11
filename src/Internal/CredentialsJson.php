<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Internal;

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsException;
use IndianOpinion\SigV4\Http\HttpResponse;

/**
 * Parses the credentials JSON returned by the container endpoint and by
 * instance metadata. Error messages never include the body.
 *
 * @internal
 */
final class CredentialsJson
{
    public static function parse(
        HttpResponse $response,
        int $maxBytes,
        string $source,
        bool $requireSuccessCode,
        \DateTimeImmutable $now,
        Logger $logger,
    ): Credentials {
        if (strlen($response->body) > $maxBytes) {
            throw new CredentialsException(sprintf(
                '%s: the credentials response is larger than %d bytes and was refused.',
                $source,
                $maxBytes,
            ));
        }
        try {
            $data = json_decode($response->body, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new CredentialsException(sprintf('%s: the credentials response is not valid JSON.', $source));
        }
        if (!is_array($data)) {
            throw new CredentialsException(sprintf('%s: the credentials response is not a JSON object.', $source));
        }
        if ($requireSuccessCode && ($data['Code'] ?? null) !== 'Success') {
            // The value is not echoed: a malformed body could carry anything.
            throw new CredentialsException(sprintf('%s: the credentials response Code is not "Success".', $source));
        }
        $fields = [];
        foreach (['AccessKeyId', 'SecretAccessKey', 'Token', 'Expiration'] as $field) {
            $value = $data[$field] ?? null;
            if (!is_string($value) || $value === '') {
                throw new CredentialsException(sprintf(
                    '%s: the credentials response lacks a non-empty "%s" field.',
                    $source,
                    $field,
                ));
            }
            $fields[$field] = $value;
        }
        $expiresAt = Iso8601::parse($fields['Expiration']);
        if ($expiresAt === null) {
            throw new CredentialsException(sprintf('%s: the Expiration value is not an ISO 8601 time.', $source));
        }
        try {
            $credentials = new Credentials(
                $fields['AccessKeyId'],
                $fields['SecretAccessKey'],
                $fields['Token'],
                $expiresAt,
                $source,
            );
        } catch (ConfigurationException $e) {
            throw new CredentialsException(sprintf('%s: %s', $source, $e->getMessage()), 0, $e);
        }
        if ($credentials->needsRefresh($now)) {
            $logger->warning('Credentials returned by the provider have already expired', [
                'source' => $source,
                'accessKeyId' => $credentials->getAccessKeyId(),
                'expiresAt' => $expiresAt->format('Y-m-d\TH:i:s\Z'),
            ]);
        }

        return $credentials;
    }
}
