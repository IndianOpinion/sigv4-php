<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Payload;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;
use IndianOpinion\SigV4\SigningOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A1: every case of the official AWS SigV4 test suite (aws-c-auth, v4),
 * header and query variants.
 *
 * The suite signs every header present in request.txt, so the test asks for
 * all of them. The `normalize` flag selects path normalisation; the suite
 * always double-encodes (a raw space on the wire signs as %20).
 *
 * `post-sts-header-after` has `omit_session_token: true`: the token is added
 * after signing. This library always signs the token (see ARCHITECTURE.md),
 * so the test reproduces that case the way a caller would: sign with the
 * token-less credentials, then append the token header or query parameter.
 */
final class OfficialVectorsTest extends TestCase
{
    private const DIR = __DIR__ . '/fixtures/aws-sig-v4';

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function cases(): iterable
    {
        $dirs = glob(self::DIR . '/*', GLOB_ONLYDIR);
        self::assertNotFalse($dirs);
        sort($dirs);
        foreach ($dirs as $dir) {
            yield basename($dir) => [$dir];
        }
    }

    public function testSuiteIsComplete(): void
    {
        self::assertCount(38, iterator_to_array(self::cases()));
    }

    #[DataProvider('cases')]
    public function testHeaderVariant(string $dir): void
    {
        [$context, $request, $options, $credentials, $appendToken] = $this->load($dir);
        $signer = new Signer(new FrozenClock($context['timestamp']));

        $signed = $signer->sign($request, $credentials, $context['region'], $context['service'], $options);

        $details = $signed->getDetails();
        self::assertSame($this->read($dir, 'header-canonical-request.txt'), $details->getCanonicalRequest());
        self::assertSame($this->read($dir, 'header-string-to-sign.txt'), $details->getStringToSign());
        self::assertSame(trim($this->read($dir, 'header-signature.txt')), $details->getSignature());

        $headers = $signed->getHeaders();
        if ($appendToken !== null) {
            $headers[] = ['X-Amz-Security-Token', $appendToken];
        }
        $expected = self::parseRequest($this->read($dir, 'header-signed-request.txt'));
        self::assertSame($expected['method'], $signed->getMethod());
        self::assertSame('https://' . $request->getHost() . $expected['target'], $signed->getUrl());
        self::assertSame(self::sortHeaders($expected['headers']), self::sortHeaders($headers));
    }

    #[DataProvider('cases')]
    public function testQueryVariant(string $dir): void
    {
        [$context, $request, $options, $credentials, $appendToken] = $this->load($dir);
        $signer = new Signer(new FrozenClock($context['timestamp']));

        $presigned = $signer->presign(
            $request,
            $credentials,
            $context['region'],
            $context['service'],
            $context['expiration_in_seconds'],
            $options,
        );

        $details = $presigned->getDetails();
        self::assertSame($this->read($dir, 'query-canonical-request.txt'), $details->getCanonicalRequest());
        self::assertSame($this->read($dir, 'query-string-to-sign.txt'), $details->getStringToSign());
        self::assertSame(trim($this->read($dir, 'query-signature.txt')), $details->getSignature());

        $url = $presigned->getUrl();
        if ($appendToken !== null) {
            $url .= '&X-Amz-Security-Token=' . rawurlencode($appendToken);
        }
        $expected = self::parseRequest($this->read($dir, 'query-signed-request.txt'));
        $prefix = 'https://' . $request->getHost();
        self::assertStringStartsWith($prefix, $url);
        [$expectedPath, $expectedQuery] = explode('?', $expected['target'], 2);
        [$actualPath, $actualQuery] = explode('?', substr($url, strlen($prefix)), 2);
        self::assertSame($expectedPath, $actualPath);
        self::assertSame(self::sortedPieces($expectedQuery), self::sortedPieces($actualQuery));
    }

    /**
     * @return array{0: array{timestamp: string, region: string, service: string, expiration_in_seconds: int}, 1: Request, 2: SigningOptions, 3: Credentials, 4: ?string}
     */
    private function load(string $dir): array
    {
        $context = json_decode($this->read($dir, 'context.json'), true, 16, JSON_THROW_ON_ERROR);
        self::assertIsArray($context);
        $parsed = self::parseRequest($this->read($dir, 'request.txt'));

        $host = '';
        $names = [];
        foreach ($parsed['headers'] as [$name, $value]) {
            $names[] = strtolower($name);
            if (strtolower($name) === 'host') {
                $host = trim($value);
            }
        }
        $signBody = (bool) $context['sign_body'];
        $request = new Request(
            $parsed['method'],
            'https://' . $host . $parsed['target'],
            $parsed['headers'],
            $parsed['body'] === '' ? null : Payload::fromString($parsed['body']),
        );
        $options = new SigningOptions(
            signHeaders: array_values(array_diff(array_unique($names), ['host'])),
            s3Style: false,
            normalizePath: (bool) $context['normalize'],
            doubleEncodePath: true,
            addContentSha256: $signBody,
        );

        $c = $context['credentials'];
        self::assertIsArray($c);
        $token = isset($c['token']) ? (string) $c['token'] : null;
        $appendToken = null;
        if ($token !== null && ($context['omit_session_token'] ?? false) === true) {
            $appendToken = $token;
            $token = null;
        }
        $credentials = new Credentials((string) $c['access_key_id'], (string) $c['secret_access_key'], $token);
        $typed = [
            'timestamp' => (string) $context['timestamp'],
            'region' => (string) $context['region'],
            'service' => (string) $context['service'],
            'expiration_in_seconds' => (int) $context['expiration_in_seconds'],
        ];

        return [$typed, $request, $options, $credentials, $appendToken];
    }

    private function read(string $dir, string $file): string
    {
        $content = file_get_contents($dir . '/' . $file);
        self::assertIsString($content);

        return $content;
    }

    /**
     * Parses the suite's request format. The request target may contain
     * spaces, and header values may continue on lines that start with
     * whitespace.
     *
     * @return array{method: string, target: string, headers: list<array{0: string, 1: string}>, body: string}
     */
    private static function parseRequest(string $raw): array
    {
        $split = strpos($raw, "\n\n");
        $head = $split === false ? rtrim($raw, "\n") : substr($raw, 0, $split);
        $body = $split === false ? '' : substr($raw, $split + 2);
        $lines = explode("\n", $head);
        $first = (string) array_shift($lines);
        $space = (int) strpos($first, ' ');
        $method = substr($first, 0, $space);
        $target = substr($first, $space + 1, (int) strrpos($first, ' ') - $space - 1);
        $headers = [];
        foreach ($lines as $line) {
            if ($line !== '' && ($line[0] === ' ' || $line[0] === "\t") && $headers !== []) {
                $headers[count($headers) - 1][1] .= "\n" . $line;
                continue;
            }
            $colon = (int) strpos($line, ':');
            $headers[] = [substr($line, 0, $colon), substr($line, $colon + 1)];
        }
        $typed = [];
        foreach ($headers as $header) {
            $typed[] = [$header[0], $header[1]];
        }

        return ['method' => $method, 'target' => $target, 'headers' => $typed, 'body' => $body];
    }

    /**
     * @param list<array{0: string, 1: string}> $headers
     *
     * @return list<string>
     */
    private static function sortHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as [$name, $value]) {
            $out[] = strtolower($name) . ':' . $value;
        }
        sort($out, SORT_STRING);

        return $out;
    }

    /**
     * @return list<string>
     */
    private static function sortedPieces(string $query): array
    {
        $pieces = explode('&', $query);
        sort($pieces, SORT_STRING);

        return $pieces;
    }
}
