<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Clock\Clock;
use IndianOpinion\SigV4\Clock\SystemClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;
use IndianOpinion\SigV4\Http\HttpRequest;
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\Http\Transport;
use IndianOpinion\SigV4\Http\TransportFactory;
use IndianOpinion\SigV4\Internal\CredentialsJson;
use IndianOpinion\SigV4\Internal\Logger;

/**
 * EC2 instance-role credentials through IMDSv2. IMDSv1 is never used.
 *
 * 1. PUT /latest/api/token for a session token (kept in memory, reused
 *    until shortly before its TTL ends).
 * 2. GET /latest/meta-data/iam/security-credentials/ for the role name
 *    (skipped when a role name is configured).
 * 3. GET /latest/meta-data/iam/security-credentials/<role>.
 *
 * Not on EC2 (the token request cannot connect or times out): not found,
 * so a chain on a laptop moves on. Reachable but refusing IMDSv2, or no
 * role attached: an exception.
 */
final class InstanceMetadataProvider implements Provider
{
    public const DEFAULT_ENDPOINT = 'http://169.254.169.254';
    public const IPV6_ENDPOINT = 'http://[fd00:ec2::254]';
    public const MAX_TOKEN_TTL = 21600;

    private const TOKEN_PATH = '/latest/api/token';
    private const ROLE_PATH = '/latest/meta-data/iam/security-credentials/';
    private const ROLE_PATTERN = '/^[A-Za-z0-9+=,.@_-]{1,64}$/D';
    private const HOP_LIMIT_HINT = 'if running in a container, the instance metadata hop limit may need to be 2';

    private readonly Environment $env;
    private ?Transport $transport;
    private readonly Clock $clock;
    private readonly Logger $logger;
    private ?string $token = null;
    private int $tokenRefreshAt = 0;

    /**
     * @param string|null $roleName skip the role listing and use this role
     * @param string|null $endpoint override the endpoint (environment overrides are honoured when this is null)
     * @param int $retries extra attempts when the transport gets no answer at all
     * @param (callable(string, string, array<string, mixed>): mixed)|null $logger
     */
    public function __construct(
        ?Environment $env = null,
        ?Transport $transport = null,
        ?Clock $clock = null,
        ?callable $logger = null,
        private readonly ?string $roleName = null,
        private readonly ?string $endpoint = null,
        private readonly int $tokenTtl = self::MAX_TOKEN_TTL,
        private readonly float $connectTimeout = 1.0,
        private readonly float $timeout = 2.0,
        private readonly int $retries = 1,
        private readonly int $maxResponseBytes = HttpRequest::DEFAULT_MAX_RESPONSE_BYTES,
    ) {
        if ($tokenTtl < 1 || $tokenTtl > self::MAX_TOKEN_TTL) {
            throw new ConfigurationException('imds: the token TTL must be between 1 and 21600 seconds.');
        }
        if ($roleName !== null && preg_match(self::ROLE_PATTERN, $roleName) !== 1) {
            throw new ConfigurationException('imds: the configured role name is not a valid IAM role name.');
        }
        if ($retries < 0 || $retries > 5) {
            throw new ConfigurationException('imds: retries must be between 0 and 5.');
        }
        if ($connectTimeout <= 0 || $timeout <= 0) {
            throw new ConfigurationException('imds: timeouts must be positive.');
        }
        $this->env = $env ?? Environment::fromGlobals();
        $this->transport = $transport;
        $this->clock = $clock ?? new SystemClock();
        $this->logger = new Logger($logger);
    }

    public function getCredentials(): Credentials
    {
        $disabled = $this->env->get('AWS_EC2_METADATA_DISABLED');
        if ($disabled !== null && strtolower(trim($disabled)) === 'true') {
            throw new CredentialsNotFoundException('imds: disabled by AWS_EC2_METADATA_DISABLED');
        }
        $base = $this->resolveEndpoint();

        $role = $this->roleName ?? $this->fetchRoleName($base);
        $response = $this->metadataGet($base, self::ROLE_PATH . $role);
        if ($response->status === 404) {
            throw new CredentialsException(sprintf('imds: no credentials for role "%s" (HTTP 404).', $role));
        }
        if ($response->status !== 200) {
            throw new CredentialsException(sprintf(
                'imds: the credentials request answered HTTP %d.',
                $response->status,
            ));
        }
        $credentials = CredentialsJson::parse(
            $response,
            $this->maxResponseBytes,
            'imds',
            true,
            $this->clock->now(),
            $this->logger,
        );
        $this->logger->debug('Credentials resolved from instance metadata', [
            'accessKeyId' => $credentials->getAccessKeyId(),
            'expiresAt' => $credentials->getExpiresAt()?->format('Y-m-d\TH:i:s\Z'),
        ]);

        return $credentials;
    }

    private function resolveEndpoint(): string
    {
        $endpoint = $this->endpoint ?? $this->env->get('AWS_EC2_METADATA_SERVICE_ENDPOINT');
        if ($endpoint === null) {
            $mode = $this->env->get('AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE');
            if ($mode === null || strcasecmp($mode, 'IPv4') === 0) {
                return self::DEFAULT_ENDPOINT;
            }
            if (strcasecmp($mode, 'IPv6') === 0) {
                return self::IPV6_ENDPOINT;
            }
            throw new ConfigurationException('imds: AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE must be IPv4 or IPv6.');
        }
        $parts = parse_url($endpoint);
        if (
            $parts === false
            || !isset($parts['scheme'], $parts['host'])
            || !in_array(strtolower($parts['scheme']), ['http', 'https'], true)
            || isset($parts['query'])
            || isset($parts['user'])
            || preg_match('/[\x00-\x20\x7F]/', $endpoint) === 1
        ) {
            throw new ConfigurationException('imds: the metadata endpoint must be an absolute http or https URL.');
        }

        return rtrim($endpoint, '/');
    }

    private function fetchRoleName(string $base): string
    {
        $response = $this->metadataGet($base, self::ROLE_PATH);
        if ($response->status === 404) {
            throw new CredentialsException('imds: no instance role attached (the role listing answered HTTP 404).');
        }
        if ($response->status !== 200) {
            throw new CredentialsException(sprintf('imds: the role listing answered HTTP %d.', $response->status));
        }
        if (strlen($response->body) > $this->maxResponseBytes) {
            throw new CredentialsException('imds: the role listing response is too large and was refused.');
        }
        $role = '';
        foreach (preg_split('/\r?\n/', $response->body) ?: [] as $line) {
            $line = trim($line);
            if ($line !== '') {
                $role = $line;
                break;
            }
        }
        if ($role === '') {
            throw new CredentialsException('imds: no instance role attached (the role listing is empty).');
        }
        if (preg_match(self::ROLE_PATTERN, $role) !== 1) {
            throw new CredentialsException('imds: the role name from instance metadata is not a valid IAM role name.');
        }

        return $role;
    }

    /**
     * GET with the session token; on a 401 fetch a new token once and retry once.
     */
    private function metadataGet(string $base, string $path): HttpResponse
    {
        $response = $this->send('GET', $base . $path, ['X-aws-ec2-metadata-token' => $this->token($base, false)]);
        if ($response->status === 401) {
            $this->logger->debug('Instance metadata token rejected; fetching a new one', []);
            $response = $this->send('GET', $base . $path, ['X-aws-ec2-metadata-token' => $this->token($base, true)]);
        }
        if ($response->isTransportError()) {
            throw new CredentialsException(sprintf(
                'imds: a metadata request failed after the token was issued (%s).',
                $response->timedOut ? 'timed out' : $response->error,
            ));
        }

        return $response;
    }

    private function token(string $base, bool $force): string
    {
        $now = $this->clock->now()->getTimestamp();
        if (!$force && $this->token !== null && $now < $this->tokenRefreshAt) {
            return $this->token;
        }
        $this->token = null;
        $response = $this->send('PUT', $base . self::TOKEN_PATH, [
            'X-aws-ec2-metadata-token-ttl-seconds' => (string) $this->tokenTtl,
        ]);
        if ($response->isTransportError()) {
            if ($response->timedOut) {
                throw new CredentialsNotFoundException(sprintf(
                    'imds: token request timed out (not on EC2?); %s',
                    self::HOP_LIMIT_HINT,
                ));
            }
            throw new CredentialsNotFoundException(sprintf(
                'imds: instance metadata service not reachable, not on EC2 (%s)',
                $response->error,
            ));
        }
        if (in_array($response->status, [403, 404, 405], true)) {
            throw new CredentialsException(sprintf(
                'imds: the IMDSv2 token request was refused with HTTP %d, so IMDSv2 is unavailable or disabled. '
                . 'IMDSv1 is never used.',
                $response->status,
            ));
        }
        if ($response->status !== 200) {
            throw new CredentialsException(sprintf('imds: the token request answered HTTP %d.', $response->status));
        }
        $token = trim($response->body);
        if ($token === '' || strlen($token) > 4096 || preg_match('/[\x00-\x1F\x7F]/', $token) === 1) {
            throw new CredentialsException('imds: the token response is empty or malformed.');
        }
        $this->token = $token;
        $this->tokenRefreshAt = $now + $this->tokenTtl - min(60, intdiv($this->tokenTtl, 2));

        return $token;
    }

    /**
     * @param array<string, string> $headers
     */
    private function send(string $method, string $url, array $headers): HttpResponse
    {
        $this->transport ??= TransportFactory::create();
        $request = new HttpRequest(
            $method,
            $url,
            $headers,
            '',
            $this->connectTimeout,
            $this->timeout,
            $this->maxResponseBytes,
        );
        $response = $this->transport->send($request);
        for ($attempt = 0; $attempt < $this->retries && $response->isTransportError(); $attempt++) {
            $response = $this->transport->send($request);
        }

        return $response;
    }
}
