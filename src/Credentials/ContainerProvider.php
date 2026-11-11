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
use IndianOpinion\SigV4\Http\Transport;
use IndianOpinion\SigV4\Http\TransportFactory;
use IndianOpinion\SigV4\Internal\CredentialsJson;
use IndianOpinion\SigV4\Internal\Logger;

/**
 * The ECS task role and EKS Pod Identity credentials endpoint.
 *
 * - AWS_CONTAINER_CREDENTIALS_RELATIVE_URI wins: GET http://169.254.170.2 plus that path.
 * - Else AWS_CONTAINER_CREDENTIALS_FULL_URI: https to any host; http only to a
 *   loopback address or the documented container hosts 169.254.170.2,
 *   169.254.170.23 and fd00:ec2::23 (the rule of botocore and the Go SDK).
 * - Authorization: the content of AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE,
 *   read on every fetch because EKS rotates it, else
 *   AWS_CONTAINER_AUTHORIZATION_TOKEN.
 *
 * Neither URI variable set: not found, with no network call. Once a
 * variable is set the provider applies, so every later failure is raised.
 */
final class ContainerProvider implements Provider
{
    public const ECS_HOST = 'http://169.254.170.2';
    public const ALLOWED_HTTP_HOSTS = ['169.254.170.2', '169.254.170.23', 'fd00:ec2::23', 'localhost'];

    private readonly Environment $env;
    private ?Transport $transport;
    private readonly Clock $clock;
    private readonly Logger $logger;

    /**
     * @param (callable(string, string, array<string, mixed>): mixed)|null $logger
     */
    public function __construct(
        ?Environment $env = null,
        ?Transport $transport = null,
        ?Clock $clock = null,
        ?callable $logger = null,
        private readonly float $connectTimeout = 1.0,
        private readonly float $timeout = 3.0,
        private readonly int $maxResponseBytes = HttpRequest::DEFAULT_MAX_RESPONSE_BYTES,
    ) {
        $this->env = $env ?? Environment::fromGlobals();
        $this->transport = $transport;
        $this->clock = $clock ?? new SystemClock();
        $this->logger = new Logger($logger);
    }

    public function getCredentials(): Credentials
    {
        $relative = $this->env->get('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI');
        $full = $this->env->get('AWS_CONTAINER_CREDENTIALS_FULL_URI');
        if ($relative === null && $full === null) {
            throw new CredentialsNotFoundException(
                'container: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI and AWS_CONTAINER_CREDENTIALS_FULL_URI are not set'
            );
        }
        $url = $relative !== null ? self::relativeUrl($relative) : self::checkFullUri((string) $full);

        $headers = ['Accept' => 'application/json'];
        $token = $this->authorizationToken();
        if ($token !== null) {
            $headers['Authorization'] = $token;
        }

        $this->transport ??= TransportFactory::create();
        $response = $this->transport->send(new HttpRequest(
            'GET',
            $url,
            $headers,
            '',
            $this->connectTimeout,
            $this->timeout,
            $this->maxResponseBytes,
        ));
        if ($response->isTransportError()) {
            throw new CredentialsException(sprintf(
                'container: the credentials endpoint did not answer (%s).',
                $response->timedOut ? 'timed out' : $response->error,
            ));
        }
        if ($response->status !== 200) {
            throw new CredentialsException(sprintf(
                'container: the credentials endpoint answered HTTP %d.',
                $response->status,
            ));
        }
        $credentials = CredentialsJson::parse(
            $response,
            $this->maxResponseBytes,
            'container',
            false,
            $this->clock->now(),
            $this->logger,
        );
        $this->logger->debug('Credentials resolved from the container endpoint', [
            'accessKeyId' => $credentials->getAccessKeyId(),
        ]);

        return $credentials;
    }

    private static function relativeUrl(string $relative): string
    {
        if ($relative[0] !== '/' || preg_match('/[\x00-\x20\x7F]/', $relative) === 1) {
            throw new ConfigurationException(
                'container: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be a path starting with "/" and no whitespace.'
            );
        }

        return self::ECS_HOST . $relative;
    }

    /**
     * @throws ConfigurationException when the URI is malformed or its host is not allowed
     */
    public static function checkFullUri(string $uri): string
    {
        $parts = parse_url($uri);
        if (
            $parts === false
            || !isset($parts['scheme'], $parts['host'])
            || preg_match('/[\x00-\x20\x7F]/', $uri) === 1
            || isset($parts['user'])
            || isset($parts['pass'])
        ) {
            throw new ConfigurationException(
                'container: AWS_CONTAINER_CREDENTIALS_FULL_URI is not a valid absolute URL.'
            );
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme === 'https') {
            return $uri;
        }
        if ($scheme !== 'http') {
            throw new ConfigurationException('container: AWS_CONTAINER_CREDENTIALS_FULL_URI must use http or https.');
        }
        $host = strtolower(trim($parts['host'], '[]'));
        if (!self::isAllowedHttpHost($host)) {
            throw new ConfigurationException(sprintf(
                'container: AWS_CONTAINER_CREDENTIALS_FULL_URI host "%s" is refused. Plain http is allowed only to a '
                . 'loopback address or to 169.254.170.2, 169.254.170.23 or fd00:ec2::23; use https for anything else.',
                $host,
            ));
        }

        return $uri;
    }

    private static function isAllowedHttpHost(string $host): bool
    {
        if ($host === 'localhost') {
            return true;
        }
        $packed = filter_var($host, FILTER_VALIDATE_IP) === false ? false : inet_pton($host);
        if ($packed === false) {
            return false;
        }
        // IPv4 loopback is the whole 127.0.0.0/8 block; IPv6 loopback is ::1.
        if (strlen($packed) === 4 && ord($packed[0]) === 127) {
            return true;
        }
        foreach (['::1', '169.254.170.2', '169.254.170.23', 'fd00:ec2::23'] as $allowed) {
            if ($packed === inet_pton($allowed)) {
                return true;
            }
        }

        return false;
    }

    private function authorizationToken(): ?string
    {
        $file = $this->env->get('AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE');
        if ($file !== null) {
            // Read failures become a typed exception below, not a PHP warning.
            set_error_handler(static fn (): bool => true);
            try {
                $token = is_file($file) && is_readable($file) ? file_get_contents($file, false, null, 0, 16384) : false;
            } finally {
                restore_error_handler();
            }
            if ($token === false) {
                throw new ConfigurationException(
                    'container: the file named by AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE cannot be read.'
                );
            }
            // A single trailing newline is common in hand-written files.
            $token = rtrim($token, "\r\n");
        } else {
            $token = $this->env->get('AWS_CONTAINER_AUTHORIZATION_TOKEN');
            if ($token === null) {
                return null;
            }
        }
        if ($token === '' || preg_match('/[\r\n\x00]/', $token) === 1) {
            throw new ConfigurationException(
                'container: the authorization token is empty or contains a line break, and was refused.'
            );
        }

        return $token;
    }
}
