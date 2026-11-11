<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Cache;

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\CacheException;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Internal\Logger;

/**
 * Encrypts credentials before they reach a shared cache.
 *
 * - Cipher: libsodium secretbox (XSalsa20-Poly1305), a fresh random nonce
 *   per write, stored as base64(nonce . ciphertext).
 * - Key: BLAKE2b (sodium generichash) over a versioned domain-separation
 *   label and your application secret. The secret is never stored.
 * - Any read failure (wrong key after a secret rotation, truncated or
 *   tampered blob, not base64, backend error) is a miss plus one warning.
 *   It is never an exception, and never falls back to plaintext.
 */
final class EncryptedCache
{
    /** Changing the label (its version) rotates every derived key. */
    public const KEY_LABEL = 'indianopinion/sigv4-php credential-cache v1';
    public const MIN_SECRET_BYTES = 16;
    public const INVALIDATION_TTL = 60;

    private readonly string $key;
    private readonly Logger $logger;

    /**
     * @param string $applicationSecret at least 16 bytes; a framework app key or a WordPress salt
     * @param (callable(string, string, array<string, mixed>): mixed)|null $logger
     * @param (\Closure(): bool)|null $sodiumProbe @internal for tests: reports whether sodium is available
     *
     * @throws CacheException when the sodium extension is missing
     * @throws ConfigurationException when the application secret is too short
     */
    public function __construct(
        private readonly CredentialCache $inner,
        #[\SensitiveParameter] string $applicationSecret,
        ?callable $logger = null,
        ?\Closure $sodiumProbe = null,
    ) {
        $available = $sodiumProbe !== null ? $sodiumProbe() : self::sodiumAvailable();
        if (!$available) {
            throw new CacheException(
                'The sodium extension is required to cache credentials in shared storage; '
                . 'credentials are never written there in plain text.'
            );
        }
        if (strlen($applicationSecret) < self::MIN_SECRET_BYTES) {
            throw new ConfigurationException(sprintf(
                'The application secret for the encrypted cache must be at least %d bytes.',
                self::MIN_SECRET_BYTES,
            ));
        }
        $this->key = self::deriveKey($applicationSecret);
        $this->logger = new Logger($logger);
    }

    public static function sodiumAvailable(): bool
    {
        return function_exists('sodium_crypto_secretbox') && function_exists('sodium_crypto_generichash');
    }

    /**
     * The 32-byte secretbox key for an application secret.
     */
    public static function deriveKey(
        #[\SensitiveParameter] string $applicationSecret,
        string $label = self::KEY_LABEL,
    ): string {
        return sodium_crypto_generichash(
            $label . "\0" . $applicationSecret,
            '',
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        );
    }

    public function getCredentials(string $key): ?Credentials
    {
        try {
            $blob = $this->inner->get($key);
        } catch (\Throwable $e) {
            $this->logger->warning('Credential cache read failed; treating as a miss', [
                'error' => $e::class,
            ]);

            return null;
        }
        if ($blob === null || $blob === '') {
            return null;
        }
        $credentials = $this->decrypt($blob);
        if ($credentials === null) {
            $this->logger->warning(
                'Cached credentials could not be decrypted (secret rotated, truncated or tampered); treating as a miss',
                [],
            );
        }

        return $credentials;
    }

    public function putCredentials(string $key, Credentials $credentials, int $ttl): void
    {
        try {
            $this->inner->set($key, $this->encrypt($credentials), $ttl);
        } catch (\Throwable $e) {
            $this->logger->warning('Credential cache write failed; credentials kept in memory only', [
                'error' => $e::class,
            ]);
        }
    }

    /**
     * Deletes the entry. When the backend cannot confirm the delete, the
     * entry is overwritten with an empty marker (which always reads as a
     * miss) and a short TTL.
     */
    public function invalidate(string $key): void
    {
        try {
            if ($this->inner->delete($key)) {
                return;
            }
        } catch (\Throwable) {
            // Fall through to the empty marker.
        }
        try {
            $this->inner->set($key, '', self::INVALIDATION_TTL);
        } catch (\Throwable $e) {
            $this->logger->warning('Credential cache invalidation failed: delete and overwrite both failed', [
                'error' => $e::class,
            ]);
        }
    }

    /**
     * @internal exposed for tests
     */
    public function encrypt(Credentials $credentials): string
    {
        $payload = json_encode([
            'accessKeyId' => $credentials->getAccessKeyId(),
            'secretAccessKey' => $credentials->getSecretAccessKey(),
            'sessionToken' => $credentials->getSessionToken(),
            'expiresAt' => $credentials->getExpiresAt()?->getTimestamp(),
            'source' => $credentials->getSource(),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return base64_encode($nonce . sodium_crypto_secretbox($payload, $nonce, $this->key));
    }

    /**
     * @internal exposed for tests
     *
     * @return array<string, mixed>|null the decrypted payload, or null when it cannot be read
     */
    public function decryptPayload(string $blob): ?array
    {
        $raw = base64_decode($blob, true);
        $minimum = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
        if ($raw === false || strlen($raw) <= $minimum) {
            return null;
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        try {
            $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $this->key);
        } catch (\SodiumException) {
            return null;
        }
        if ($plain === false) {
            return null;
        }
        try {
            $data = json_decode($plain, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!is_array($data)) {
            return null;
        }
        /** @var array<string, mixed> $data */
        return $data;
    }

    private function decrypt(string $blob): ?Credentials
    {
        $data = $this->decryptPayload($blob);
        if ($data === null) {
            return null;
        }
        $key = $data['accessKeyId'] ?? null;
        $secret = $data['secretAccessKey'] ?? null;
        $token = $data['sessionToken'] ?? null;
        $expiresAt = $data['expiresAt'] ?? null;
        $source = $data['source'] ?? null;
        if (
            !is_string($key)
            || !is_string($secret)
            || ($token !== null && !is_string($token))
            || ($expiresAt !== null && !is_int($expiresAt))
            || !is_string($source)
        ) {
            return null;
        }
        try {
            return new Credentials(
                $key,
                $secret,
                $token,
                $expiresAt === null ? null : (new \DateTimeImmutable('@' . $expiresAt)),
                $source,
            );
        } catch (ConfigurationException) {
            return null;
        }
    }
}
