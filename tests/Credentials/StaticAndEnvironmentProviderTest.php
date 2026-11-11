<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Credentials;

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Credentials\Environment;
use IndianOpinion\SigV4\Credentials\EnvironmentProvider;
use IndianOpinion\SigV4\Credentials\StaticProvider;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cases C1 and C2.
 */
final class StaticAndEnvironmentProviderTest extends TestCase
{
    private const VARS = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'];

    protected function tearDown(): void
    {
        foreach (self::VARS as $name) {
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function emptyParts(): iterable
    {
        yield 'empty key' => ['', 'secret'];
        yield 'empty secret' => ['AKIDEXAMPLE', ''];
    }

    #[DataProvider('emptyParts')]
    public function testC1EmptyKeyOrSecretThrowsAtConstruction(string $key, string $secret): void
    {
        $this->expectException(ConfigurationException::class);
        StaticProvider::fromKeys($key, $secret);
    }

    public function testC1StaticProviderReturnsItsCredentials(): void
    {
        $expires = new \DateTimeImmutable('2030-01-01T00:00:00Z');
        $credentials = StaticProvider::fromKeys('AKIDEXAMPLE', 'secret', 'token', $expires)->getCredentials();
        self::assertSame('AKIDEXAMPLE', $credentials->getAccessKeyId());
        self::assertSame('token', $credentials->getSessionToken());
        self::assertEquals($expires, $credentials->getExpiresAt());
        self::assertSame('static', $credentials->getSource());
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function sources(): iterable
    {
        yield 'getenv' => ['getenv'];
        yield '$_ENV' => ['env'];
        yield '$_SERVER' => ['server'];
    }

    #[DataProvider('sources')]
    public function testC2ReadsEachOfTheThreeSources(string $source): void
    {
        $values = ['AWS_ACCESS_KEY_ID' => 'AKIDFROM' . strtoupper($source), 'AWS_SECRET_ACCESS_KEY' => 'secret-' . $source];
        foreach ($values as $name => $value) {
            if ($source === 'getenv') {
                putenv($name . '=' . $value);
            } elseif ($source === 'env') {
                $_ENV[$name] = $value;
            } else {
                $_SERVER[$name] = $value;
            }
        }
        $credentials = (new EnvironmentProvider())->getCredentials();
        self::assertSame($values['AWS_ACCESS_KEY_ID'], $credentials->getAccessKeyId());
        self::assertSame('env', $credentials->getSource());
        self::assertNull($credentials->getExpiresAt());
    }

    public function testC2GetenvWinsOverTheSuperglobals(): void
    {
        putenv('AWS_ACCESS_KEY_ID=AKIDGETENV');
        putenv('AWS_SECRET_ACCESS_KEY=secret');
        $_SERVER['AWS_ACCESS_KEY_ID'] = 'AKIDSERVER';
        self::assertSame('AKIDGETENV', (new EnvironmentProvider())->getCredentials()->getAccessKeyId());
    }

    public function testC2SessionTokenIsOptional(): void
    {
        $env = new Environment([
            'AWS_ACCESS_KEY_ID' => 'AKID',
            'AWS_SECRET_ACCESS_KEY' => 'secret',
            'AWS_SESSION_TOKEN' => 'token',
        ]);
        self::assertSame('token', (new EnvironmentProvider($env))->getCredentials()->getSessionToken());
    }

    public function testC2OnlyKeySetThrows(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is not');
        (new EnvironmentProvider(new Environment(['AWS_ACCESS_KEY_ID' => 'AKID'])))->getCredentials();
    }

    public function testC2OnlySecretSetThrows(): void
    {
        $this->expectException(ConfigurationException::class);
        (new EnvironmentProvider(new Environment(['AWS_SECRET_ACCESS_KEY' => 'secret'])))->getCredentials();
    }

    public function testC2NoneSetIsNotFound(): void
    {
        $this->expectException(CredentialsNotFoundException::class);
        (new EnvironmentProvider(new Environment([])))->getCredentials();
    }

    public function testC2EmptyValuesCountAsUnset(): void
    {
        $this->expectException(CredentialsNotFoundException::class);
        (new EnvironmentProvider(new Environment(['AWS_ACCESS_KEY_ID' => '', 'AWS_SECRET_ACCESS_KEY' => ''])))->getCredentials();
    }

    public function testCredentialsMaskSecretsInStringAndDebugForms(): void
    {
        $credentials = new Credentials('AKIDEXAMPLE', 'the-secret', 'the-token', null, 'env');
        $text = (string) $credentials . print_r($credentials, true) . var_export($credentials->__debugInfo(), true);
        self::assertStringContainsString('AKIDEXAMPLE', $text);
        self::assertStringNotContainsString('the-secret', $text);
        self::assertStringNotContainsString('the-token', $text);
    }

    public function testCredentialsCannotBeSerialised(): void
    {
        $this->expectException(\LogicException::class);
        serialize(new Credentials('AKIDEXAMPLE', 'the-secret'));
    }
}
