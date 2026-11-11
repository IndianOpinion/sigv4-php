<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Credentials;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Credentials\ChainProvider;
use IndianOpinion\SigV4\Credentials\ContainerProvider;
use IndianOpinion\SigV4\Credentials\DefaultChain;
use IndianOpinion\SigV4\Credentials\Environment;
use IndianOpinion\SigV4\Credentials\EnvironmentProvider;
use IndianOpinion\SigV4\Credentials\InstanceMetadataProvider;
use IndianOpinion\SigV4\Credentials\StaticProvider;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;
use IndianOpinion\SigV4\Http\FakeTransport;
use IndianOpinion\SigV4\Http\HttpResponse;
use IndianOpinion\SigV4\Tests\Support\FailingProvider;
use IndianOpinion\SigV4\Tests\Support\Imds;
use PHPUnit\Framework\TestCase;

/**
 * Chain semantics: C18, F2, F3, F7, F8.
 */
final class ChainProviderTest extends TestCase
{
    private static function failing(\Throwable $e): FailingProvider
    {
        return new FailingProvider($e);
    }

    public function testC18NotFoundMovesOn(): void
    {
        $chain = new ChainProvider([
            self::failing(new CredentialsNotFoundException('first: nothing')),
            StaticProvider::fromKeys('AKIDSECOND', 'secret'),
        ]);
        self::assertSame('AKIDSECOND', $chain->getCredentials()->getAccessKeyId());
    }

    public function testC18ConfigurationErrorStopsTheChain(): void
    {
        $after = self::failing(new CredentialsNotFoundException('never reached'));
        $chain = new ChainProvider([
            new EnvironmentProvider(new Environment(['AWS_ACCESS_KEY_ID' => 'AKID'])),
            $after,
        ]);
        try {
            $chain->getCredentials();
            self::fail('Expected a configuration exception.');
        } catch (ConfigurationException) {
            self::assertSame(0, $after->calls);
        }
    }

    public function testC18F2FinalMessageListsEveryProvider(): void
    {
        $env = new Environment(['AWS_EC2_METADATA_DISABLED' => 'true']);
        $chain = new ChainProvider([
            new EnvironmentProvider($env),
            new ContainerProvider($env, new FakeTransport()),
            new InstanceMetadataProvider($env, new FakeTransport()),
        ]);
        try {
            $chain->getCredentials();
            self::fail('Expected not found.');
        } catch (CredentialsNotFoundException $e) {
            self::assertCount(3, $e->getReasons());
            self::assertStringContainsString('env:', $e->getMessage());
            self::assertStringContainsString('container:', $e->getMessage());
            self::assertStringContainsString('imds:', $e->getMessage());
        }
    }

    public function testF3UnreachableImdsFallsThroughToTheNextProvider(): void
    {
        $env = new Environment([]);
        $chain = new ChainProvider([
            new InstanceMetadataProvider($env, new FakeTransport([HttpResponse::failure('no route'), HttpResponse::failure('no route')])),
            StaticProvider::fromKeys('AKIDFALLBACK', 'secret'),
        ]);
        self::assertSame('AKIDFALLBACK', $chain->getCredentials()->getAccessKeyId());
    }

    public function testF7ContainerFailureWithVariablesSetStopsTheChain(): void
    {
        $env = new Environment(['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' => '/creds']);
        $imdsTransport = new FakeTransport();
        $chain = new ChainProvider([
            new ContainerProvider($env, new FakeTransport([new HttpResponse(500)])),
            new InstanceMetadataProvider($env, $imdsTransport),
        ]);
        try {
            $chain->getCredentials();
            self::fail('Expected a credentials exception.');
        } catch (CredentialsException) {
            self::assertSame(0, $imdsTransport->count());
        }
    }

    public function testF8RefusedContainerHostStopsTheChain(): void
    {
        $env = new Environment(['AWS_CONTAINER_CREDENTIALS_FULL_URI' => 'http://attacker.example.com/']);
        $this->expectException(ConfigurationException::class);
        (new ChainProvider([
            new ContainerProvider($env, new FakeTransport()),
            StaticProvider::fromKeys('AKIDNEVER', 'secret'),
        ]))->getCredentials();
    }

    public function testEmptyChainIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        new ChainProvider([]);
    }

    public function testDefaultChainOrder(): void
    {
        $transport = new FakeTransport([Imds::token(), Imds::role(), Imds::credentials()]);
        $env = new Environment([]);
        $clock = new FrozenClock('2026-11-11T12:00:00Z');

        $static = DefaultChain::create(new Credentials('AKIDSTATIC', 'secret'), env: $env, transport: $transport, clock: $clock);
        self::assertSame('AKIDSTATIC', $static->getCredentials()->getAccessKeyId());

        $fromEnv = DefaultChain::create(env: new Environment(['AWS_ACCESS_KEY_ID' => 'AKIDENV', 'AWS_SECRET_ACCESS_KEY' => 's']), transport: $transport, clock: $clock);
        self::assertSame('AKIDENV', $fromEnv->getCredentials()->getAccessKeyId());

        $imds = DefaultChain::create(env: $env, transport: $transport, clock: $clock);
        self::assertSame(Imds::KEY, $imds->getCredentials()->getAccessKeyId());
        self::assertSame(0, $transport->remaining());

        $noImds = DefaultChain::create(env: $env, transport: new FakeTransport(), useInstanceMetadata: false);
        $this->expectException(CredentialsNotFoundException::class);
        $noImds->getCredentials();
    }
}
