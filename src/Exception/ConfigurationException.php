<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Exception;

/**
 * Configuration is wrong or unsafe (half-set environment, refused endpoint, bad token). Chains stop here.
 */
final class ConfigurationException extends SigV4Exception
{
}
