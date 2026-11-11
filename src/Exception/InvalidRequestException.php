<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Exception;

/**
 * The request, URL, region, service, payload or expiry given to the signer is not valid.
 */
final class InvalidRequestException extends SigV4Exception
{
}
