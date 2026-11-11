<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Exception;

/**
 * No usable HTTP transport (no curl and no allow_url_fopen), raised on first network use.
 */
final class TransportException extends SigV4Exception
{
}
