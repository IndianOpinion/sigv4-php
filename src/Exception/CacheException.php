<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Exception;

/**
 * A cache cannot be built (missing extension) or failed at run time.
 * Run-time cache failures are caught and logged as warnings by the
 * encrypted cache, so they never reach code that asked for credentials.
 */
final class CacheException extends SigV4Exception
{
}
