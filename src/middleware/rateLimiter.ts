import { Request, Response, NextFunction } from 'express';
import { getRedisClient } from '@/config/redis';
import logger from '@/config/logger';
import { 
  MESSAGES, 
  ENV_VARS, 
  DEFAULTS, 
  RATE_LIMIT, 
  REDIS_KEYS, 
  HTTP_STATUS, 
  ERROR_TYPES, 
  HEADERS 
} from '@/constants';

interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: Request) => string;
  message?: string;
  statusCode?: number;
}

class TokenBucket {
  private getRedisClientSafely() {
    const client = getRedisClient();
    if (!client) {
      logger.debug('Redis not available for rate limiting - using fail-open policy');
    }
    return client;
  }

  async isAllowed(
    key: string,
    maxTokens: number,
    refillRate: number,
    windowMs: number,
  ): Promise<{ allowed: boolean; tokensRemaining: number; resetTime: number }> {
    const now = Date.now();
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const redisKey = `${REDIS_KEYS.RATE_LIMIT_PREFIX}:${key}:${windowStart}`;

    try {
      const redisClient = this.getRedisClientSafely();
      
      if (!redisClient) {
        // If Redis is not available, fail open (allow request)
        logger.debug('Redis not available, allowing request (fail-open policy)');
        return {
          allowed: true,
          tokensRemaining: maxTokens,
          resetTime: windowStart + windowMs,
        };
      }

      // Get current token count and last refill time
      const bucketData = await redisClient.hmget(redisKey, 'tokens', 'lastRefill');
      
      const tokensStr = bucketData?.[0] ? String(bucketData[0]) : maxTokens.toString();
      const lastRefillStr = bucketData?.[1] ? String(bucketData[1]) : now.toString();
      
      let tokens = parseInt(tokensStr);
      const lastRefill = parseInt(lastRefillStr);

      // Calculate tokens to add based on time elapsed
      const timePassed = now - lastRefill;
      const tokensToAdd = Math.floor(timePassed * refillRate / RATE_LIMIT.TOKEN_BUCKET_REFILL_MULTIPLIER);
      tokens = Math.min(maxTokens, tokens + tokensToAdd);

      if (tokens > 0) {
        // Allow request and consume token
        tokens -= 1;
        
        // Update bucket in Redis
        await redisClient.hmset(redisKey, {
          tokens: tokens.toString(),
          lastRefill: now.toString(),
        });
        
        // Set expiration for cleanup
        await redisClient.expire(redisKey, Math.ceil(windowMs / RATE_LIMIT.TOKENS_PER_SECOND_DIVISOR) + DEFAULTS.REDIS_CLEANUP_BUFFER);

        return {
          allowed: true,
          tokensRemaining: tokens,
          resetTime: windowStart + windowMs,
        };
      } else {
        return {
          allowed: false,
          tokensRemaining: 0,
          resetTime: windowStart + windowMs,
        };
      }
    } catch (error) {
      logger.error(MESSAGES.ERROR.RATE_LIMITER_ERROR, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        key,
        maxTokens,
        refillRate,
        windowMs,
      });
      // Fail open - allow request if Redis is down
      return {
        allowed: true,
        tokensRemaining: maxTokens,
        resetTime: windowStart + windowMs,
      };
    }
  }
}

const tokenBucket = new TokenBucket();

const createRateLimiter = (options: RateLimitOptions) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const key = options.keyGenerator ? options.keyGenerator(req) : (req.ip || DEFAULTS.UNKNOWN_IP);
      const refillRate = options.maxRequests / (options.windowMs / RATE_LIMIT.TOKENS_PER_SECOND_DIVISOR); // tokens per second

      const result = await tokenBucket.isAllowed(
        key,
        options.maxRequests,
        refillRate,
        options.windowMs,
      );

      // Set rate limit headers
      res.set({
        [HEADERS.RATE_LIMIT_LIMIT]: options.maxRequests.toString(),
        [HEADERS.RATE_LIMIT_REMAINING]: result.tokensRemaining.toString(),
        [HEADERS.RATE_LIMIT_RESET]: new Date(result.resetTime).toISOString(),
      });

      if (!result.allowed) {
        logger.warn(MESSAGES.WARNING.RATE_LIMIT_EXCEEDED, {
          key,
          ip: req.ip,
          userAgent: req.get(HEADERS.USER_AGENT),
          url: req.url,
          method: req.method,
          maxRequests: options.maxRequests,
          windowMs: options.windowMs,
        });

        res.status(options.statusCode || HTTP_STATUS.TOO_MANY_REQUESTS).json({
          error: ERROR_TYPES.TOO_MANY_REQUESTS,
          message: options.message || 'Rate limit exceeded. Please try again later.',
          retryAfter: Math.ceil((result.resetTime - Date.now()) / RATE_LIMIT.RETRY_AFTER_DIVISOR),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Log successful rate limit check at debug level
      logger.debug(MESSAGES.INFO.RATE_LIMIT_CHECK_PASSED, {
        key,
        tokensRemaining: result.tokensRemaining,
        maxRequests: options.maxRequests,
      });

      next();
    } catch (error) {
      logger.error(MESSAGES.ERROR.RATE_LIMITER_MIDDLEWARE_ERROR, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        ip: req.ip,
        url: req.url,
        method: req.method,
      });
      // Fail open - allow request if there's an error
      next();
    }
  };
};

// Default IP-based rate limiter
const rateLimiter = createRateLimiter({
  windowMs: parseInt(process.env[ENV_VARS.RATE_LIMIT_WINDOW_MS] || DEFAULTS.RATE_LIMIT_WINDOW_MS.toString()),
  maxRequests: parseInt(process.env[ENV_VARS.RATE_LIMIT_MAX_REQUESTS] || DEFAULTS.RATE_LIMIT_MAX_REQUESTS.toString()),
  message: 'Too many requests from this IP, please try again later.',
});

// User-based rate limiter (requires authentication)
const userRateLimiter = createRateLimiter({
  windowMs: parseInt(process.env[ENV_VARS.RATE_LIMIT_WINDOW_MS] || DEFAULTS.RATE_LIMIT_WINDOW_MS.toString()),
  maxRequests: parseInt(process.env[ENV_VARS.RATE_LIMIT_MAX_REQUESTS_PER_USER] || DEFAULTS.RATE_LIMIT_MAX_REQUESTS_PER_USER.toString()),
  keyGenerator: (req: Request): string => {
    const user = (req as any).user;
    return user ? `${REDIS_KEYS.USER_PREFIX}:${user.id}` : (req.ip || DEFAULTS.UNKNOWN_IP);
  },
  message: 'Too many requests from this user, please try again later.',
});

export { rateLimiter, userRateLimiter, createRateLimiter }; 