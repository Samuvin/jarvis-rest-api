import { Request, Response, NextFunction } from 'express';
import { 
  IRateLimiter, 
  IRateLimitStrategy, 
  IRedisConnection, 
  ILogger, 
  RateLimitOptions, 
  RateLimitResult 
} from '@/types/interfaces';
import { 
  MESSAGES, 
  DEFAULTS, 
  RATE_LIMIT, 
  REDIS_KEYS, 
  HTTP_STATUS, 
  ERROR_TYPES, 
  HEADERS 
} from '@/constants';

/**
 * Token Bucket Strategy for rate limiting
 * Implements Strategy Pattern
 */
class TokenBucketStrategy implements IRateLimitStrategy {
  constructor(
    private redisConnection: IRedisConnection,
    private logger: ILogger
  ) {}

  async isAllowed(
    key: string,
    maxTokens: number,
    refillRate: number,
    windowMs: number,
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const redisKey = `${REDIS_KEYS.RATE_LIMIT_PREFIX}:${key}:${windowStart}`;

    try {
      const redisClient = this.redisConnection.getClient();
      
      if (!redisClient) {
        // Fail-open policy when Redis is not available
        this.logger.debug('Redis not available for rate limiting - using fail-open policy');
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
      this.logger.error(MESSAGES.ERROR.RATE_LIMITER_ERROR, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        key,
        maxTokens,
        refillRate,
        windowMs,
      });
      // Fail-open policy on error
      return {
        allowed: true,
        tokensRemaining: maxTokens,
        resetTime: windowStart + windowMs,
      };
    }
  }
}

/**
 * Rate Limiter Service implementing IRateLimiter
 * Uses Strategy Pattern for different rate limiting algorithms
 */
export class RateLimiterService implements IRateLimiter {
  private strategy: IRateLimitStrategy;

  constructor(
    redisConnection: IRedisConnection,
    private logger: ILogger
  ) {
    // Use Token Bucket strategy by default
    this.strategy = new TokenBucketStrategy(redisConnection, logger);
  }

  /**
   * Set rate limiting strategy (Strategy Pattern)
   */
  setStrategy(strategy: IRateLimitStrategy): void {
    this.strategy = strategy;
  }

  /**
   * Create rate limiting middleware
   */
  middleware(options: RateLimitOptions): (req: Request, res: Response, next: NextFunction) => Promise<void> {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const key = options.keyGenerator ? options.keyGenerator(req) : (req.ip || DEFAULTS.UNKNOWN_IP);
        const refillRate = options.maxRequests / (options.windowMs / RATE_LIMIT.TOKENS_PER_SECOND_DIVISOR);

        const result = await this.strategy.isAllowed(
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
          this.logger.warn(MESSAGES.WARNING.RATE_LIMIT_EXCEEDED, {
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
        this.logger.debug(MESSAGES.INFO.RATE_LIMIT_CHECK_PASSED, {
          key,
          tokensRemaining: result.tokensRemaining,
          maxRequests: options.maxRequests,
        });

        next();
      } catch (error) {
        this.logger.error(MESSAGES.ERROR.RATE_LIMITER_MIDDLEWARE_ERROR, {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined,
          ip: req.ip,
          url: req.url,
          method: req.method,
        });
        // Fail-open policy on error
        next();
      }
    };
  }
} 