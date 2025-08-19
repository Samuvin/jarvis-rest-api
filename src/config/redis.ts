import { Redis } from '@upstash/redis';
import logger from '@/config/logger';
import { MESSAGES, ENV_VARS } from '@/constants';

let redisClient: Redis | null = null;
let redisConnectionFailed = false;

const connectRedis = async (): Promise<Redis | null> => {
  try {
    const upstashUrl = process.env[ENV_VARS.UPSTASH_REDIS_REST_URL];
    const upstashToken = process.env[ENV_VARS.UPSTASH_REDIS_REST_TOKEN];
    
    if (!upstashUrl || !upstashToken) {
      logger.warn('Upstash Redis credentials missing - Redis disabled', {
        hasUrl: !!upstashUrl,
        hasToken: !!upstashToken,
      });
      return null;
    }

    logger.info('Connecting to Upstash Redis...', {
      url: upstashUrl,
    });

    redisClient = new Redis({
      url: upstashUrl,
      token: upstashToken,
    });

    // Test the connection
    const testResult = await redisClient.ping();
    if (testResult !== 'PONG') {
      throw new Error(`Redis ping test failed: ${testResult}`);
    }

    logger.info('Upstash Redis connection verified successfully');
    redisConnectionFailed = false;
    return redisClient;

  } catch (error) {
    logger.warn('Upstash Redis connection failed - continuing without Redis (fail-open)', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    redisConnectionFailed = true;
    redisClient = null;
    return null;
  }
};

const getRedisClient = (): Redis | null => {
  if (redisConnectionFailed) {
    return null;
  }
  return redisClient;
};

const disconnectRedis = async (): Promise<void> => {
  try {
    // Upstash Redis doesn't need explicit disconnection (REST API)
    logger.info('Upstash Redis disconnected');
    redisClient = null;
    redisConnectionFailed = false;
  } catch (error) {
    logger.warn('Error disconnecting from Redis', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
};

export { connectRedis, getRedisClient, disconnectRedis }; 