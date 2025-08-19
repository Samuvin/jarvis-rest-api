import { Redis } from '@upstash/redis';
import { IRedisConnection, ILogger, IConfig } from '@/types/interfaces';
import { MESSAGES } from '@/constants';

export class RedisConnection implements IRedisConnection {
  private client: Redis | null = null;
  private connectionFailed = false;

  constructor(
    private config: IConfig,
    private logger: ILogger
  ) {}

  async connect(): Promise<Redis | null> {
    try {
      if (!this.config.redis.upstashUrl || !this.config.redis.upstashToken) {
        this.logger.warn('Upstash Redis credentials missing - Redis disabled', {
          hasUrl: !!this.config.redis.upstashUrl,
          hasToken: !!this.config.redis.upstashToken,
        });
        return null;
      }

      this.logger.info('Connecting to Upstash Redis...', {
        url: this.config.redis.upstashUrl,
      });

      this.client = new Redis({
        url: this.config.redis.upstashUrl,
        token: this.config.redis.upstashToken,
      });

      // Test the connection
      const testResult = await this.client.ping();
      if (testResult !== 'PONG') {
        throw new Error(`Redis ping test failed: ${testResult}`);
      }

      this.logger.info('Upstash Redis connection verified successfully');
      this.connectionFailed = false;
      return this.client;

    } catch (error) {
      this.logger.warn('Upstash Redis connection failed - continuing without Redis (fail-open)', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      this.connectionFailed = true;
      this.client = null;
      return null;
    }
  }

  async disconnect(): Promise<void> {
    try {
      // Upstash Redis doesn't need explicit disconnection (REST API)
      this.logger.info('Upstash Redis disconnected');
      this.client = null;
      this.connectionFailed = false;
    } catch (error) {
      this.logger.warn('Error disconnecting from Redis', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  getClient(): Redis | null {
    if (this.connectionFailed) {
      return null;
    }
    return this.client;
  }
} 