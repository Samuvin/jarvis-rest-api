import { IConfig } from '@/types/interfaces';
import { DEFAULTS, ENV_VARS } from '@/constants';

class ConfigService implements IConfig {
  public readonly server = {
    port: parseInt(process.env[ENV_VARS.PORT] || DEFAULTS.PORT.toString()),
    environment: process.env[ENV_VARS.NODE_ENV] || DEFAULTS.NODE_ENV,
    allowedOrigins: process.env[ENV_VARS.ALLOWED_ORIGINS]?.split(',') || ['http://localhost:3000'],
  };

  public readonly database = {
    mongoUri: this.getRequiredEnvVar(ENV_VARS.MONGO_URI),
  };

  public readonly redis = {
    url: process.env[ENV_VARS.REDIS_URL],
    upstashUrl: process.env[ENV_VARS.UPSTASH_REDIS_REST_URL],
    upstashToken: process.env[ENV_VARS.UPSTASH_REDIS_REST_TOKEN],
  };

  public readonly rateLimit = {
    windowMs: parseInt(process.env[ENV_VARS.RATE_LIMIT_WINDOW_MS] || DEFAULTS.RATE_LIMIT_WINDOW_MS.toString()),
    maxRequests: parseInt(process.env[ENV_VARS.RATE_LIMIT_MAX_REQUESTS] || DEFAULTS.RATE_LIMIT_MAX_REQUESTS.toString()),
    maxRequestsPerUser: parseInt(process.env[ENV_VARS.RATE_LIMIT_MAX_REQUESTS_PER_USER] || DEFAULTS.RATE_LIMIT_MAX_REQUESTS_PER_USER.toString()),
  };

  public readonly logging = {
    level: process.env[ENV_VARS.LOG_LEVEL] || (this.server.environment === 'production' ? 'info' : 'debug'),
    toConsole: process.env[ENV_VARS.LOG_TO_CONSOLE] === 'true',
    toFile: process.env[ENV_VARS.LOG_TO_FILE] === 'true',
  };

  private getRequiredEnvVar(key: string): string {
    const value = process.env[key];
    if (!value) {
      throw new Error(`Required environment variable ${key} is not defined`);
    }
    return value;
  }

  public validate(): void {
    // Validate critical configuration
    if (!this.database.mongoUri) {
      throw new Error('MongoDB URI is required');
    }

    if (this.server.port < 1 || this.server.port > 65535) {
      throw new Error('Invalid port number');
    }

    // Validate Redis configuration
    if (!this.redis.upstashUrl || !this.redis.upstashToken) {
      console.warn('Upstash Redis credentials not provided - Redis will be disabled');
    }
  }
}

// Singleton instance
export const config = new ConfigService();

// Validate configuration on import
config.validate(); 