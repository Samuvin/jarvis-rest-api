import { 
  IServiceFactory, 
  IDatabaseConnection, 
  IRedisConnection, 
  IRateLimiter, 
  IHealthChecker, 
  IRepositoryFactory,
  ILogger 
} from '@/types/interfaces';
import { IJWTService, IAuthService } from '@/types/auth';
import { IAuthMiddleware } from '@/middleware/auth';
import { config } from '@/config';
import { MongoDBConnection } from '@/services/MongoDBConnection';
import { RedisConnection } from '@/services/RedisConnection';
import { RateLimiterService } from '@/services/RateLimiterService';
import { HealthCheckerService } from '@/services/HealthCheckerService';
import { JWTService } from '@/services/JWTService';
import { AuthService } from '@/services/AuthService';
import { AuthMiddleware } from '@/middleware/auth';
import { RepositoryFactory } from '@/repositories/RepositoryFactory';
import logger from '@/config/logger';

/**
 * Service Factory implementing Factory Pattern
 * Creates services with proper dependency injection
 * Following SOLID principles
 */
export class ServiceFactory implements IServiceFactory {
  private databaseConnection: IDatabaseConnection | null = null;
  private redisConnection: IRedisConnection | null = null;
  private rateLimiter: IRateLimiter | null = null;
  private healthChecker: IHealthChecker | null = null;
  private repositoryFactory: IRepositoryFactory | null = null;
  private jwtService: IJWTService | null = null;
  private authService: IAuthService | null = null;
  private authMiddleware: IAuthMiddleware | null = null;
  private logger: ILogger;

  constructor(logger: ILogger) {
    this.logger = logger;
  }

  /**
   * Create or return existing database connection (Singleton pattern)
   */
  createDatabaseConnection(): IDatabaseConnection {
    if (!this.databaseConnection) {
      this.databaseConnection = new MongoDBConnection(config, this.logger);
    }
    return this.databaseConnection;
  }

  /**
   * Create or return existing Redis connection (Singleton pattern)
   */
  createRedisConnection(): IRedisConnection {
    if (!this.redisConnection) {
      this.redisConnection = new RedisConnection(config, this.logger);
    }
    return this.redisConnection;
  }

  /**
   * Create or return existing rate limiter with strategy injection
   */
  createRateLimiter(): IRateLimiter {
    if (!this.rateLimiter) {
      const redisConnection = this.createRedisConnection();
      this.rateLimiter = new RateLimiterService(redisConnection, this.logger);
    }
    return this.rateLimiter;
  }

  /**
   * Create or return existing health checker with service dependencies
   */
  createHealthChecker(): IHealthChecker {
    if (!this.healthChecker) {
      const databaseConnection = this.createDatabaseConnection();
      const redisConnection = this.createRedisConnection();
      this.healthChecker = new HealthCheckerService(
        databaseConnection,
        redisConnection,
        config,
        this.logger
      );
    }
    return this.healthChecker;
  }

  /**
   * Create or return existing repository factory with database access
   */
  createRepositoryFactory(): IRepositoryFactory {
    if (!this.repositoryFactory) {
      this.repositoryFactory = new RepositoryFactory(this.logger);
      this.logger.debug('RepositoryFactory instance created in ServiceFactory');
    }
    return this.repositoryFactory;
  }

  /**
   * Create or return existing JWT service with refresh token repository
   */
  createJWTService(): IJWTService {
    if (!this.jwtService) {
      const repositoryFactory = this.createRepositoryFactory();
      const refreshTokenRepo = repositoryFactory.getRefreshTokenRepository();
      this.jwtService = new JWTService(refreshTokenRepo, config, this.logger);
      this.logger.debug('JWTService instance created in ServiceFactory');
    }
    return this.jwtService;
  }

  /**
   * Create or return existing authentication service with dependencies
   */
  createAuthService(): IAuthService {
    if (!this.authService) {
      const repositoryFactory = this.createRepositoryFactory();
      const userRepo = repositoryFactory.getUserRepository();
      const jwtService = this.createJWTService();
      this.authService = new AuthService(userRepo, jwtService, this.logger);
      this.logger.debug('AuthService instance created in ServiceFactory');
    }
    return this.authService;
  }

  /**
   * Create or return existing authentication middleware
   */
  createAuthMiddleware(): IAuthMiddleware {
    if (!this.authMiddleware) {
      const jwtService = this.createJWTService();
      const repositoryFactory = this.createRepositoryFactory();
      const userRepo = repositoryFactory.getUserRepository();
      this.authMiddleware = new AuthMiddleware(jwtService, userRepo, this.logger);
      this.logger.debug('AuthMiddleware instance created in ServiceFactory');
    }
    return this.authMiddleware;
  }

  /**
   * Reset factory state (useful for testing)
   */
  reset(): void {
    this.databaseConnection = null;
    this.redisConnection = null;
    this.rateLimiter = null;
    this.healthChecker = null;
    this.repositoryFactory = null;
    this.jwtService = null;
    this.authService = null;
    this.authMiddleware = null;
  }
}

// Export singleton factory instance
export const serviceFactory = new ServiceFactory(logger); 