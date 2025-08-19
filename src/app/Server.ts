import { Server as HttpServer } from 'http';
import { ILogger, IConfig } from '@/types/interfaces';
import { Application } from './Application';
import { serviceFactory } from '@/services/ServiceFactory';
import { MESSAGES } from '@/constants';

/**
 * Server class responsible for server lifecycle management
 * Follows Single Responsibility Principle
 */
export class Server {
  private httpServer?: HttpServer;
  private application: Application;

  constructor(
    private config: IConfig,
    private logger: ILogger
  ) {
    this.application = new Application(config, logger);
    this.setupGracefulShutdown();
  }

  /**
   * Start the server and initialize all services
   */
  async start(): Promise<void> {
    try {
      this.logger.info(MESSAGES.SUCCESS.SERVER_STARTING, {
        port: this.config.server.port,
        environment: this.config.server.environment,
      });

      // Initialize services using Service Factory
      await this.initializeServices();

      // Start HTTP server
      this.httpServer = this.application.getApp().listen(this.config.server.port, () => {
        this.logger.info(MESSAGES.SUCCESS.SERVER_STARTED, {
          port: this.config.server.port,
          environment: this.config.server.environment,
          healthCheckUrl: `http://localhost:${this.config.server.port}/v1/status`,
        });
      });

    } catch (error) {
      this.logger.error(MESSAGES.ERROR.SERVER_START_ERROR, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  /**
   * Stop the server and cleanup resources
   */
  async stop(): Promise<void> {
    this.logger.info('Stopping server...');
    
    if (this.httpServer) {
      return new Promise((resolve) => {
        this.httpServer!.close(() => {
          this.logger.info('Server stopped successfully');
          resolve();
        });
      });
    }
  }

  /**
   * Initialize all services using the Service Factory
   */
  private async initializeServices(): Promise<void> {
    // Initialize database connection
    const databaseConnection = serviceFactory.createDatabaseConnection();
    await databaseConnection.connect();

    // Initialize Redis connection (fail-open approach)
    const redisConnection = serviceFactory.createRedisConnection();
    const redisConnected = await redisConnection.connect();
    
    if (!redisConnected) {
      this.logger.warn('Starting server without Redis - rate limiting and caching will be disabled');
    }
  }

  /**
   * Setup graceful shutdown handlers
   */
  private setupGracefulShutdown(): void {
    // Handle graceful shutdown
    process.on('SIGTERM', this.gracefulShutdown.bind(this));
    process.on('SIGINT', this.gracefulShutdown.bind(this));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
      this.logger.error(MESSAGES.ERROR.UNCAUGHT_EXCEPTION, {
        error: error.message,
        stack: error.stack,
      });
      process.exit(1);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
      this.logger.error(MESSAGES.ERROR.UNHANDLED_REJECTION, {
        reason: reason instanceof Error ? reason.message : String(reason),
        stack: reason instanceof Error ? reason.stack : undefined,
        promise: promise.toString(),
      });
      process.exit(1);
    });
  }

  /**
   * Graceful shutdown handler
   */
  private async gracefulShutdown(signal: string): Promise<void> {
    this.logger.info(`${signal} received, shutting down gracefully`);
    
    try {
      await this.stop();
      process.exit(0);
    } catch (error) {
      this.logger.error('Error during graceful shutdown', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      process.exit(1);
    }
  }
} 