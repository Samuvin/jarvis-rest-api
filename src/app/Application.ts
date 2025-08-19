import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import path from 'path';

import { ILogger, IConfig } from '@/types/interfaces';
import { serviceFactory } from '@/services/ServiceFactory';
import { errorHandler } from '@/middleware/errorHandler';
import { HTTP_STATUS, ERROR_TYPES, HEADERS } from '@/constants';

// Import routes
import authRoutes from '@/routes/auth';
import chatRoutes from '@/routes/chat';
import uploadRoutes from '@/routes/upload';
import vectorRoutes from '@/routes/vector';
import userRoutes from '@/routes/user';
import featureRoutes from '@/routes/features';
import usageRoutes from '@/routes/usage';
import statusRoutes from '@/routes/status';
import adminRoutes from '@/routes/admin';

/**
 * Application class responsible for Express app configuration
 * Follows Single Responsibility Principle
 */
export class Application {
  private app: express.Application;

  constructor(
    private config: IConfig,
    private logger: ILogger
  ) {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  /**
   * Setup security and parsing middleware
   */
  private setupMiddleware(): void {
    // Security middleware
    this.app.use(helmet());
    this.app.use(cors({
      origin: this.config.server.allowedOrigins,
      credentials: true,
    }));

    // Request parsing and compression
    this.app.use(compression());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Logging middleware
    this.app.use(morgan('combined', {
      stream: {
        write: (message: string) => {
          this.logger.http(message.trim());
        },
      },
    }));

    // Rate limiting middleware
    const rateLimiter = serviceFactory.createRateLimiter();
    this.app.use(rateLimiter.middleware({
      windowMs: this.config.rateLimit.windowMs,
      maxRequests: this.config.rateLimit.maxRequests,
      message: 'Too many requests from this IP, please try again later.',
    }));

    // Static files for uploads
    this.app.use('/uploads', express.static(path.join(__dirname, '../../uploads')));
  }

  /**
   * Setup API routes
   */
  private setupRoutes(): void {
    // Health check endpoint (no auth required)
    this.app.use('/v1/status', statusRoutes);

    // API routes with authentication
    this.app.use('/v1/auth', authRoutes);
    this.app.use('/v1/chat', chatRoutes);
    this.app.use('/v1/upload', uploadRoutes);
    this.app.use('/v1/vector', vectorRoutes);
    this.app.use('/v1/users', userRoutes);
    this.app.use('/v1/features', featureRoutes);
    this.app.use('/v1/usage', usageRoutes);
    this.app.use('/v1/admin', adminRoutes);

    // 404 handler
    this.app.use('*', (req: express.Request, res: express.Response) => {
      this.logger.warn('Route not found', {
        url: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get(HEADERS.USER_AGENT),
      });

      res.status(HTTP_STATUS.NOT_FOUND).json({
        error: ERROR_TYPES.NOT_FOUND,
        message: `Route ${req.originalUrl} not found`,
        timestamp: new Date().toISOString(),
      });
    });
  }

  /**
   * Setup error handling middleware
   */
  private setupErrorHandling(): void {
    this.app.use(errorHandler);
  }

  /**
   * Get the Express application instance
   */
  getApp(): express.Application {
    return this.app;
  }
} 