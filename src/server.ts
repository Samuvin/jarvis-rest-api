import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config();

// Import logger first
import logger from '@/config/logger';
import { 
  MESSAGES, 
  ENV_VARS, 
  DEFAULTS, 
  HTTP_STATUS, 
  ERROR_TYPES, 
  HEADERS 
} from '@/constants';

// Import configurations and middleware
import { connectMongoDB } from '@/config/mongodb';
import { connectRedis } from '@/config/redis';
import { errorHandler } from '@/middleware/errorHandler';
import { rateLimiter } from '@/middleware/rateLimiter';

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

const app = express();
const PORT = process.env[ENV_VARS.PORT] || DEFAULTS.PORT;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env[ENV_VARS.ALLOWED_ORIGINS]?.split(',') || ['http://localhost:3000'],
  credentials: true,
}));

// Request parsing and compression
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware with Winston
app.use(morgan('combined', {
  stream: {
    write: (message: string) => {
      logger.http(message.trim());
    },
  },
}));

// Rate limiting
app.use(rateLimiter);

// Static files for uploads
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Health check endpoint (no auth required)
app.use('/v1/status', statusRoutes);

// API routes with authentication
app.use('/v1/auth', authRoutes);
app.use('/v1/chat', chatRoutes);
app.use('/v1/upload', uploadRoutes);
app.use('/v1/vector', vectorRoutes);
app.use('/v1/users', userRoutes);
app.use('/v1/features', featureRoutes);
app.use('/v1/usage', usageRoutes);
app.use('/v1/admin', adminRoutes);

// 404 handler
app.use('*', (req: express.Request, res: express.Response) => {
  logger.warn(MESSAGES.WARNING.ROUTE_NOT_FOUND, {
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

// Error handling middleware
app.use(errorHandler);

// Initialize database connections and start server
const startServer = async (): Promise<void> => {
  try {
    logger.info(MESSAGES.SUCCESS.SERVER_STARTING, {
      port: PORT,
      environment: process.env[ENV_VARS.NODE_ENV] || DEFAULTS.NODE_ENV,
    });

    // Connect to databases
    await connectMongoDB();
    
    // Connect to Redis (fail-open approach)
    const redisConnected = await connectRedis();
    if (!redisConnected) {
      logger.warn('Starting server without Redis - rate limiting and caching will be disabled');
    }

    // Start server
    app.listen(PORT, () => {
      logger.info(MESSAGES.SUCCESS.SERVER_STARTED, {
        port: PORT,
        environment: process.env[ENV_VARS.NODE_ENV] || DEFAULTS.NODE_ENV,
        healthCheckUrl: `http://localhost:${PORT}/v1/status`,
      });
    });
  } catch (error) {
    logger.error(MESSAGES.ERROR.SERVER_START_ERROR, {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info(MESSAGES.INFO.GRACEFUL_SHUTDOWN_SIGTERM);
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info(MESSAGES.INFO.GRACEFUL_SHUTDOWN_SIGINT);
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error(MESSAGES.ERROR.UNCAUGHT_EXCEPTION, {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  logger.error(MESSAGES.ERROR.UNHANDLED_REJECTION, {
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
    promise: promise.toString(),
  });
  process.exit(1);
});

// Start the server
startServer().catch(error => {
  logger.error(MESSAGES.ERROR.SERVER_STARTUP_ERROR, {
    error: error instanceof Error ? error.message : 'Unknown error',
    stack: error instanceof Error ? error.stack : undefined,
  });
  process.exit(1);
});

export default app; 