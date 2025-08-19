import { Router, Request, Response } from 'express';
import mongoose from 'mongoose';
import { getRedisClient } from '@/config/redis';
import { asyncHandler } from '@/middleware/errorHandler';
import logger from '@/config/logger';
import { 
  MESSAGES, 
  ENV_VARS, 
  DEFAULTS, 
  STATUS, 
  HTTP_STATUS, 
  MONGO_STATES,
  HEADERS 
} from '@/constants';

const router = Router();

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  uptime: number;
  version: string;
  environment: string;
  services: {
    mongodb: 'connected' | 'disconnected' | 'error';
    redis: 'connected' | 'disconnected' | 'error';
    vectorDb: 'connected' | 'disconnected' | 'not_configured';
  };
  system: {
    nodeVersion: string;
    platform: string;
    memory: {
      used: number;
      total: number;
      percentage: number;
    };
  };
}

// Health check endpoint
router.get('/', asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();
  
  // Check MongoDB connection
  let mongoStatus: 'connected' | 'disconnected' | 'error' = STATUS.DISCONNECTED;
  try {
    if (mongoose.connection.readyState === MONGO_STATES.CONNECTED) {
      mongoStatus = STATUS.CONNECTED;
    } else if (mongoose.connection.readyState === MONGO_STATES.DISCONNECTED) {
      mongoStatus = STATUS.DISCONNECTED;
    } else {
      mongoStatus = STATUS.ERROR;
    }
  } catch (error) {
    mongoStatus = STATUS.ERROR;
    logger.error(MESSAGES.ERROR.MONGODB_STATUS_CHECK_ERROR, {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  // Check Redis connection
  let redisStatus: 'connected' | 'disconnected' | 'error' = STATUS.DISCONNECTED;
  try {
    const redisClient = getRedisClient();
    const pong = await redisClient.ping();
    redisStatus = pong === 'PONG' ? STATUS.CONNECTED : STATUS.ERROR;
  } catch (error) {
    redisStatus = STATUS.ERROR;
    logger.error(MESSAGES.ERROR.REDIS_STATUS_CHECK_ERROR, {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  // Check Vector DB (placeholder for now)
  let vectorDbStatus: 'connected' | 'disconnected' | 'not_configured' = STATUS.NOT_CONFIGURED;
  if (process.env[ENV_VARS.UPSTASH_VECTOR_REST_URL] && process.env[ENV_VARS.UPSTASH_VECTOR_REST_TOKEN]) {
    vectorDbStatus = STATUS.CONNECTED; // TODO: Implement actual health check
  }

  // Calculate overall status
  let overallStatus: 'healthy' | 'degraded' | 'unhealthy' = STATUS.HEALTHY;
  if (mongoStatus === STATUS.ERROR || redisStatus === STATUS.ERROR) {
    overallStatus = STATUS.UNHEALTHY;
  } else if (mongoStatus !== STATUS.CONNECTED || redisStatus !== STATUS.CONNECTED) {
    overallStatus = STATUS.DEGRADED;
  }

  // System information
  const memUsage = process.memoryUsage();
  const memTotal = memUsage.heapTotal + memUsage.external;
  const memUsed = memUsage.heapUsed;

  const healthStatus: HealthStatus = {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || DEFAULTS.VERSION,
    environment: process.env[ENV_VARS.NODE_ENV] || DEFAULTS.NODE_ENV,
    services: {
      mongodb: mongoStatus,
      redis: redisStatus,
      vectorDb: vectorDbStatus,
    },
    system: {
      nodeVersion: process.version,
      platform: process.platform,
      memory: {
        used: memUsed,
        total: memTotal,
        percentage: Math.round((memUsed / memTotal) * 100),
      },
    },
  };

  const responseTime = Date.now() - startTime;
  
  // Log health check
  logger.http(MESSAGES.INFO.HEALTH_CHECK_PERFORMED, {
    status: overallStatus,
    responseTime,
    services: healthStatus.services,
    ip: req.ip,
  });
  
  // Set response status based on health
  const statusCode = overallStatus === STATUS.HEALTHY ? HTTP_STATUS.OK : 
                    overallStatus === STATUS.DEGRADED ? HTTP_STATUS.OK : HTTP_STATUS.SERVICE_UNAVAILABLE;

  res.status(statusCode)
     .set(HEADERS.RESPONSE_TIME, `${responseTime}ms`)
     .json(healthStatus);
}));

// Readiness probe (for Kubernetes)
router.get('/ready', asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const mongoReady = mongoose.connection.readyState === MONGO_STATES.CONNECTED;
  let redisReady = false;
  
  try {
    const redisClient = getRedisClient();
    const pong = await redisClient.ping();
    redisReady = pong === 'PONG';
  } catch (error) {
    redisReady = false;
    logger.debug(MESSAGES.WARNING.REDIS_NOT_READY, {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  const isReady = mongoReady && redisReady;

  logger.debug(MESSAGES.INFO.READINESS_PROBE_CHECK, {
    ready: isReady,
    mongodb: mongoReady,
    redis: redisReady,
    ip: req.ip,
  });

  if (isReady) {
    res.status(HTTP_STATUS.OK).json({ 
      status: STATUS.READY, 
      timestamp: new Date().toISOString() 
    });
  } else {
    res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({ 
      status: STATUS.NOT_READY, 
      mongodb: mongoReady,
      redis: redisReady,
      timestamp: new Date().toISOString(),
    });
  }
}));

// Liveness probe (for Kubernetes)
router.get('/live', (req: Request, res: Response): void => {
  logger.debug(MESSAGES.INFO.LIVENESS_PROBE_CHECK, { ip: req.ip });
  
  res.status(HTTP_STATUS.OK).json({ 
    status: STATUS.ALIVE, 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

export default router; 