import mongoose from 'mongoose';
import { 
  IHealthChecker, 
  IDatabaseConnection, 
  IRedisConnection, 
  ILogger, 
  IConfig,
  HealthStatus,
  ServiceStatus,
  SystemInfo
} from '@/types/interfaces';
import { MESSAGES, DEFAULTS, STATUS, MONGO_STATES, ENV_VARS } from '@/constants';

export class HealthCheckerService implements IHealthChecker {
  constructor(
    private databaseConnection: IDatabaseConnection,
    private redisConnection: IRedisConnection,
    private config: IConfig,
    private logger: ILogger
  ) {}

  async checkHealth(): Promise<HealthStatus> {
    const startTime = Date.now();
    
    // Check all services in parallel for better performance
    const [mongoStatus, redisStatus, vectorDbStatus] = await Promise.all([
      this.checkMongoDB(),
      this.checkRedis(),
      this.checkVectorDB(),
    ]);

    // Determine overall status
    let overallStatus: 'healthy' | 'degraded' | 'unhealthy' = STATUS.HEALTHY;
    if (mongoStatus.status === STATUS.ERROR || redisStatus.status === STATUS.ERROR) {
      overallStatus = STATUS.UNHEALTHY;
    } else if (mongoStatus.status !== STATUS.CONNECTED || redisStatus.status !== STATUS.CONNECTED) {
      overallStatus = STATUS.DEGRADED;
    }

    const systemInfo = this.getSystemInfo();
    const responseTime = Date.now() - startTime;

    this.logger.http(MESSAGES.INFO.HEALTH_CHECK_PERFORMED, {
      status: overallStatus,
      responseTime,
      services: { mongodb: mongoStatus.status, redis: redisStatus.status, vectorDb: vectorDbStatus.status },
      ip: 'internal', // This would be set by the route handler
    });

    return {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || DEFAULTS.VERSION,
      environment: this.config.server.environment,
      services: {
        mongodb: mongoStatus,
        redis: redisStatus,
        vectorDb: vectorDbStatus,
      },
      system: systemInfo,
    };
  }

  async checkMongoDB(): Promise<ServiceStatus> {
    try {
      if (this.databaseConnection.isConnected()) {
        return { status: STATUS.CONNECTED };
      } else if (mongoose.connection.readyState === MONGO_STATES.DISCONNECTED) {
        return { status: STATUS.DISCONNECTED };
      } else {
        return { status: STATUS.ERROR };
      }
    } catch (error) {
      this.logger.error(MESSAGES.ERROR.MONGODB_STATUS_CHECK_ERROR, {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return { status: STATUS.ERROR };
    }
  }

  async checkRedis(): Promise<ServiceStatus> {
    try {
      const redisClient = this.redisConnection.getClient();
      if (redisClient) {
        const pong = await redisClient.ping();
        return { status: pong === 'PONG' ? STATUS.CONNECTED : STATUS.ERROR };
      } else {
        return { status: STATUS.DISCONNECTED };
      }
    } catch (error) {
      this.logger.error(MESSAGES.ERROR.REDIS_STATUS_CHECK_ERROR, {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return { status: STATUS.ERROR };
    }
  }

  async checkVectorDB(): Promise<ServiceStatus> {
    // Check if Upstash Vector credentials are configured
    if (process.env[ENV_VARS.UPSTASH_VECTOR_REST_URL] && process.env[ENV_VARS.UPSTASH_VECTOR_REST_TOKEN]) {
      // TODO: Implement actual Upstash Vector health check
      return { status: STATUS.CONNECTED };
    }
    return { status: STATUS.NOT_CONFIGURED };
  }

  private getSystemInfo(): SystemInfo {
    const memUsage = process.memoryUsage();
    const memTotal = memUsage.heapTotal + memUsage.external;
    const memUsed = memUsage.heapUsed;

    return {
      nodeVersion: process.version,
      platform: process.platform,
      memory: {
        used: memUsed,
        total: memTotal,
        percentage: Math.round((memUsed / memTotal) * 100),
      },
    };
  }
} 