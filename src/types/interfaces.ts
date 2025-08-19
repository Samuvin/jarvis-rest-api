// Core service interfaces for Dependency Inversion Principle

import { Request, Response, NextFunction } from 'express';
import { Redis } from '@upstash/redis';
import { IRepositoryFactory } from './repository';

// Export repository interfaces
export * from './repository';

// Database Connection Interfaces
export interface IDatabaseConnection {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
}

export interface IRedisConnection {
  connect(): Promise<Redis | null>;
  disconnect(): Promise<void>;
  getClient(): Redis | null;
}

// Rate Limiting Interfaces
export interface IRateLimitStrategy {
  isAllowed(key: string, maxTokens: number, refillRate: number, windowMs: number): Promise<RateLimitResult>;
}

export interface IRateLimiter {
  middleware(options: RateLimitOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
}

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: Request) => string;
  message?: string;
  statusCode?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  tokensRemaining: number;
  resetTime: number;
}

// Health Check Interface
export interface IHealthChecker {
  checkHealth(): Promise<HealthStatus>;
  checkMongoDB(): Promise<ServiceStatus>;
  checkRedis(): Promise<ServiceStatus>;
  checkVectorDB(): Promise<ServiceStatus>;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  uptime: number;
  version: string;
  environment: string;
  services: {
    mongodb: ServiceStatus;
    redis: ServiceStatus;
    vectorDb: ServiceStatus;
  };
  system: SystemInfo;
}

export interface ServiceStatus {
  status: 'connected' | 'disconnected' | 'error' | 'not_configured';
}

export interface SystemInfo {
  nodeVersion: string;
  platform: string;
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
}

// Logger Interface
export interface ILogger {
  info(message: string, metadata?: Record<string, any>): void;
  warn(message: string, metadata?: Record<string, any>): void;
  error(message: string, metadata?: Record<string, any>): void;
  debug(message: string, metadata?: Record<string, any>): void;
  http(message: string, metadata?: Record<string, any>): void;
}

// Configuration Interface
export interface IConfig {
  server: {
    port: number;
    environment: string;
    allowedOrigins: string[];
  };
  database: {
    mongoUri: string;
  };
  redis: {
    url?: string | undefined;
    upstashUrl?: string | undefined;
    upstashToken?: string | undefined;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
    maxRequestsPerUser: number;
  };
  logging: {
    level: string;
    toConsole: boolean;
    toFile: boolean;
  };
}

// Service Factory Interface
export interface IServiceFactory {
  createDatabaseConnection(): IDatabaseConnection;
  createRedisConnection(): IRedisConnection;
  createRateLimiter(): IRateLimiter;
  createHealthChecker(): IHealthChecker;
  createRepositoryFactory(): IRepositoryFactory;
} 