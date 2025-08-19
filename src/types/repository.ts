import { Types } from 'mongoose';
import { IUser } from '@/models/User';
import { IChatSession } from '@/models/ChatSession';
import { IUpload } from '@/models/Upload';
import { IRefreshToken } from '@/models/RefreshToken';

// Generic Repository Interface
export interface IBaseRepository<T> {
  create(data: Partial<T>): Promise<T>;
  findById(id: string | Types.ObjectId): Promise<T | null>;
  findOne(filter: Partial<T>): Promise<T | null>;
  find(filter: Partial<T>, options?: QueryOptions): Promise<T[]>;
  updateById(id: string | Types.ObjectId, data: Partial<T>): Promise<T | null>;
  deleteById(id: string | Types.ObjectId): Promise<boolean>;
  count(filter: Partial<T>): Promise<number>;
}

// Query Options Interface
export interface QueryOptions {
  limit?: number;
  skip?: number;
  sort?: Record<string, 1 | -1>;
  select?: string | string[];
  populate?: string | string[];
}

// User Repository Interface
export interface IUserRepository extends IBaseRepository<IUser> {
  findByEmail(email: string): Promise<IUser | null>;
  findByUsername(username: string): Promise<IUser | null>;
  findByEmailOrUsername(emailOrUsername: string): Promise<IUser | null>;
  findActiveUsers(options?: QueryOptions): Promise<IUser[]>;
  updateLastLogin(userId: string | Types.ObjectId, ipAddress?: string, userAgent?: string): Promise<void>;
  resetUsage(userId: string | Types.ObjectId): Promise<void>;
  deactivateUser(userId: string | Types.ObjectId): Promise<boolean>;
  updatePreferences(userId: string | Types.ObjectId, preferences: Partial<IUser['preferences']>): Promise<IUser | null>;
  incrementUsage(userId: string | Types.ObjectId, requests: number, tokens: number): Promise<void>;
  createUser(userData: {
    email: string;
    username: string;
    password: string;
    scopes?: string[];
  }): Promise<IUser>;
}

// Chat Session Repository Interface
export interface IChatSessionRepository extends IBaseRepository<IChatSession> {
  findByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IChatSession[]>;
  findActiveSessionsByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IChatSession[]>;
  addMessageToSession(sessionId: string | Types.ObjectId, message: IChatSession['messages'][0]): Promise<IChatSession | null>;
  updateSessionStatus(sessionId: string | Types.ObjectId, status: IChatSession['status']): Promise<IChatSession | null>;
  findExpiredSessions(): Promise<IChatSession[]>;
  getSessionStats(userId: string | Types.ObjectId): Promise<{
    totalSessions: number;
    activeSessions: number;
    totalMessages: number;
    totalTokens: number;
  }>;
}

// Upload Repository Interface
export interface IUploadRepository extends IBaseRepository<IUpload> {
  findByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IUpload[]>;
  findByStatus(status: IUpload['status'], options?: QueryOptions): Promise<IUpload[]>;
  findByType(type: IUpload['type'], options?: QueryOptions): Promise<IUpload[]>;
  findByHash(hash: string): Promise<IUpload | null>;
  updateStatus(uploadId: string | Types.ObjectId, status: IUpload['status'], error?: string): Promise<IUpload | null>;
  markAsProcessed(uploadId: string | Types.ObjectId, extractedText?: string, vectorized?: boolean): Promise<IUpload | null>;
  findPendingUploads(options?: QueryOptions): Promise<IUpload[]>;
  findFailedUploads(options?: QueryOptions): Promise<IUpload[]>;
  getUploadStats(userId: string | Types.ObjectId): Promise<{
    totalUploads: number;
    totalSize: number;
    byType: Record<string, number>;
    byStatus: Record<string, number>;
  }>;
}

// Refresh Token Repository Interface
export interface IRefreshTokenRepository {
  create(data: Partial<IRefreshToken>): Promise<IRefreshToken>;
  findByToken(token: string): Promise<IRefreshToken | null>;
  findByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IRefreshToken[]>;
  findActiveTokensByUserId(userId: string | Types.ObjectId): Promise<IRefreshToken[]>;
  revokeToken(tokenId: string | Types.ObjectId): Promise<boolean>;
  revokeAllUserTokens(userId: string | Types.ObjectId): Promise<number>;
  cleanExpiredTokens(): Promise<number>;
  markAsUsed(tokenId: string | Types.ObjectId, ipAddress?: string, userAgent?: string): Promise<IRefreshToken | null>;
  createRefreshToken(data: {
    userId: Types.ObjectId;
    token: string;
    scopes: string[];
    expiresInDays?: number;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<IRefreshToken>;
}

// Pagination Result Interface
export interface IPaginationResult<T> {
  data: T[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    pages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

// Repository Factory Interface
export interface IRepositoryFactory {
  getUserRepository(): IUserRepository;
  getChatSessionRepository(): IChatSessionRepository;
  getUploadRepository(): IUploadRepository;
  getRefreshTokenRepository(): IRefreshTokenRepository;
} 