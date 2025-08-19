import { Types } from 'mongoose';
import { BaseRepository } from './BaseRepository';
import { IRefreshTokenRepository, QueryOptions } from '@/types/repository';
import { ILogger } from '@/types/interfaces';
import { RefreshToken, IRefreshToken } from '@/models/RefreshToken';
import { DATABASE } from '@/constants';

export class RefreshTokenRepository extends BaseRepository<IRefreshToken> implements IRefreshTokenRepository {
  constructor(logger: ILogger) {
    super(RefreshToken, logger);
  }

  async findByToken(token: string): Promise<IRefreshToken | null> {
    try {
      this.logger.debug('Finding refresh token by token', { token: token.substring(0, 10) + '...' });
      const refreshToken = await this.model.findOne({ token }).populate('userId', 'email username scopes isActive');
      this.logger.debug('Refresh token found by token', { 
        token: token.substring(0, 10) + '...', 
        found: !!refreshToken,
        status: refreshToken?.status,
        expired: refreshToken?.isExpired()
      });
      return refreshToken;
    } catch (error) {
      this.logger.error('Error finding refresh token by token', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        token: token.substring(0, 10) + '...',
      });
      throw error;
    }
  }

  async findByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IRefreshToken[]> {
    try {
      this.logger.debug('Finding refresh tokens by user ID', { userId, options });
      const tokens = await this.find({ userId } as Partial<IRefreshToken>, {
        ...options,
        sort: options?.sort || { 'metadata.createdAt': DATABASE.INDEXES.DESCENDING },
      });
      this.logger.debug('Refresh tokens found by user ID', { userId, count: tokens.length });
      return tokens;
    } catch (error) {
      this.logger.error('Error finding refresh tokens by user ID', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        options,
      });
      throw error;
    }
  }

  async findActiveTokensByUserId(userId: string | Types.ObjectId): Promise<IRefreshToken[]> {
    try {
      this.logger.debug('Finding active refresh tokens by user ID', { userId });
      const tokens = await this.model.find({
        userId,
        status: DATABASE.TOKEN.STATUS.ACTIVE,
        expiresAt: { $gt: new Date() }
      })
      .sort({ 'metadata.createdAt': DATABASE.INDEXES.DESCENDING })
      .exec();
      this.logger.debug('Active refresh tokens found by user ID', { userId, count: tokens.length });
      return tokens;
    } catch (error) {
      this.logger.error('Error finding active refresh tokens by user ID', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
      });
      throw error;
    }
  }

  async revokeToken(tokenId: string | Types.ObjectId): Promise<boolean> {
    try {
      this.logger.debug('Revoking refresh token', { tokenId });
      const token = await this.model.findById(tokenId);
      if (!token) {
        this.logger.warn('Refresh token not found for revocation', { tokenId });
        return false;
      }

      await token.revoke();
      this.logger.info('Refresh token revoked', { tokenId, userId: token.userId });
      return true;
    } catch (error) {
      this.logger.error('Error revoking refresh token', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        tokenId,
      });
      throw error;
    }
  }

  async revokeAllUserTokens(userId: string | Types.ObjectId): Promise<number> {
    try {
      this.logger.debug('Revoking all refresh tokens for user', { userId });
      const result = await this.model.updateMany(
        { 
          userId, 
          status: DATABASE.TOKEN.STATUS.ACTIVE 
        },
        { 
          status: DATABASE.TOKEN.STATUS.REVOKED,
          'metadata.revokedAt': new Date(),
          'metadata.updatedAt': new Date(),
        }
      );
      
      const revokedCount = result.modifiedCount || 0;
      this.logger.info('All user refresh tokens revoked', { userId, revokedCount });
      return revokedCount;
    } catch (error) {
      this.logger.error('Error revoking all user refresh tokens', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
      });
      throw error;
    }
  }

  async cleanExpiredTokens(): Promise<number> {
    try {
      this.logger.debug('Cleaning expired refresh tokens');
      const deletedCount = await (RefreshToken as any).cleanExpiredTokens();
      this.logger.info('Expired refresh tokens cleaned', { deletedCount });
      return deletedCount;
    } catch (error) {
      this.logger.error('Error cleaning expired refresh tokens', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async markAsUsed(
    tokenId: string | Types.ObjectId,
    ipAddress?: string,
    userAgent?: string
  ): Promise<IRefreshToken | null> {
    try {
      this.logger.debug('Marking refresh token as used', { tokenId, ipAddress, userAgent });
      const token = await this.model.findById(tokenId);
      if (!token) {
        this.logger.warn('Refresh token not found for usage marking', { tokenId });
        return null;
      }

      await token.markAsUsed(ipAddress, userAgent);
      this.logger.debug('Refresh token marked as used', { tokenId });
      return token;
    } catch (error) {
      this.logger.error('Error marking refresh token as used', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        tokenId,
        ipAddress,
        userAgent,
      });
      throw error;
    }
  }

  /**
   * Create refresh token with expiry date
   */
  async createRefreshToken(data: {
    userId: Types.ObjectId;
    token: string;
    scopes: string[];
    expiresInDays?: number;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<IRefreshToken> {
    try {
      this.logger.debug('Creating refresh token', { 
        userId: data.userId, 
        scopes: data.scopes,
        expiresInDays: data.expiresInDays
      });

      const expiresInDays = data.expiresInDays || DATABASE.TOKEN.EXPIRY.REFRESH_TOKEN_DAYS;
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + expiresInDays);

      const refreshToken = await this.create({
        userId: data.userId,
        token: data.token,
        scopes: data.scopes,
        expiresAt,
        metadata: {
          createdAt: new Date(),
          updatedAt: new Date(),
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
        },
      } as Partial<IRefreshToken>);

      this.logger.info('Refresh token created successfully', { 
        id: refreshToken._id,
        userId: refreshToken.userId,
        expiresAt: refreshToken.expiresAt
      });

      return refreshToken;
    } catch (error) {
      this.logger.error('Error creating refresh token', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId: data.userId,
        scopes: data.scopes,
      });
      throw error;
    }
  }
} 