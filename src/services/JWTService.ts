import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Types } from 'mongoose';
import { 
  IJWTService, 
  IJWTPayload, 
  ITokenResponse, 
  ITokenGenerationData 
} from '@/types/auth';
import { IRefreshToken } from '@/models/RefreshToken';
import { IRefreshTokenRepository } from '@/repositories/RefreshTokenRepository';
import { ILogger, IConfig } from '@/types/interfaces';
import { DATABASE, ENV_VARS, DEFAULTS } from '@/constants';

export class JWTService implements IJWTService {
  private jwtSecret: string;
  private jwtAlgorithm: jwt.Algorithm;
  private issuer: string;
  private audience: string;

  constructor(
    private refreshTokenRepo: IRefreshTokenRepository,
    private config: IConfig,
    private logger: ILogger
  ) {
    this.jwtSecret = this.getJWTSecret();
    this.jwtAlgorithm = DATABASE.AUTH.JWT.ALGORITHM as jwt.Algorithm;
    this.issuer = DATABASE.AUTH.JWT.ISSUER;
    this.audience = DATABASE.AUTH.JWT.AUDIENCE;
  }

  private getJWTSecret(): string {
    const secret = process.env[ENV_VARS.JWT_SECRET];
    if (!secret) {
      this.logger.warn('JWT_SECRET not provided, using default (not recommended for production)');
      return 'fallback-jwt-secret-change-in-production';
    }
    return secret;
  }

  async generateAccessToken(data: ITokenGenerationData): Promise<string> {
    try {
      this.logger.debug('Generating access token', { 
        userId: data.userId, 
        scopes: data.scopes,
        expiresInHours: data.expiresInHours 
      });

      const now = Math.floor(Date.now() / 1000);
      const expiresInHours = data.expiresInHours || DATABASE.TOKEN.EXPIRY.ACCESS_TOKEN_HOURS;
      const expiresIn = expiresInHours * 60 * 60; // Convert to seconds
      
      const payload: IJWTPayload = {
        sub: data.userId.toString(),
        iat: now,
        exp: now + expiresIn,
        iss: this.issuer,
        aud: this.audience,
        scopes: data.scopes,
        type: 'access',
        jti: crypto.randomUUID(),
      };

      const token = jwt.sign(payload, this.jwtSecret, {
        algorithm: this.jwtAlgorithm,
        noTimestamp: true, // We set iat manually
      });

      this.logger.info('Access token generated successfully', {
        userId: data.userId,
        scopes: data.scopes,
        expiresAt: new Date((now + expiresIn) * 1000).toISOString(),
        jti: payload.jti,
      });

      return token;
    } catch (error) {
      this.logger.error('Error generating access token', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId: data.userId,
        scopes: data.scopes,
      });
      throw error;
    }
  }

  async generateRefreshToken(data: ITokenGenerationData): Promise<{ token: string; refreshTokenDoc: IRefreshToken }> {
    try {
      this.logger.debug('Generating refresh token', {
        userId: data.userId,
        scopes: data.scopes
      });

      const now = Math.floor(Date.now() / 1000);
      const expiresInDays = DATABASE.TOKEN.EXPIRY.REFRESH_TOKEN_DAYS;
      const expiresIn = expiresInDays * 24 * 60 * 60; // Convert to seconds
      
      const jti = crypto.randomUUID();
      const payload: IJWTPayload = {
        sub: data.userId.toString(),
        iat: now,
        exp: now + expiresIn,
        iss: this.issuer,
        aud: this.audience,
        scopes: data.scopes,
        type: 'refresh',
        jti,
      };

      const token = jwt.sign(payload, this.jwtSecret, {
        algorithm: this.jwtAlgorithm,
        noTimestamp: true,
      });

      // Store refresh token in database
      const refreshTokenDoc = await this.refreshTokenRepo.createRefreshToken({
        userId: data.userId,
        token: jti, // Store JWT ID, not the full token
        scopes: data.scopes,
        expiresInDays,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      });

      this.logger.info('Refresh token generated and stored', {
        userId: data.userId,
        tokenId: refreshTokenDoc._id,
        jti,
        expiresAt: refreshTokenDoc.expiresAt.toISOString(),
      });

      return { token, refreshTokenDoc };
    } catch (error) {
      this.logger.error('Error generating refresh token', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId: data.userId,
        scopes: data.scopes,
      });
      throw error;
    }
  }

  async generateTokenPair(data: ITokenGenerationData): Promise<ITokenResponse> {
    try {
      this.logger.debug('Generating token pair', {
        userId: data.userId,
        scopes: data.scopes
      });

      const [accessToken, refreshTokenResult] = await Promise.all([
        this.generateAccessToken(data),
        this.generateRefreshToken(data),
      ]);

      const tokenResponse: ITokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: (data.expiresInHours || DATABASE.TOKEN.EXPIRY.ACCESS_TOKEN_HOURS) * 3600,
        refresh_token: refreshTokenResult.token,
        scope: data.scopes.join(' '),
      };

      this.logger.info('Token pair generated successfully', {
        userId: data.userId,
        hasAccessToken: !!tokenResponse.access_token,
        hasRefreshToken: !!tokenResponse.refresh_token,
        scopes: data.scopes,
      });

      return tokenResponse;
    } catch (error) {
      this.logger.error('Error generating token pair', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId: data.userId,
        scopes: data.scopes,
      });
      throw error;
    }
  }

  async verifyAccessToken(token: string): Promise<IJWTPayload | null> {
    try {
      this.logger.debug('Verifying access token');

      const payload = jwt.verify(token, this.jwtSecret, {
        algorithms: [this.jwtAlgorithm],
        issuer: this.issuer,
        audience: this.audience,
      }) as IJWTPayload;

      if (payload.type !== 'access') {
        this.logger.warn('Token type mismatch in access token verification', {
          expected: 'access',
          actual: payload.type,
          jti: payload.jti,
        });
        return null;
      }

      this.logger.debug('Access token verified successfully', {
        sub: payload.sub,
        scopes: payload.scopes,
        exp: payload.exp,
        jti: payload.jti,
      });

      return payload;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        this.logger.debug('Access token verification failed', {
          error: error.message,
          name: error.name,
        });
      } else {
        this.logger.error('Error verifying access token', {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined,
        });
      }
      return null;
    }
  }

  async verifyRefreshToken(token: string): Promise<{ payload: IJWTPayload; refreshTokenDoc: IRefreshToken } | null> {
    try {
      this.logger.debug('Verifying refresh token');

      // First verify JWT signature and structure
      const payload = jwt.verify(token, this.jwtSecret, {
        algorithms: [this.jwtAlgorithm],
        issuer: this.issuer,
        audience: this.audience,
      }) as IJWTPayload;

      if (payload.type !== 'refresh') {
        this.logger.warn('Token type mismatch in refresh token verification', {
          expected: 'refresh',
          actual: payload.type,
          jti: payload.jti,
        });
        return null;
      }

      // Check if refresh token exists in database and is active
      const refreshTokenDoc = await this.refreshTokenRepo.findByToken(payload.jti!);
      if (!refreshTokenDoc) {
        this.logger.warn('Refresh token not found in database', {
          jti: payload.jti,
          sub: payload.sub,
        });
        return null;
      }

      if (!refreshTokenDoc.isActive()) {
        this.logger.warn('Refresh token is not active', {
          jti: payload.jti,
          status: refreshTokenDoc.status,
          expired: refreshTokenDoc.isExpired(),
          sub: payload.sub,
        });
        return null;
      }

      this.logger.debug('Refresh token verified successfully', {
        jti: payload.jti,
        sub: payload.sub,
        scopes: payload.scopes,
        tokenId: refreshTokenDoc._id,
      });

      return { payload, refreshTokenDoc };
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        this.logger.debug('Refresh token verification failed', {
          error: error.message,
          name: error.name,
        });
      } else {
        this.logger.error('Error verifying refresh token', {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined,
        });
      }
      return null;
    }
  }

  async revokeRefreshToken(token: string): Promise<boolean> {
    try {
      this.logger.debug('Revoking refresh token');

      const verificationResult = await this.verifyRefreshToken(token);
      if (!verificationResult) {
        this.logger.warn('Cannot revoke invalid or non-existent refresh token');
        return false;
      }

      const { refreshTokenDoc } = verificationResult;
      await refreshTokenDoc.revoke();

      this.logger.info('Refresh token revoked successfully', {
        tokenId: refreshTokenDoc._id,
        userId: refreshTokenDoc.userId,
        jti: verificationResult.payload.jti,
      });

      return true;
    } catch (error) {
      this.logger.error('Error revoking refresh token', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      return false;
    }
  }

  async revokeAllUserTokens(userId: string | Types.ObjectId): Promise<number> {
    try {
      this.logger.debug('Revoking all refresh tokens for user', { userId });

      const revokedCount = await this.refreshTokenRepo.revokeAllUserTokens(userId);

      this.logger.info('All user refresh tokens revoked', { userId, revokedCount });
      return revokedCount;
    } catch (error) {
      this.logger.error('Error revoking all user tokens', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
      });
      throw error;
    }
  }

  /**
   * Clean up expired tokens (can be called periodically)
   */
  async cleanExpiredTokens(): Promise<number> {
    try {
      this.logger.debug('Cleaning expired refresh tokens');
      const deletedCount = await this.refreshTokenRepo.cleanExpiredTokens();
      this.logger.info('Expired tokens cleaned', { deletedCount });
      return deletedCount;
    } catch (error) {
      this.logger.error('Error cleaning expired tokens', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }
} 