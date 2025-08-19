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
import { IRefreshTokenRepository } from '@/types/repository';
import { ILogger, IConfig } from '@/types/interfaces';
import { DATABASE, ENV_VARS, DEFAULTS, MESSAGES, AUTH } from '@/constants';

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
      this.logger.warn(MESSAGES.WARNING.JWT_SECRET_NOT_PROVIDED);
      return AUTH.DEFAULTS.JWT_SECRET_FALLBACK;
    }
    return secret;
  }

  async generateAccessToken(data: ITokenGenerationData): Promise<string> {
    try {
      const jti = crypto.randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const exp = now + (DATABASE.TOKEN.EXPIRY.ACCESS_TOKEN_HOURS * 3600);

      const payload: IJWTPayload = {
        sub: data.userId.toString(),
        iat: now,
        exp,
        iss: this.issuer,
        aud: this.audience,
        scopes: data.scopes,
        type: DATABASE.TOKEN.TYPES.ACCESS,
        jti,
      };

      const token = jwt.sign(payload, this.jwtSecret, {
        algorithm: this.jwtAlgorithm,
      });

      this.logger.info('Access token generated successfully', {
        userId: data.userId.toString(),
        scopes: data.scopes,
        expiresAt: new Date(exp * 1000).toISOString(),
        jti,
      });

      return token;

    } catch (error) {
      this.logger.error('Error generating access token', {
        error: error instanceof Error ? error.message : 'unknown',
        userId: data.userId.toString(),
      });
      throw error;
    }
  }

  async generateRefreshToken(data: ITokenGenerationData): Promise<{ token: string; refreshTokenDoc: IRefreshToken }> {
    try {
      const jti = crypto.randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const exp = now + (DATABASE.TOKEN.EXPIRY.REFRESH_TOKEN_DAYS * 24 * 3600);

      const payload: IJWTPayload = {
        sub: data.userId.toString(),
        iat: now,
        exp,
        iss: this.issuer,
        aud: this.audience,
        scopes: data.scopes,
        type: DATABASE.TOKEN.TYPES.REFRESH,
        jti,
      };

      const token = jwt.sign(payload, this.jwtSecret, {
        algorithm: this.jwtAlgorithm,
      });

      // Store refresh token in database
      const refreshTokenDoc = await this.refreshTokenRepo.createRefreshToken({
        userId: data.userId,
        token,
        scopes: data.scopes,
        expiresInDays: DATABASE.TOKEN.EXPIRY.REFRESH_TOKEN_DAYS,
        ...(data.ipAddress && { ipAddress: data.ipAddress }),
        ...(data.userAgent && { userAgent: data.userAgent }),
      });

      this.logger.info('Refresh token generated and stored', {
        userId: data.userId.toString(),
        tokenId: refreshTokenDoc._id.toString(),
        jti,
        expiresAt: refreshTokenDoc.expiresAt.toISOString(),
      });

      return { token, refreshTokenDoc };

    } catch (error) {
      this.logger.error('Error generating refresh token', {
        error: error instanceof Error ? error.message : 'unknown',
        userId: data.userId.toString(),
      });
      throw error;
    }
  }

  async generateTokenPair(data: ITokenGenerationData): Promise<ITokenResponse> {
    try {
      const [accessToken, { token: refreshToken }] = await Promise.all([
        this.generateAccessToken(data),
        this.generateRefreshToken(data),
      ]);

      this.logger.info('Token pair generated successfully', {
        userId: data.userId.toString(),
        hasAccessToken: !!accessToken,
        hasRefreshToken: !!refreshToken,
        scopes: data.scopes,
      });

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: DATABASE.TOKEN.EXPIRY.ACCESS_TOKEN_HOURS * 3600,
        refresh_token: refreshToken,
        scope: data.scopes.join(' '),
      };

    } catch (error) {
      this.logger.error('Error generating token pair', {
        error: error instanceof Error ? error.message : 'unknown',
        userId: data.userId.toString(),
      });
      throw error;
    }
  }

  async verifyAccessToken(token: string): Promise<IJWTPayload | null> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret, {
        algorithms: [this.jwtAlgorithm],
        issuer: this.issuer,
        audience: this.audience,
      }) as IJWTPayload;

      // Validate token type
      if (decoded.type !== DATABASE.TOKEN.TYPES.ACCESS) {
        this.logger.warn('Token type mismatch in access token verification', {
          expectedType: DATABASE.TOKEN.TYPES.ACCESS,
          actualType: decoded.type,
          jti: decoded.jti,
        });
        return null;
      }

      return decoded;

    } catch (error) {
      this.logger.debug('Access token verification failed', {
        error: error instanceof Error ? error.message : 'unknown',
        tokenPrefix: token.substring(0, 20),
      });
      return null;
    }
  }

  async verifyRefreshToken(token: string): Promise<{ payload: IJWTPayload; refreshTokenDoc: IRefreshToken } | null> {
    try {
      // First verify the JWT signature and structure
      const decoded = jwt.verify(token, this.jwtSecret, {
        algorithms: [this.jwtAlgorithm],
        issuer: this.issuer,
        audience: this.audience,
      }) as IJWTPayload;

      // Validate token type
      if (decoded.type !== DATABASE.TOKEN.TYPES.REFRESH) {
        this.logger.warn('Token type mismatch in refresh token verification', {
          expectedType: DATABASE.TOKEN.TYPES.REFRESH,
          actualType: decoded.type,
          jti: decoded.jti,
        });
        return null;
      }

      // Check if token exists in database and is active
      const refreshTokenDoc = await this.refreshTokenRepo.findByToken(token);
      if (!refreshTokenDoc || !refreshTokenDoc.isActive()) {
        this.logger.warn('Refresh token not found or inactive in database', {
          jti: decoded.jti,
          tokenExists: !!refreshTokenDoc,
          tokenActive: refreshTokenDoc?.isActive(),
        });
        return null;
      }

      return { payload: decoded, refreshTokenDoc };

    } catch (error) {
      this.logger.debug('Refresh token verification failed', {
        error: error instanceof Error ? error.message : 'unknown',
        tokenPrefix: token.substring(0, 20),
      });
      return null;
    }
  }

  async revokeRefreshToken(token: string): Promise<boolean> {
    try {
      // Find the token in the database
      const refreshTokenDoc = await this.refreshTokenRepo.findByToken(token);
      if (!refreshTokenDoc) {
        this.logger.info('Refresh token not found for revocation', {
          tokenPrefix: token.substring(0, 20),
        });
        return false; // Token doesn't exist, consider it already revoked
      }

      // Revoke the token
      await refreshTokenDoc.revoke();
      
      this.logger.info('Refresh token revoked successfully', {
        tokenId: refreshTokenDoc._id.toString(),
        userId: refreshTokenDoc.userId.toString(),
        jti: refreshTokenDoc.token ? (jwt.decode(refreshTokenDoc.token) as jwt.JwtPayload)?.jti || 'unknown' : 'unknown',
      });

      return true;

    } catch (error) {
      this.logger.error('Error revoking refresh token', {
        error: error instanceof Error ? error.message : 'unknown',
        tokenPrefix: token.substring(0, 20),
      });
      return false;
    }
  }

  async revokeAllUserTokens(userId: string | Types.ObjectId): Promise<number> {
    try {
      this.logger.info('Starting bulk token revocation for user', { userId: userId.toString() });
      
      const revokedCount = await this.refreshTokenRepo.revokeAllUserTokens(userId);
      
      this.logger.info('Bulk token revocation completed', {
        userId: userId.toString(),
        revokedCount,
      });

      return revokedCount;

    } catch (error) {
      this.logger.error('Error revoking all user tokens', {
        error: error instanceof Error ? error.message : 'unknown',
        userId: userId.toString(),
      });
      return 0;
    }
  }

  async cleanExpiredTokens(): Promise<number> {
    try {
      this.logger.info(MESSAGES.AUTH.TOKEN_CLEANUP_STARTED);
      
      const cleanedCount = await this.refreshTokenRepo.cleanExpiredTokens();
      
      this.logger.info(MESSAGES.AUTH.TOKEN_CLEANUP_COMPLETED, {
        cleanedCount,
      });

      return cleanedCount;

    } catch (error) {
      this.logger.error('Error cleaning expired tokens', {
        error: error instanceof Error ? error.message : 'unknown',
      });
      return 0;
    }
  }
} 