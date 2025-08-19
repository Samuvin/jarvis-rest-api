import { Request, Response, NextFunction } from 'express';
import { IJWTService, IAuthenticatedRequest } from '@/types/auth';
import { IUserRepository } from '@/types/repository';
import { ILogger } from '@/types/interfaces';
import { HTTP_STATUS, ERROR_TYPES, HEADERS, MESSAGES, AUTH, OAUTH2 } from '@/constants';

export interface IAuthMiddleware {
  authenticate(req: Request, res: Response, next: NextFunction): Promise<void>;
  requireScope(scopes: string | string[]): (req: Request, res: Response, next: NextFunction) => Promise<void>;
  optional(req: Request, res: Response, next: NextFunction): Promise<void>;
}

export class AuthMiddleware implements IAuthMiddleware {
  constructor(
    private jwtService: IJWTService,
    private userRepo: IUserRepository,
    private logger: ILogger
  ) {}

  /**
   * Required authentication middleware
   * Validates JWT token and attaches user to request
   */
  authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = this.extractTokenFromHeader(req);
      
      if (!token) {
        this.logger.warn(MESSAGES.AUTH.AUTHENTICATION_REQUIRED, {
          path: req.path,
          method: req.method,
          ip: req.ip,
        });
        
        res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: OAUTH2.ERRORS.INVALID_REQUEST,
          error_description: AUTH.ERROR_MESSAGES.AUTHENTICATION_REQUIRED,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Verify the access token
      const payload = await this.jwtService.verifyAccessToken(token);
      if (!payload) {
        this.logger.warn(MESSAGES.AUTH.INVALID_ACCESS_TOKEN, {
          path: req.path,
          method: req.method,
          ip: req.ip,
        });
        
        res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: OAUTH2.ERRORS.INVALID_TOKEN,
          error_description: AUTH.ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Get user details and verify user is still active
      const user = await this.userRepo.findById(payload.sub);
      if (!user || !user.isActive) {
        this.logger.warn(MESSAGES.AUTH.TOKEN_VALID_USER_INACTIVE, {
          userId: payload.sub,
          userFound: !!user,
          userActive: user?.isActive,
          path: req.path,
        });
        
        res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: OAUTH2.ERRORS.INVALID_TOKEN,
          error_description: AUTH.ERROR_MESSAGES.USER_INACTIVE,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Attach user and token payload to request
      const authReq = req as IAuthenticatedRequest;
      authReq.user = user;
      authReq.token = payload;

      this.logger.debug('Authentication successful', {
        userId: user._id,
        username: user.username,
        scopes: payload.scopes,
        path: req.path,
      });

      next();

    } catch (error) {
      this.logger.error('Error in authentication middleware', {
        error: error instanceof Error ? error.message : 'unknown',
        path: req.path,
        method: req.method,
        ip: req.ip,
      });
      
      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        error: OAUTH2.ERRORS.SERVER_ERROR,
        error_description: OAUTH2.ERROR_DESCRIPTIONS.SERVER_ERROR,
        timestamp: new Date().toISOString(),
      });
    }
  };

  /**
   * Scope-based authorization middleware
   * Requires specific scopes to access the endpoint
   */
  requireScope = (scopes: string | string[]) => {
    const requiredScopes = Array.isArray(scopes) ? scopes : [scopes];
    
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const authReq = req as IAuthenticatedRequest;
        
        if (!authReq.token) {
          this.logger.warn('Scope check attempted without authentication', {
            path: req.path,
            method: req.method,
            requiredScopes,
          });
          
          res.status(HTTP_STATUS.UNAUTHORIZED).json({
            error: OAUTH2.ERRORS.INVALID_REQUEST,
            error_description: AUTH.ERROR_MESSAGES.AUTHENTICATION_REQUIRED,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        const userScopes = authReq.token.scopes || [];
        const hasRequiredScope = requiredScopes.some(scope => userScopes.includes(scope));

        if (!hasRequiredScope) {
          this.logger.warn(MESSAGES.AUTH.INSUFFICIENT_SCOPE, {
            userId: authReq.user?._id,
            userScopes,
            requiredScopes,
            path: req.path,
          });
          
          res.status(HTTP_STATUS.FORBIDDEN).json({
            error: OAUTH2.ERRORS.INSUFFICIENT_SCOPE,
            error_description: AUTH.ERROR_MESSAGES.INSUFFICIENT_SCOPE,
            required_scopes: requiredScopes,
            user_scopes: userScopes,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        this.logger.debug('Scope authorization successful', {
          userId: authReq.user?._id,
          userScopes,
          requiredScopes,
          path: req.path,
        });

        next();

      } catch (error) {
        this.logger.error('Error in scope authorization middleware', {
          error: error instanceof Error ? error.message : 'unknown',
          requiredScopes,
          path: req.path,
          method: req.method,
        });
        
        res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
          error: OAUTH2.ERRORS.SERVER_ERROR,
          error_description: OAUTH2.ERROR_DESCRIPTIONS.SERVER_ERROR,
          timestamp: new Date().toISOString(),
        });
      }
    };
  };

  /**
   * Optional authentication middleware
   * Attaches user if token is provided and valid, but doesn't fail if not
   */
  optional = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = this.extractTokenFromHeader(req);
      
      if (!token) {
        this.logger.debug(MESSAGES.AUTH.OPTIONAL_AUTH_SKIPPED, {
          path: req.path,
          method: req.method,
        });
        next();
        return;
      }

      // Verify the access token
      const payload = await this.jwtService.verifyAccessToken(token);
      if (!payload) {
        this.logger.debug('Optional authentication failed - invalid token', {
          path: req.path,
          method: req.method,
        });
        next(); // Continue without authentication
        return;
      }

      // Get user details
      const user = await this.userRepo.findById(payload.sub);
      if (!user || !user.isActive) {
        this.logger.debug('Optional authentication failed - user not found or inactive', {
          userId: payload.sub,
          userFound: !!user,
          userActive: user?.isActive,
          path: req.path,
        });
        next(); // Continue without authentication
        return;
      }

      // Attach user and token to request
      const authReq = req as IAuthenticatedRequest;
      authReq.user = user;
      authReq.token = payload;

      this.logger.debug(MESSAGES.AUTH.OPTIONAL_AUTH_SUCCESS, {
        userId: user._id,
        username: user.username,
        path: req.path,
      });

      next();

    } catch (error) {
      this.logger.debug(MESSAGES.AUTH.OPTIONAL_AUTH_ERROR, {
        error: error instanceof Error ? error.message : 'unknown',
        path: req.path,
        method: req.method,
      });
      
      // For optional auth, continue even if there's an error
      next();
    }
  };

  /**
   * Extract Bearer token from Authorization header
   */
  private extractTokenFromHeader(req: Request): string | null {
    const authHeader = req.get(HEADERS.AUTHORIZATION);
    
    if (!authHeader) {
      return null;
    }

    const parts = authHeader.split(' ');
    if (parts.length !== AUTH.MIDDLEWARE.AUTHORIZATION_HEADER_PARTS || parts[0] !== AUTH.MIDDLEWARE.BEARER_PREFIX) {
      this.logger.debug(MESSAGES.AUTH.INVALID_AUTHORIZATION_HEADER, {
        header: authHeader.substring(0, AUTH.MIDDLEWARE.HEADER_SUBSTRING_LIMIT),
        path: req.path,
      });
      return null;
    }

    return parts[1] || null;
  }
}

// Convenience middleware creators
export const createAuthMiddleware = (
  jwtService: IJWTService,
  userRepo: IUserRepository,
  logger: ILogger
): IAuthMiddleware => {
  return new AuthMiddleware(jwtService, userRepo, logger);
};

// Export middleware instance for dependency injection
export let authMiddleware: IAuthMiddleware | null = null;

export const setAuthMiddleware = (middleware: IAuthMiddleware): void => {
  authMiddleware = middleware;
};

export const getAuthMiddleware = (): IAuthMiddleware => {
  if (!authMiddleware) {
    throw new Error('AuthMiddleware not initialized. Call setAuthMiddleware() first.');
  }
  return authMiddleware;
}; 