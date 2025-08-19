import { Request, Response, NextFunction } from 'express';
import { IJWTService, IAuthenticatedRequest } from '@/types/auth';
import { IUserRepository } from '@/types/repository';
import { ILogger } from '@/types/interfaces';
import { HTTP_STATUS, ERROR_TYPES, HEADERS } from '@/constants';

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
        this.logger.warn('Authentication required but no token provided', {
          path: req.path,
          method: req.method,
          ip: req.ip,
        });
        
        res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: 'invalid_request',
          error_description: 'Authentication required. Please provide a valid access token.',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Verify the access token
      const payload = await this.jwtService.verifyAccessToken(token);
      if (!payload) {
        this.logger.warn('Invalid or expired access token', {
          path: req.path,
          method: req.method,
          ip: req.ip,
        });
        
        res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: 'invalid_token',
          error_description: 'The access token provided is expired, revoked, malformed, or invalid.',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Get user details and verify user is still active
      const user = await this.userRepo.findById(payload.sub);
      if (!user || !user.isActive) {
        this.logger.warn('Token valid but user not found or inactive', {
          userId: payload.sub,
          userFound: !!user,
          userActive: user?.isActive,
          path: req.path,
        });
        
        res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: 'invalid_token',
          error_description: 'The user associated with this token is no longer active.',
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
        scopes: payload.scopes,
        path: req.path,
        method: req.method,
      });

      next();
    } catch (error) {
      this.logger.error('Error in authentication middleware', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        path: req.path,
        method: req.method,
        ip: req.ip,
      });
      
      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        error: 'server_error',
        error_description: 'An internal server error occurred during authentication.',
        timestamp: new Date().toISOString(),
      });
    }
  };

  /**
   * Scope-based authorization middleware factory
   * Creates middleware that requires specific scopes
   */
  requireScope = (scopes: string | string[]) => {
    const requiredScopes = Array.isArray(scopes) ? scopes : [scopes];
    
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const authReq = req as IAuthenticatedRequest;
        
        // Must be authenticated first
        if (!authReq.user || !authReq.token) {
          this.logger.warn('Scope check failed: not authenticated', {
            path: req.path,
            method: req.method,
            requiredScopes,
          });
          
          res.status(HTTP_STATUS.UNAUTHORIZED).json({
            error: 'invalid_request',
            error_description: 'Authentication required before scope validation.',
            timestamp: new Date().toISOString(),
          });
          return;
        }

        // Check if user has required scopes
        const userScopes = authReq.token.scopes;
        const hasRequiredScopes = requiredScopes.every(scope => userScopes.includes(scope));
        
        if (!hasRequiredScopes) {
          this.logger.warn('Insufficient scopes for request', {
            userId: authReq.user._id,
            userScopes,
            requiredScopes,
            path: req.path,
            method: req.method,
          });
          
          res.status(HTTP_STATUS.FORBIDDEN).json({
            error: 'insufficient_scope',
            error_description: `This request requires the following scopes: ${requiredScopes.join(', ')}`,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        this.logger.debug('Scope authorization successful', {
          userId: authReq.user._id,
          requiredScopes,
          userScopes,
          path: req.path,
        });

        next();
      } catch (error) {
        this.logger.error('Error in scope authorization middleware', {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined,
          requiredScopes,
          path: req.path,
          method: req.method,
        });
        
        res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
          error: 'server_error',
          error_description: 'An internal server error occurred during authorization.',
          timestamp: new Date().toISOString(),
        });
      }
    };
  };

  /**
   * Optional authentication middleware
   * Attaches user to request if valid token is provided, but doesn't require it
   */
  optional = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = this.extractTokenFromHeader(req);
      
      if (!token) {
        // No token provided - continue without authentication
        next();
        return;
      }

      // Try to verify the token
      const payload = await this.jwtService.verifyAccessToken(token);
      if (!payload) {
        // Invalid token - continue without authentication
        this.logger.debug('Optional auth: invalid token provided, continuing without authentication', {
          path: req.path,
          ip: req.ip,
        });
        next();
        return;
      }

      // Get user details
      const user = await this.userRepo.findById(payload.sub);
      if (user && user.isActive) {
        // Attach user and token to request
        const authReq = req as IAuthenticatedRequest;
        authReq.user = user;
        authReq.token = payload;
        
        this.logger.debug('Optional authentication successful', {
          userId: user._id,
          scopes: payload.scopes,
          path: req.path,
        });
      }

      next();
    } catch (error) {
      this.logger.debug('Error in optional authentication - continuing without auth', {
        error: error instanceof Error ? error.message : 'Unknown error',
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
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      this.logger.debug('Invalid authorization header format', {
        header: authHeader.substring(0, 50),
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
    throw new Error('Auth middleware not initialized. Call setAuthMiddleware first.');
  }
  return authMiddleware;
}; 