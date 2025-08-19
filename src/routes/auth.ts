import { Router, Request, Response } from 'express';
import Joi from 'joi';
import { ILoginRequest, IRegistrationRequest, IOAuth2Error } from '@/types/auth';
import { serviceFactory } from '@/services/ServiceFactory';
import { asyncHandler } from '@/middleware/errorHandler';
import { userRateLimiter } from '@/middleware/rateLimiter';
import logger from '@/config/logger';
import { 
  MESSAGES, 
  HTTP_STATUS, 
  ERROR_TYPES, 
  DATABASE, 
  HEADERS 
} from '@/constants';

const router = Router();

// Get services from factory
const authService = serviceFactory.createAuthService();

// Validation schemas
const loginSchema = Joi.object({
  grant_type: Joi.string()
    .valid(...Object.values(DATABASE.TOKEN.GRANTS))
    .required(),
  username: Joi.string().when('grant_type', {
    is: DATABASE.TOKEN.GRANTS.PASSWORD,
    then: Joi.required(),
    otherwise: Joi.optional(),
  }),
  password: Joi.string().when('grant_type', {
    is: DATABASE.TOKEN.GRANTS.PASSWORD,
    then: Joi.required(),
    otherwise: Joi.optional(),
  }),
  refresh_token: Joi.string().when('grant_type', {
    is: DATABASE.TOKEN.GRANTS.REFRESH_TOKEN,
    then: Joi.required(),
    otherwise: Joi.optional(),
  }),
  client_id: Joi.string().optional(),
  client_secret: Joi.string().optional(),
  scope: Joi.string().optional(),
});

const registrationSchema = Joi.object({
  email: Joi.string().email().required(),
  username: Joi.string().min(DATABASE.VALIDATION.USERNAME.MIN_LENGTH)
    .max(DATABASE.VALIDATION.USERNAME.MAX_LENGTH).required(),
  password: Joi.string().min(DATABASE.AUTH.PASSWORD.MIN_LENGTH).required(),
  scopes: Joi.array().items(Joi.string().valid(...Object.values(DATABASE.USER.SCOPES))).optional(),
});

/**
 * POST /v1/auth/token - OAuth2 Token Endpoint
 * Supports multiple grant types: password, refresh_token, client_credentials
 */
router.post('/token', 
  userRateLimiter, 
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const ipAddress = req.ip;
    const userAgent = req.get(HEADERS.USER_AGENT);

    logger.info(MESSAGES.REQUESTS.TOKEN_GENERATION_REQUESTED, { 
      ip: ipAddress,
      userAgent: userAgent?.substring(0, 100),
      grantType: req.body?.grant_type || 'unknown',
    });

    try {
      // Validate request body
      const { error, value } = loginSchema.validate(req.body);
      if (error) {
        logger.warn('Token request validation failed', {
          error: error.details?.[0]?.message || 'Validation error',
          ip: ipAddress,
          grantType: req.body?.grant_type || 'unknown',
        });

        const oauth2Error: IOAuth2Error = {
          error: 'invalid_request',
          error_description: error.details?.[0]?.message || 'Invalid request parameters',
        };

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const loginRequest: ILoginRequest = value;

      // Process authentication request
      const authResult = await authService.login(loginRequest, ipAddress, userAgent);

      const responseTime = Date.now() - startTime;

      if (!authResult.success) {
        logger.warn('Authentication failed', {
          error: authResult.error,
          grantType: loginRequest.grant_type,
          username: loginRequest.username,
          ip: ipAddress,
          responseTime,
        });

        // Map internal errors to OAuth2 errors
        const oauth2Error: IOAuth2Error = {
          error: authResult.error === 'server_error' ? 'server_error' :
                 authResult.error === 'unsupported_grant_type' ? 'unsupported_grant_type' :
                 'invalid_grant',
          error_description: getErrorDescription(authResult.error || 'invalid_grant'),
        };

        const statusCode = oauth2Error.error === 'server_error' ? 
          HTTP_STATUS.INTERNAL_SERVER_ERROR : 
          HTTP_STATUS.BAD_REQUEST;

        res.status(statusCode).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      logger.info('Authentication successful', {
        userId: authResult.user?._id,
        grantType: loginRequest.grant_type,
        scopes: authResult.tokens?.scope,
        ip: ipAddress,
        responseTime,
      });

      // Return OAuth2 token response
      res.status(HTTP_STATUS.OK).json({
        ...authResult.tokens,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error('Internal error during token generation', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        ip: ipAddress,
        grantType: req.body?.grant_type || 'unknown',
        responseTime,
      });

      const oauth2Error: IOAuth2Error = {
        error: 'server_error',
        error_description: 'An internal server error occurred',
      };

      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        ...oauth2Error,
        timestamp: new Date().toISOString(),
      });
    }
  })
);

/**
 * POST /v1/auth/refresh - Refresh access token using refresh token
 */
router.post('/refresh',
  userRateLimiter,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const ipAddress = req.ip;
    const userAgent = req.get(HEADERS.USER_AGENT);

    logger.info(MESSAGES.REQUESTS.TOKEN_REFRESH_REQUESTED, { 
      ip: ipAddress,
      userAgent: userAgent?.substring(0, 100),
    });

    try {
      const { refresh_token } = req.body;

      if (!refresh_token) {
        logger.warn('Refresh token missing in request', { ip: ipAddress });

        const oauth2Error: IOAuth2Error = {
          error: 'invalid_request',
          error_description: 'refresh_token is required',
        };

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Process refresh token request
      const authResult = await authService.refreshToken(refresh_token, ipAddress, userAgent);

      const responseTime = Date.now() - startTime;

      if (!authResult.success) {
        logger.warn('Token refresh failed', {
          error: authResult.error,
          ip: ipAddress,
          responseTime,
        });

        const oauth2Error: IOAuth2Error = {
          error: 'invalid_grant',
          error_description: 'The provided refresh token is invalid, expired, or revoked',
        };

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      logger.info('Token refresh successful', {
        userId: authResult.user?._id,
        ip: ipAddress,
        responseTime,
      });

      // Return new token pair
      res.status(HTTP_STATUS.OK).json({
        ...authResult.tokens,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error('Internal error during token refresh', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        ip: ipAddress,
        responseTime,
      });

      const oauth2Error: IOAuth2Error = {
        error: 'server_error',
        error_description: 'An internal server error occurred',
      };

      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        ...oauth2Error,
        timestamp: new Date().toISOString(),
      });
    }
  })
);

/**
 * POST /v1/auth/revoke - Revoke an access or refresh token
 */
router.post('/revoke',
  userRateLimiter,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const ipAddress = req.ip;
    const userAgent = req.get(HEADERS.USER_AGENT);

    logger.info(MESSAGES.REQUESTS.TOKEN_REVOCATION_REQUESTED, { 
      ip: ipAddress,
      userAgent: userAgent?.substring(0, 100),
    });

    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        logger.warn('Token missing in revocation request', { ip: ipAddress });

        const oauth2Error: IOAuth2Error = {
          error: 'invalid_request',
          error_description: 'token is required',
        };

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Determine token type (default to refresh_token for safety)
      const tokenType: 'access' | 'refresh' = token_type_hint === 'access_token' ? 'access' : 'refresh';

      // Attempt to revoke the token
      const revoked = await authService.revokeToken(token, tokenType);

      const responseTime = Date.now() - startTime;

      logger.info('Token revocation processed', {
        tokenType,
        revoked,
        ip: ipAddress,
        responseTime,
      });

      // OAuth2 spec says to return 200 even if token was already revoked/invalid
      res.status(HTTP_STATUS.OK).json({
        revoked,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error('Internal error during token revocation', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        ip: ipAddress,
        responseTime,
      });

      const oauth2Error: IOAuth2Error = {
        error: 'server_error',
        error_description: 'An internal server error occurred',
      };

      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        ...oauth2Error,
        timestamp: new Date().toISOString(),
      });
    }
  })
);

/**
 * POST /v1/auth/register - User registration endpoint
 */
router.post('/register',
  userRateLimiter,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const ipAddress = req.ip;
    const userAgent = req.get(HEADERS.USER_AGENT);

    logger.info('User registration requested', { 
      ip: ipAddress,
      email: req.body.email,
      username: req.body.username,
    });

    try {
      // Validate request body
      const { error, value } = registrationSchema.validate(req.body);
      if (error) {
        logger.warn('Registration request validation failed', {
          error: error.details?.[0]?.message || 'Validation error',
          ip: ipAddress,
          email: req.body.email,
        });

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          error: 'invalid_request',
          error_description: error.details?.[0]?.message || 'Invalid request parameters',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const registrationRequest: IRegistrationRequest = value;

      // Process registration request
      const authResult = await authService.register(registrationRequest, ipAddress, userAgent);

      const responseTime = Date.now() - startTime;

      if (!authResult.success) {
        logger.warn('User registration failed', {
          error: authResult.error,
          email: registrationRequest.email,
          username: registrationRequest.username,
          ip: ipAddress,
          responseTime,
        });

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          error: 'registration_failed',
          error_description: authResult.error || 'Registration failed',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      logger.info('User registration successful', {
        userId: authResult.user?._id,
        email: authResult.user?.email,
        username: authResult.user?.username,
        ip: ipAddress,
        responseTime,
      });

      // Return user info and tokens
      res.status(HTTP_STATUS.CREATED).json({
        user: {
          id: authResult.user?._id,
          email: authResult.user?.email,
          username: authResult.user?.username,
          scopes: authResult.user?.scopes,
          createdAt: authResult.user?.metadata.createdAt,
        },
        ...authResult.tokens,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error('Internal error during registration', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        ip: ipAddress,
        email: req.body.email,
        responseTime,
      });

      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        error: 'server_error',
        error_description: 'An internal server error occurred during registration',
        timestamp: new Date().toISOString(),
      });
    }
  })
);

/**
 * Helper function to get OAuth2 error descriptions
 */
function getErrorDescription(error: string): string {
  switch (error) {
    case 'invalid_request':
      return 'The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.';
    case 'invalid_client':
      return 'Client authentication failed.';
    case 'invalid_grant':
      return 'The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI.';
    case 'unauthorized_client':
      return 'The authenticated client is not authorized to use this authorization grant type.';
    case 'unsupported_grant_type':
      return 'The authorization grant type is not supported by the authorization server.';
    case 'invalid_scope':
      return 'The requested scope is invalid, unknown, or malformed.';
    case 'server_error':
      return 'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.';
    default:
      return 'An error occurred during authentication.';
  }
}

export default router; 