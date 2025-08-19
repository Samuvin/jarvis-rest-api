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
  HEADERS,
  OAUTH2,
  AUTH,
  DEFAULTS
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
      userAgent: userAgent?.substring(0, AUTH.MIDDLEWARE.USER_AGENT_SUBSTRING_LIMIT),
      grantType: req.body?.grant_type || 'unknown',
    });

    try {
      // Validate request body
      const { error, value } = loginSchema.validate(req.body);
      if (error) {
        logger.warn(MESSAGES.AUTH.TOKEN_REQUEST_VALIDATION_FAILED, {
          error: error.details?.[0]?.message || AUTH.ERROR_MESSAGES.VALIDATION_ERROR,
          ip: ipAddress,
          grantType: req.body?.grant_type || 'unknown',
        });

        const oauth2Error: IOAuth2Error = {
          error: OAUTH2.ERRORS.INVALID_REQUEST,
          error_description: error.details?.[0]?.message || AUTH.ERROR_MESSAGES.INVALID_REQUEST_PARAMETERS,
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
        logger.warn(MESSAGES.AUTH.LOGIN_FAILED, {
          error: authResult.error,
          grantType: loginRequest.grant_type,
          username: loginRequest.username,
          ip: ipAddress,
          responseTime,
        });

        // Map internal errors to OAuth2 errors
        const oauth2Error: IOAuth2Error = {
          error: authResult.error === OAUTH2.ERRORS.SERVER_ERROR ? OAUTH2.ERRORS.SERVER_ERROR :
                 authResult.error === OAUTH2.ERRORS.UNSUPPORTED_GRANT_TYPE ? OAUTH2.ERRORS.UNSUPPORTED_GRANT_TYPE :
                 OAUTH2.ERRORS.INVALID_GRANT,
          error_description: getErrorDescription(authResult.error || OAUTH2.ERRORS.INVALID_GRANT),
        };

        const statusCode = oauth2Error.error === OAUTH2.ERRORS.SERVER_ERROR ? 
          HTTP_STATUS.INTERNAL_SERVER_ERROR : 
          HTTP_STATUS.BAD_REQUEST;

        res.status(statusCode).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      logger.info(MESSAGES.AUTH.LOGIN_SUCCESSFUL, {
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
      logger.error(ERROR_TYPES.INTERNAL_SERVER_ERROR, {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        grantType: req.body?.grant_type || 'unknown',
        ip: ipAddress,
        responseTime,
      });

      const oauth2Error: IOAuth2Error = {
        error: OAUTH2.ERRORS.SERVER_ERROR,
        error_description: OAUTH2.ERROR_DESCRIPTIONS.SERVER_ERROR,
      };

      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        ...oauth2Error,
        timestamp: new Date().toISOString(),
      });
    }
  })
);

/**
 * POST /v1/auth/refresh - OAuth2 Token Refresh Endpoint
 */
router.post('/refresh',
  userRateLimiter,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const ipAddress = req.ip;
    const userAgent = req.get(HEADERS.USER_AGENT);

    logger.info(MESSAGES.REQUESTS.TOKEN_REFRESH_REQUESTED, { 
      ip: ipAddress,
      userAgent: userAgent?.substring(0, AUTH.MIDDLEWARE.USER_AGENT_SUBSTRING_LIMIT),
    });

    try {
      const refreshRequest: ILoginRequest = {
        grant_type: DATABASE.TOKEN.GRANTS.REFRESH_TOKEN,
        refresh_token: req.body.refresh_token,
      };

      const authResult = await authService.login(refreshRequest, ipAddress, userAgent);
      const responseTime = Date.now() - startTime;

      if (!authResult.success) {
        logger.warn(MESSAGES.AUTH.TOKEN_REQUEST_VALIDATION_FAILED, {
          error: authResult.error,
          ip: ipAddress,
          responseTime,
        });

        const oauth2Error: IOAuth2Error = {
          error: OAUTH2.ERRORS.INVALID_GRANT,
          error_description: AUTH.ERROR_MESSAGES.REFRESH_TOKEN_INVALID,
        };

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      logger.info(MESSAGES.AUTH.TOKEN_REFRESHED, {
        userId: authResult.user?._id,
        ip: ipAddress,
        responseTime,
      });

      res.status(HTTP_STATUS.OK).json({
        ...authResult.tokens,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error(ERROR_TYPES.INTERNAL_SERVER_ERROR, {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        ip: ipAddress,
        responseTime,
      });

      const oauth2Error: IOAuth2Error = {
        error: OAUTH2.ERRORS.SERVER_ERROR,
        error_description: OAUTH2.ERROR_DESCRIPTIONS.SERVER_ERROR,
      };

      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        ...oauth2Error,
        timestamp: new Date().toISOString(),
      });
    }
  })
);

/**
 * POST /v1/auth/revoke - OAuth2 Token Revocation Endpoint
 */
router.post('/revoke',
  userRateLimiter,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const ipAddress = req.ip;
    const userAgent = req.get(HEADERS.USER_AGENT);

    logger.info(MESSAGES.REQUESTS.TOKEN_REVOCATION_REQUESTED, { 
      ip: ipAddress,
      userAgent: userAgent?.substring(0, AUTH.MIDDLEWARE.USER_AGENT_SUBSTRING_LIMIT),
      tokenType: req.body.token_type_hint,
    });

    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        const oauth2Error: IOAuth2Error = {
          error: OAUTH2.ERRORS.INVALID_REQUEST,
          error_description: OAUTH2.ERROR_DESCRIPTIONS.INVALID_REQUEST,
        };

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          ...oauth2Error,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Default to refresh token if no hint provided
      const tokenType = token_type_hint || DATABASE.TOKEN.TYPES.REFRESH;
      const revocationResult = await authService.revokeToken(token, tokenType);

      const responseTime = Date.now() - startTime;

      logger.info(MESSAGES.AUTH.TOKEN_REVOKED, {
        revoked: revocationResult,
        tokenType,
        ip: ipAddress,
        responseTime,
      });

      // OAuth2 revocation always returns 200, even for invalid tokens (security)
      res.status(HTTP_STATUS.OK).json({
        revoked: revocationResult,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error(ERROR_TYPES.INTERNAL_SERVER_ERROR, {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        ip: ipAddress,
        responseTime,
      });

      // Even on server error, return 200 for security (don't leak information)
      res.status(HTTP_STATUS.OK).json({
        revoked: false,
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

    logger.info(MESSAGES.REQUESTS.USER_REGISTRATION_REQUESTED, { 
      ip: ipAddress,
      email: req.body.email,
      username: req.body.username,
    });

    try {
      // Validate request body
      const { error, value } = registrationSchema.validate(req.body);
      if (error) {
        logger.warn(MESSAGES.AUTH.REGISTRATION_REQUEST_VALIDATION_FAILED, {
          error: error.details?.[0]?.message || AUTH.ERROR_MESSAGES.VALIDATION_ERROR,
          ip: ipAddress,
          email: req.body.email,
        });

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          error: OAUTH2.ERRORS.INVALID_REQUEST,
          error_description: error.details?.[0]?.message || AUTH.ERROR_MESSAGES.INVALID_REQUEST_PARAMETERS,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const registrationRequest: IRegistrationRequest = value;

      // Process registration request
      const authResult = await authService.register(registrationRequest, ipAddress, userAgent);

      const responseTime = Date.now() - startTime;

      if (!authResult.success) {
        logger.warn(MESSAGES.AUTH.USER_ALREADY_EXISTS, {
          error: authResult.error,
          email: registrationRequest.email,
          username: registrationRequest.username,
          ip: ipAddress,
          responseTime,
        });

        res.status(HTTP_STATUS.BAD_REQUEST).json({
          error: AUTH.ERROR_TYPES.REGISTRATION_FAILED,
          error_description: authResult.error || AUTH.ERROR_MESSAGES.VALIDATION_ERROR,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      logger.info(MESSAGES.AUTH.REGISTRATION_SUCCESSFUL, {
        userId: authResult.user?._id,
        email: authResult.user?.email,
        username: authResult.user?.username,
        scopes: authResult.user?.scopes,
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
          createdAt: authResult.user?.metadata?.createdAt,
        },
        ...authResult.tokens,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error(ERROR_TYPES.INTERNAL_SERVER_ERROR, {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        email: req.body.email,
        ip: ipAddress,
        responseTime,
      });

      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        error: OAUTH2.ERRORS.SERVER_ERROR,
        error_description: OAUTH2.ERROR_DESCRIPTIONS.SERVER_ERROR,
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
    case OAUTH2.ERRORS.INVALID_REQUEST:
      return OAUTH2.ERROR_DESCRIPTIONS.INVALID_REQUEST;
    case OAUTH2.ERRORS.INVALID_CLIENT:
      return OAUTH2.ERROR_DESCRIPTIONS.INVALID_CLIENT;
    case OAUTH2.ERRORS.INVALID_GRANT:
      return OAUTH2.ERROR_DESCRIPTIONS.INVALID_GRANT;
    case OAUTH2.ERRORS.UNAUTHORIZED_CLIENT:
      return OAUTH2.ERROR_DESCRIPTIONS.UNAUTHORIZED_CLIENT;
    case OAUTH2.ERRORS.UNSUPPORTED_GRANT_TYPE:
      return OAUTH2.ERROR_DESCRIPTIONS.UNSUPPORTED_GRANT_TYPE;
    case OAUTH2.ERRORS.INVALID_SCOPE:
      return OAUTH2.ERROR_DESCRIPTIONS.INVALID_SCOPE;
    case OAUTH2.ERRORS.SERVER_ERROR:
      return OAUTH2.ERROR_DESCRIPTIONS.SERVER_ERROR;
    default:
      return OAUTH2.ERROR_DESCRIPTIONS.DEFAULT;
  }
}

export default router; 