import { Request, Response, NextFunction } from 'express';
import logger from '@/config/logger';
import { 
  MESSAGES, 
  ENV_VARS, 
  HTTP_STATUS, 
  ERROR_TYPES, 
  STATUS 
} from '@/constants';

interface CustomError extends Error {
  statusCode?: number;
  status?: string;
  isOperational?: boolean;
}

const errorHandler = (
  error: CustomError,
  req: Request,
  res: Response,
  _next: NextFunction,
): void => {
  // Set default error values
  let statusCode = error.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR;
  let message = error.message || ERROR_TYPES.INTERNAL_SERVER_ERROR;
  let status = error.status || STATUS.ERROR;

  // Handle specific error types
  if (error.name === ERROR_TYPES.VALIDATION_ERROR) {
    statusCode = HTTP_STATUS.BAD_REQUEST;
    message = 'Validation Error';
    status = STATUS.FAIL;
  }

  if (error.name === ERROR_TYPES.CAST_ERROR) {
    statusCode = HTTP_STATUS.BAD_REQUEST;
    message = 'Invalid ID format';
    status = STATUS.FAIL;
  }

  if (error.name === ERROR_TYPES.JWT_ERROR) {
    statusCode = HTTP_STATUS.UNAUTHORIZED;
    message = 'Invalid token';
    status = STATUS.FAIL;
  }

  if (error.name === ERROR_TYPES.TOKEN_EXPIRED_ERROR) {
    statusCode = HTTP_STATUS.UNAUTHORIZED;
    message = 'Token expired';
    status = STATUS.FAIL;
  }

  if (error.name === ERROR_TYPES.MONGO_ERROR && (error as any).code === 11000) {
    statusCode = HTTP_STATUS.BAD_REQUEST;
    message = 'Duplicate field value';
    status = STATUS.FAIL;
  }

  // Log error for debugging (only in development or for server errors)
  if (process.env[ENV_VARS.NODE_ENV] === 'development' || statusCode >= HTTP_STATUS.INTERNAL_SERVER_ERROR) {
    logger.error(MESSAGES.ERROR.REQUEST_ERROR, {
      error: error.message,
      stack: error.stack,
      statusCode,
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      body: req.body,
      params: req.params,
      query: req.query,
    });
  } else {
    // Log client errors with less detail
    logger.warn(MESSAGES.ERROR.CLIENT_ERROR, {
      error: message,
      statusCode,
      url: req.url,
      method: req.method,
      ip: req.ip,
    });
  }

  // Send error response
  const errorResponse = {
    status,
    error: message,
    ...(process.env[ENV_VARS.NODE_ENV] === 'development' && { stack: error.stack }),
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
  };

  res.status(statusCode).json(errorResponse);
};

// Async error wrapper
const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Custom error class
class AppError extends Error {
  public statusCode: number;
  public status: string;
  public isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? STATUS.FAIL : STATUS.ERROR;
    this.isOperational = true;

    // Capture stack trace if available (Node.js specific)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export { errorHandler, asyncHandler, AppError }; 