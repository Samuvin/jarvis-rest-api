// API Response Messages
export const MESSAGES = {
  // Success Messages
  SUCCESS: {
    MONGODB_CONNECTED: 'Connected to MongoDB successfully',
    MONGODB_RECONNECTED: 'MongoDB reconnected',
    MONGODB_DISCONNECTED: 'Disconnected from MongoDB',
    REDIS_CONNECTED: 'Connected to Redis successfully',
    REDIS_CONNECTING: 'Connecting to Redis...',
    REDIS_DISCONNECTED: 'Disconnected from Redis',
    SERVER_STARTED: 'Jarvis API server started successfully',
    SERVER_STARTING: 'Starting Jarvis API server...',
  },

  // Warning Messages
  WARNING: {
    MONGODB_DISCONNECTED: 'MongoDB disconnected',
    REDIS_CONNECTION_ENDED: 'Redis connection ended',
    REDIS_NOT_READY: 'Redis not ready',
    ROUTE_NOT_FOUND: 'Route not found',
    RATE_LIMIT_EXCEEDED: 'Rate limit exceeded',
    JWT_SECRET_NOT_PROVIDED: 'JWT_SECRET not provided, using default (not recommended for production)',
  },

  // Error Messages
  ERROR: {
    MONGODB_CONNECTION_ERROR: 'MongoDB connection error',
    MONGODB_DISCONNECT_ERROR: 'Error disconnecting from MongoDB',
    REDIS_CLIENT_ERROR: 'Redis client error',
    REDIS_CONNECTION_ERROR: 'Failed to connect to Redis',
    REDIS_DISCONNECT_ERROR: 'Error disconnecting from Redis',
    REDIS_NOT_INITIALIZED: 'Redis client not initialized. Call connectRedis() first.',
    SERVER_START_ERROR: 'Failed to start server',
    SERVER_STARTUP_ERROR: 'Unhandled error during server startup',
    RATE_LIMITER_ERROR: 'Rate limiter error - failing open',
    RATE_LIMITER_MIDDLEWARE_ERROR: 'Rate limiter middleware error - failing open',
    REQUEST_ERROR: 'Request error occurred',
    CLIENT_ERROR: 'Client error occurred',
    UNCAUGHT_EXCEPTION: 'Uncaught exception',
    UNHANDLED_REJECTION: 'Unhandled promise rejection',
    MONGODB_STATUS_CHECK_ERROR: 'Error checking MongoDB status',
    REDIS_STATUS_CHECK_ERROR: 'Error checking Redis status',
    ENVIRONMENT_VARIABLE_MISSING: 'Environment variable is not defined',
  },

  // Info Messages
  INFO: {
    GRACEFUL_SHUTDOWN_SIGTERM: 'SIGTERM received, shutting down gracefully',
    GRACEFUL_SHUTDOWN_SIGINT: 'SIGINT received, shutting down gracefully',
    HEALTH_CHECK_PERFORMED: 'Health check performed',
    READINESS_PROBE_CHECK: 'Readiness probe check',
    LIVENESS_PROBE_CHECK: 'Liveness probe check',
    RATE_LIMIT_CHECK_PASSED: 'Rate limit check passed',
  },

  // Authentication Messages
  AUTH: {
    // Success messages
    LOGIN_SUCCESSFUL: 'Authentication successful',
    REGISTRATION_SUCCESSFUL: 'User registration successful',
    LOGOUT_SUCCESSFUL: 'User logged out successfully',
    TOKEN_REFRESHED: 'Token refreshed successfully',
    TOKEN_REVOKED: 'Token revoked successfully',
    PASSWORD_UPDATED: 'Password updated successfully',
    
    // Request logging
    LOGIN_ATTEMPT_STARTED: 'Login attempt started',
    REGISTRATION_ATTEMPT_STARTED: 'Registration attempt started',
    TOKEN_REFRESH_ATTEMPT: 'Token refresh attempt',
    TOKEN_REVOCATION_ATTEMPT: 'Token revocation attempt',
    LOGOUT_REQUESTED: 'User logout requested',
    
    // Warning messages
    WEAK_PASSWORD: 'Registration failed: weak password',
    USER_ALREADY_EXISTS: 'Registration failed: user already exists',
    LOGIN_FAILED: 'Login attempt failed',
    TOKEN_REQUEST_VALIDATION_FAILED: 'Token request validation failed',
    REGISTRATION_REQUEST_VALIDATION_FAILED: 'Registration request validation failed',
    AUTHENTICATION_REQUIRED: 'Authentication required but no token provided',
    INVALID_ACCESS_TOKEN: 'Invalid or expired access token',
    TOKEN_VALID_USER_INACTIVE: 'Token valid but user not found or inactive',
    INSUFFICIENT_SCOPE: 'Token lacks required scope for this operation',
    INVALID_AUTHORIZATION_HEADER: 'Invalid authorization header format',
    
    // Optional auth messages
    OPTIONAL_AUTH_SUCCESS: 'Optional authentication successful',
    OPTIONAL_AUTH_SKIPPED: 'Optional authentication skipped - no token provided',
    OPTIONAL_AUTH_ERROR: 'Error in optional authentication - continuing without auth',
    
    // Cleanup and maintenance
    TOKEN_CLEANUP_STARTED: 'Starting expired token cleanup',
    TOKEN_CLEANUP_COMPLETED: 'Expired token cleanup completed',
  },

  // Request Logging
  REQUESTS: {
    TOKEN_GENERATION_REQUESTED: 'Token generation requested',
    TOKEN_REFRESH_REQUESTED: 'Token refresh requested',
    TOKEN_REVOCATION_REQUESTED: 'Token revocation requested',
    CHAT_REQUEST_RECEIVED: 'Chat request received',
    CHAT_HISTORY_REQUESTED: 'Chat history requested',
    CHAT_SESSION_END_REQUESTED: 'Chat session end requested',
    CHAT_HISTORY_DELETION_REQUESTED: 'Chat history deletion requested',
    FILE_UPLOAD_REQUESTED: 'File upload requested',
    FILE_DOWNLOAD_REQUESTED: 'File download requested',
    FILE_DELETION_REQUESTED: 'File deletion requested',
    VECTOR_QUERY_REQUESTED: 'Vector query requested',
    VECTOR_BATCH_INSERT_REQUESTED: 'Vector batch insert requested',
    VECTOR_DELETION_REQUESTED: 'Vector deletion requested',
    USER_INFO_REQUESTED: 'User info requested',
    FEATURE_FLAGS_REQUESTED: 'Feature flags requested',
    USAGE_METRICS_REQUESTED: 'Usage metrics requested',
    ADMIN_USERS_LIST_REQUESTED: 'Admin users list requested',
    ADMIN_FEATURE_FLAG_CREATION_REQUESTED: 'Admin feature flag creation requested',
    ADMIN_METRICS_REQUESTED: 'Admin metrics requested',
    USER_REGISTRATION_REQUESTED: 'User registration requested',
  },
};

// API Response Status
export const STATUS = {
  HEALTHY: 'healthy' as const,
  DEGRADED: 'degraded' as const,
  UNHEALTHY: 'unhealthy' as const,
  READY: 'ready' as const,
  NOT_READY: 'not ready' as const,
  ALIVE: 'alive' as const,
  CONNECTED: 'connected' as const,
  DISCONNECTED: 'disconnected' as const,
  ERROR: 'error' as const,
  NOT_CONFIGURED: 'not_configured' as const,
  SUCCESS: 'success' as const,
  FAIL: 'fail' as const,
};

// HTTP Status Codes
export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
} as const;

// Error Types
export const ERROR_TYPES = {
  VALIDATION_ERROR: 'ValidationError',
  CAST_ERROR: 'CastError',
  JWT_ERROR: 'JsonWebTokenError',
  TOKEN_EXPIRED_ERROR: 'TokenExpiredError',
  MONGO_ERROR: 'MongoError',
  TOO_MANY_REQUESTS: 'Too Many Requests',
  NOT_FOUND: 'Not Found',
  INTERNAL_SERVER_ERROR: 'Internal Server Error',
  NOT_IMPLEMENTED: 'Not Implemented',
} as const;

// Environment Variables
export const ENV_VARS = {
  NODE_ENV: 'NODE_ENV',
  PORT: 'PORT',
  MONGO_URI: 'MONGO_URI',
  REDIS_URL: 'REDIS_URL',
  UPSTASH_REDIS_REST_URL: 'UPSTASH_REDIS_REST_URL',
  UPSTASH_REDIS_REST_TOKEN: 'UPSTASH_REDIS_REST_TOKEN',
  UPSTASH_VECTOR_URL: 'UPSTASH_VECTOR_URL',
  UPSTASH_VECTOR_TOKEN: 'UPSTASH_VECTOR_TOKEN',
  UPSTASH_VECTOR_REST_URL: 'UPSTASH_VECTOR_REST_URL',
  UPSTASH_VECTOR_REST_TOKEN: 'UPSTASH_VECTOR_REST_TOKEN',
  HUGGING_FACE_API_KEY: 'HUGGING_FACE_API_KEY',
  JWT_SECRET: 'JWT_SECRET',
  JWT_EXPIRES_IN: 'JWT_EXPIRES_IN',
  JWT_REFRESH_EXPIRES_IN: 'JWT_REFRESH_EXPIRES_IN',
  LOG_LEVEL: 'LOG_LEVEL',
  LOG_TO_CONSOLE: 'LOG_TO_CONSOLE',
  LOG_TO_FILE: 'LOG_TO_FILE',
  RATE_LIMIT_WINDOW_MS: 'RATE_LIMIT_WINDOW_MS',
  RATE_LIMIT_MAX_REQUESTS: 'RATE_LIMIT_MAX_REQUESTS',
  RATE_LIMIT_MAX_REQUESTS_PER_USER: 'RATE_LIMIT_MAX_REQUESTS_PER_USER',
  ALLOWED_ORIGINS: 'ALLOWED_ORIGINS',
} as const;

// Default Values
export const DEFAULTS = {
  PORT: 3000,
  NODE_ENV: 'development',
  LOG_LEVEL: 'info',
  LOG_LEVEL_DEV: 'debug',
  RATE_LIMIT_WINDOW_MS: 900000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 100,
  RATE_LIMIT_MAX_REQUESTS_PER_USER: 50,
  JWT_EXPIRES_IN: '1h',
  JWT_REFRESH_EXPIRES_IN: '7d',
  MAX_FILE_SIZE: 10485760, // 10MB
  VERSION: '1.0.0',
  UNKNOWN_IP: 'unknown',
  REDIS_CLEANUP_BUFFER: 60, // seconds
} as const;

// Rate Limiting
export const RATE_LIMIT = {
  REDIS_KEY_PREFIX: 'rate_limit',
  TOKENS_PER_SECOND_DIVISOR: 1000,
  RETRY_AFTER_DIVISOR: 1000,
  TOKEN_BUCKET_REFILL_MULTIPLIER: 1000,
} as const;

// Redis Keys
export const REDIS_KEYS = {
  RATE_LIMIT_PREFIX: 'rate_limit',
  FEATURE_FLAGS_PREFIX: 'feature_flags',
  SESSION_PREFIX: 'session',
  USER_PREFIX: 'user',
} as const;

// MongoDB Connection States
export const MONGO_STATES = {
  DISCONNECTED: 0,
  CONNECTED: 1,
  CONNECTING: 2,
  DISCONNECTING: 3,
} as const;

// Not Implemented Messages for Placeholder Routes
export const NOT_IMPLEMENTED = {
  AUTH_ENDPOINTS: 'Authentication endpoints will be implemented in Task 3',
  CHAT_ENDPOINTS: 'Chat endpoints will be implemented in Task 4',
  UPLOAD_ENDPOINTS: 'Upload endpoints will be implemented in Task 5',
  VECTOR_ENDPOINTS: 'Vector endpoints will be implemented in Task 5',
  USER_ENDPOINTS: 'User endpoints will be implemented in Task 6',
  FEATURE_FLAG_ENDPOINTS: 'Feature flag endpoints will be implemented in Task 6',
  USAGE_ENDPOINTS: 'Usage endpoints will be implemented in Task 7',
  ADMIN_ENDPOINTS: 'Admin endpoints will be implemented in Task 8',
} as const;

// Regex Patterns
export const PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
} as const;

// File Upload
export const FILE_UPLOAD = {
  MAX_SIZE: 10485760, // 10MB
  ALLOWED_TYPES: {
    PDF: 'application/pdf',
    JPEG: 'image/jpeg',
    PNG: 'image/png',
    WEBP: 'image/webp',
    MP3: 'audio/mpeg',
    WAV: 'audio/wav',
    MP4: 'audio/mp4',
  },
  UPLOAD_DIR: './uploads',
} as const;

// API Versions
export const API = {
  VERSION: 'v1',
  BASE_PATH: '/v1',
} as const;

// Headers
export const HEADERS = {
  RATE_LIMIT_LIMIT: 'X-RateLimit-Limit',
  RATE_LIMIT_REMAINING: 'X-RateLimit-Remaining',
  RATE_LIMIT_RESET: 'X-RateLimit-Reset',
  RESPONSE_TIME: 'X-Response-Time',
  AUTHORIZATION: 'Authorization',
  USER_AGENT: 'User-Agent',
  CONTENT_TYPE: 'Content-Type',
} as const;

// Export database constants
export { DATABASE } from './database'; 

// OAuth2 and Authentication Constants
export const OAUTH2 = {
  // OAuth2 Error Types (RFC 6749)
  ERRORS: {
    INVALID_REQUEST: 'invalid_request',
    INVALID_CLIENT: 'invalid_client', 
    INVALID_GRANT: 'invalid_grant',
    UNAUTHORIZED_CLIENT: 'unauthorized_client',
    UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type',
    INVALID_SCOPE: 'invalid_scope',
    SERVER_ERROR: 'server_error',
    TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',
    // Additional token errors
    INVALID_TOKEN: 'invalid_token',
    EXPIRED_TOKEN: 'expired_token',
    INSUFFICIENT_SCOPE: 'insufficient_scope',
  },
  
  // OAuth2 Error Descriptions (RFC 6749)
  ERROR_DESCRIPTIONS: {
    INVALID_REQUEST: 'The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.',
    INVALID_CLIENT: 'Client authentication failed.',
    INVALID_GRANT: 'The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI.',
    UNAUTHORIZED_CLIENT: 'The authenticated client is not authorized to use this authorization grant type.',
    UNSUPPORTED_GRANT_TYPE: 'The authorization grant type is not supported by the authorization server.',
    INVALID_SCOPE: 'The requested scope is invalid, unknown, or malformed.',
    SERVER_ERROR: 'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
    TEMPORARILY_UNAVAILABLE: 'The authorization server is currently unable to handle the request due to temporary overloading or maintenance.',
    INVALID_TOKEN: 'The access token provided is expired, revoked, malformed, or invalid.',
    EXPIRED_TOKEN: 'The access token provided has expired.',
    INSUFFICIENT_SCOPE: 'The request requires higher privileges than provided by the access token.',
    DEFAULT: 'An error occurred during authentication.',
  },
  
  // Token Type
  TOKEN_TYPE: 'Bearer',
  
  // Grant Types (already in DATABASE.TOKEN.GRANTS but duplicated for clarity)
  GRANT_TYPES: {
    CLIENT_CREDENTIALS: 'client_credentials',
    PASSWORD: 'password', 
    REFRESH_TOKEN: 'refresh_token',
    AUTHORIZATION_CODE: 'authorization_code',
  },
} as const;

// Authentication Constants
export const AUTH = {
  // Error Types for Internal Use
  ERROR_TYPES: {
    REGISTRATION_FAILED: 'registration_failed',
    LOGIN_FAILED: 'login_failed',
    TOKEN_GENERATION_FAILED: 'token_generation_failed',
    TOKEN_REFRESH_FAILED: 'token_refresh_failed',
    TOKEN_REVOCATION_FAILED: 'token_revocation_failed',
    USER_NOT_FOUND: 'user_not_found',
    USER_INACTIVE: 'user_inactive',
    WEAK_PASSWORD: 'weak_password',
    USER_ALREADY_EXISTS: 'user_already_exists',
    INVALID_CREDENTIALS: 'invalid_credentials',
    SCOPE_VALIDATION_FAILED: 'scope_validation_failed',
  },
  
  // Authentication Error Messages
  ERROR_MESSAGES: {
    AUTHENTICATION_REQUIRED: 'Authentication required. Please provide a valid access token.',
    INVALID_OR_EXPIRED_TOKEN: 'The access token provided is expired, revoked, malformed, or invalid.',
    USER_INACTIVE: 'The user associated with this token is no longer active.',
    INSUFFICIENT_SCOPE: 'Your token does not have the required permissions for this operation.',
    INVALID_CREDENTIALS: 'Invalid username or password.',
    USER_ALREADY_EXISTS: 'User with this email or username already exists',
    WEAK_PASSWORD: 'Password does not meet security requirements',
    INVALID_TOKEN_FORMAT: 'Invalid token format. Expected format: Bearer <token>',
    TOKEN_EXPIRED: 'Your session has expired. Please log in again.',
    REFRESH_TOKEN_INVALID: 'The provided refresh token is invalid, expired, or revoked',
    INVALID_REQUEST_PARAMETERS: 'Invalid request parameters',
    VALIDATION_ERROR: 'Validation error',
  },
  
  // Password Validation Messages
  PASSWORD_VALIDATION: {
    TOO_SHORT: 'Password must be at least 8 characters long',
    MISSING_UPPERCASE: 'Password must contain at least one uppercase letter',
    MISSING_LOWERCASE: 'Password must contain at least one lowercase letter', 
    MISSING_NUMBERS: 'Password must contain at least one number',
    MISSING_SYMBOLS: 'Password must contain at least one special character',
    COMMON_PASSWORD: 'Password is too common, please choose a stronger password',
  },
  
  // Default Values
  DEFAULTS: {
    JWT_SECRET_FALLBACK: 'fallback-jwt-secret-change-in-production',
    PASSWORD_SCORE_THRESHOLD: 2,
    TOKEN_CLEANUP_BATCH_SIZE: 1000,
  },
  
  // Middleware Constants
  MIDDLEWARE: {
    BEARER_PREFIX: 'Bearer',
    AUTHORIZATION_HEADER_PARTS: 2,
    HEADER_SUBSTRING_LIMIT: 50,
    USER_AGENT_SUBSTRING_LIMIT: 100,
  },
} as const; 