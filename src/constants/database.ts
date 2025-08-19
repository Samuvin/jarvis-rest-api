// Database Configuration Constants
export const DATABASE = {
  COLLECTIONS: {
    USERS: 'users',
    CHAT_SESSIONS: 'chatsessions',
    CHAT_MESSAGES: 'chatmessages', 
    UPLOADS: 'uploads',
    REFRESH_TOKENS: 'refreshtokens',
    USAGE_LOGS: 'usagelogs',
    FEATURE_FLAGS: 'featureflags',
  },
  
  INDEXES: {
    ASCENDING: 1,
    DESCENDING: -1,
  },
  
  VALIDATION: {
    EMAIL_REGEX: /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
    PASSWORD: {
      MIN_LENGTH: 8,
      BCRYPT_ROUNDS: 12,
      HASH_LENGTH: 60,
    },
    USERNAME: {
      MIN_LENGTH: 3,
      MAX_LENGTH: 30,
    },
    TEXT: {
      MAX_LENGTH: 1000000, // 1MB text limit
      TITLE_MAX_LENGTH: 200,
    },
    FILE: {
      MAX_SIZE: 10 * 1024 * 1024, // 10MB
      ALLOWED_TYPES: ['image/jpeg', 'image/png', 'image/webp', 'application/pdf', 'audio/mpeg', 'audio/wav'],
    },
  },
  
  USER: {
    SCOPES: {
      READ: 'read',
      WRITE: 'write', 
      ADMIN: 'admin',
      CHAT: 'chat',
      UPLOAD: 'upload',
      VECTOR: 'vector',
      USER: 'user',
    },
    LANGUAGES: ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko'],
    THEMES: {
      LIGHT: 'light',
      DARK: 'dark',
    },
    DEFAULTS: {
      LANGUAGE: 'en',
      TIMEZONE: 'UTC',
      THEME: 'light',
      SCOPES: ['read', 'chat'],
    },
  },
  
  CHAT: {
    MESSAGE_TYPES: {
      USER: 'user',
      ASSISTANT: 'assistant',
      SYSTEM: 'system',
    },
    STATUS: {
      ACTIVE: 'active',
      COMPLETED: 'completed',
      FAILED: 'failed',
    },
    MODELS: {
      GPT_3_5_TURBO: 'gpt-3.5-turbo',
      GPT_4: 'gpt-4',
      CLAUDE: 'claude-3-sonnet',
      LLAMA: 'llama-2-70b',
    },
    LIMITS: {
      MAX_MESSAGES_PER_SESSION: 100,
      MAX_MESSAGE_LENGTH: 4000,
      SESSION_TIMEOUT_HOURS: 24,
    },
  },
  
  UPLOAD: {
    STATUS: {
      PENDING: 'pending',
      PROCESSING: 'processing', 
      COMPLETED: 'completed',
      FAILED: 'failed',
    },
    TYPES: {
      DOCUMENT: 'document',
      IMAGE: 'image',
      AUDIO: 'audio',
    },
  },
  
  TOKEN: {
    TYPES: {
      ACCESS: 'access',
      REFRESH: 'refresh',
    },
    EXPIRY: {
      ACCESS_TOKEN_HOURS: 1,
      REFRESH_TOKEN_DAYS: 7,
    },
    STATUS: {
      ACTIVE: 'active',
      REVOKED: 'revoked',
      EXPIRED: 'expired',
    },
    GRANTS: {
      CLIENT_CREDENTIALS: 'client_credentials',
      PASSWORD: 'password',
      REFRESH_TOKEN: 'refresh_token',
      AUTHORIZATION_CODE: 'authorization_code',
    },
  },
  
  USAGE: {
    RESET_INTERVALS: {
      DAILY: 'daily',
      WEEKLY: 'weekly', 
      MONTHLY: 'monthly',
    },
    METRICS: {
      REQUESTS: 'requests',
      TOKENS: 'tokens',
      UPLOADS: 'uploads',
      VECTOR_QUERIES: 'vector_queries',
    },
  },
  
  PAGINATION: {
    DEFAULT_LIMIT: 20,
    MAX_LIMIT: 100,
    DEFAULT_SKIP: 0,
  },

  AUTH: {
    PASSWORD: {
      MIN_LENGTH: 8,
      REQUIRE_UPPERCASE: true,
      REQUIRE_LOWERCASE: true,
      REQUIRE_NUMBERS: true,
      REQUIRE_SYMBOLS: true,
    },
    LOGIN: {
      MAX_ATTEMPTS: 5,
      LOCKOUT_DURATION_MINUTES: 15,
    },
    JWT: {
      ALGORITHM: 'HS256',
      ISSUER: 'jarvis-api',
      AUDIENCE: 'jarvis-client',
    },
  },
} as const; 