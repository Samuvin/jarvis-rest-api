import { Types } from 'mongoose';
import { Request } from 'express';
import { IUser } from '@/models/User';
import { IRefreshToken } from '@/models/RefreshToken';

// JWT Token Payload Interface
export interface IJWTPayload {
  sub: string; // User ID
  iat: number; // Issued at
  exp: number; // Expires at
  iss: string; // Issuer
  aud: string; // Audience
  scopes: string[];
  type: 'access' | 'refresh';
  jti?: string; // JWT ID
}

// Token Response Interface
export interface ITokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

// Token Generation Data
export interface ITokenGenerationData {
  userId: Types.ObjectId;
  scopes: string[];
  expiresInHours?: number;
  ipAddress?: string;
  userAgent?: string;
}

// Login Request Interface
export interface ILoginRequest {
  grant_type: 'password' | 'client_credentials' | 'refresh_token' | 'authorization_code';
  username?: string;
  password?: string;
  refresh_token?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

// Registration Request Interface
export interface IRegistrationRequest {
  email: string;
  username: string;
  password: string;
  scopes?: string[];
}

// Authentication Result
export interface IAuthResult {
  success: boolean;
  user?: IUser;
  error?: string;
  tokens?: ITokenResponse;
}

// JWT Service Interface
export interface IJWTService {
  generateAccessToken(data: ITokenGenerationData): Promise<string>;
  generateRefreshToken(data: ITokenGenerationData): Promise<{ token: string; refreshTokenDoc: IRefreshToken }>;
  generateTokenPair(data: ITokenGenerationData): Promise<ITokenResponse>;
  verifyAccessToken(token: string): Promise<IJWTPayload | null>;
  verifyRefreshToken(token: string): Promise<{ payload: IJWTPayload; refreshTokenDoc: IRefreshToken } | null>;
  revokeRefreshToken(token: string): Promise<boolean>;
  revokeAllUserTokens(userId: string | Types.ObjectId): Promise<number>;
}

// Authentication Service Interface
export interface IAuthService {
  login(request: ILoginRequest, ipAddress?: string, userAgent?: string): Promise<IAuthResult>;
  register(request: IRegistrationRequest, ipAddress?: string, userAgent?: string): Promise<IAuthResult>;
  refreshToken(refreshToken: string, ipAddress?: string, userAgent?: string): Promise<IAuthResult>;
  revokeToken(token: string, tokenType: 'access' | 'refresh'): Promise<boolean>;
  validateCredentials(usernameOrEmail: string, password: string): Promise<IUser | null>;
}

// Authentication Middleware User
export interface IAuthenticatedRequest extends Request {
  user?: IUser;
  token?: IJWTPayload;
}

// Password Validation Result
export interface IPasswordValidation {
  isValid: boolean;
  errors: string[];
  score: number; // 0-4 strength score
}

// OAuth2 Error Response
export interface IOAuth2Error {
  error: 'invalid_request' | 'invalid_client' | 'invalid_grant' | 'unauthorized_client' | 'unsupported_grant_type' | 'invalid_scope' | 'server_error';
  error_description?: string;
  error_uri?: string;
}

// Rate Limiting for Authentication
export interface IAuthRateLimit {
  maxAttempts: number;
  windowMs: number;
  lockoutDuration: number;
} 