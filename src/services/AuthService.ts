import { Types } from 'mongoose';
import { 
  IAuthService, 
  IAuthResult, 
  ILoginRequest, 
  IRegistrationRequest, 
  IPasswordValidation 
} from '@/types/auth';
import { IUser } from '@/models/User';
import { IUserRepository } from '@/types/repository';
import { IJWTService } from '@/types/auth';
import { ILogger } from '@/types/interfaces';
import { DATABASE, HTTP_STATUS } from '@/constants';
import { ITokenGenerationData } from '@/types/auth';

export class AuthService implements IAuthService {
  constructor(
    private userRepo: IUserRepository,
    private jwtService: IJWTService,
    private logger: ILogger
  ) {}

  async login(
    request: ILoginRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    try {
      this.logger.info('Login attempt started', {
        grantType: request.grant_type,
        username: request.username,
        ipAddress,
        userAgent: userAgent?.substring(0, 100),
      });

      // Handle different OAuth2 grant types
      switch (request.grant_type) {
        case DATABASE.TOKEN.GRANTS.PASSWORD:
          return await this.handlePasswordGrant(request, ipAddress, userAgent);
        
        case DATABASE.TOKEN.GRANTS.REFRESH_TOKEN:
          return await this.handleRefreshTokenGrant(request, ipAddress, userAgent);
          
        case DATABASE.TOKEN.GRANTS.CLIENT_CREDENTIALS:
          return await this.handleClientCredentialsGrant(request, ipAddress, userAgent);
          
        default:
          this.logger.warn('Unsupported grant type', { grantType: request.grant_type });
          return {
            success: false,
            error: 'unsupported_grant_type',
          };
      }
    } catch (error) {
      this.logger.error('Error during login', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        grantType: request.grant_type,
        username: request.username,
      });
      return {
        success: false,
        error: 'server_error',
      };
    }
  }

  async register(
    request: IRegistrationRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    try {
      this.logger.info('Registration attempt started', {
        email: request.email,
        username: request.username,
        ipAddress,
      });

      // Validate password strength
      const passwordValidation = this.validatePassword(request.password);
      if (!passwordValidation.isValid) {
        this.logger.warn('Registration failed: weak password', {
          email: request.email,
          errors: passwordValidation.errors,
        });
        return {
          success: false,
          error: `invalid_request: ${passwordValidation.errors.join(', ')}`,
        };
      }

      // Check if user already exists
      const existingUser = await this.userRepo.findByEmailOrUsername(request.email);
      if (existingUser) {
        this.logger.warn('Registration failed: user already exists', {
          email: request.email,
          username: request.username,
        });
        return {
          success: false,
          error: 'invalid_request: User with this email or username already exists',
        };
      }

      // Create new user
      const user = await this.userRepo.createUser({
        email: request.email,
        username: request.username,
        password: request.password,
        scopes: request.scopes || [...DATABASE.USER.DEFAULTS.SCOPES], // Convert readonly to mutable
      });

      // Update login metadata
      await user.updateLastLogin(ipAddress, userAgent);

      // Generate tokens
      const tokenData: ITokenGenerationData = {
        userId: user._id,
        scopes: user.scopes.slice(), // Convert readonly to mutable array
      };
      if (ipAddress) tokenData.ipAddress = ipAddress;
      if (userAgent) tokenData.userAgent = userAgent;

      const tokens = await this.jwtService.generateTokenPair(tokenData);

      this.logger.info('User registration successful', {
        userId: user._id,
        email: user.email,
        username: user.username,
        scopes: user.scopes,
      });

      return {
        success: true,
        user,
        tokens,
      };
    } catch (error) {
      this.logger.error('Error during registration', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        email: request.email,
        username: request.username,
      });
      return {
        success: false,
        error: 'server_error',
      };
    }
  }

  async refreshToken(
    refreshToken: string, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    try {
      this.logger.debug('Refresh token attempt', { ipAddress });

      // Verify refresh token
      const verificationResult = await this.jwtService.verifyRefreshToken(refreshToken);
      if (!verificationResult) {
        this.logger.warn('Invalid refresh token provided');
        return {
          success: false,
          error: 'invalid_grant',
        };
      }

      const { payload, refreshTokenDoc } = verificationResult;

      // Get user details
      const user = await this.userRepo.findById(payload.sub);
      if (!user || !user.isActive) {
        this.logger.warn('User not found or inactive for refresh token', {
          userId: payload.sub,
          userActive: user?.isActive,
        });
        return {
          success: false,
          error: 'invalid_grant',
        };
      }

      // Mark refresh token as used
      await refreshTokenDoc.markAsUsed(ipAddress, userAgent);

      // Generate new token pair
      const tokenData: ITokenGenerationData = {
        userId: user._id,
        scopes: user.scopes.slice(),
      };
      if (ipAddress) tokenData.ipAddress = ipAddress;
      if (userAgent) tokenData.userAgent = userAgent;

      const tokens = await this.jwtService.generateTokenPair(tokenData);

      this.logger.info('Refresh token successful', {
        userId: user._id,
        newTokenGenerated: true,
      });

      return {
        success: true,
        user,
        tokens,
      };
    } catch (error) {
      this.logger.error('Error during token refresh', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      return {
        success: false,
        error: 'server_error',
      };
    }
  }

  async revokeToken(token: string, tokenType: 'access' | 'refresh'): Promise<boolean> {
    try {
      this.logger.debug('Token revocation attempt', { tokenType });

      if (tokenType === 'refresh') {
        const success = await this.jwtService.revokeRefreshToken(token);
        this.logger.info('Token revocation result', { tokenType, success });
        return success;
      } else {
        // Access tokens are stateless - revocation would require a blacklist
        // For now, we'll just log the attempt
        this.logger.info('Access token revocation requested (stateless tokens cannot be revoked)', {
          tokenType,
        });
        return true; // Return true as the request was processed
      }
    } catch (error) {
      this.logger.error('Error during token revocation', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        tokenType,
      });
      return false;
    }
  }

  async validateCredentials(usernameOrEmail: string, password: string): Promise<IUser | null> {
    try {
      this.logger.debug('Validating user credentials', { usernameOrEmail });

      const user = await this.userRepo.findByEmailOrUsername(usernameOrEmail);
      if (!user) {
        this.logger.debug('User not found', { usernameOrEmail });
        return null;
      }

      if (!user.isActive) {
        this.logger.warn('Login attempt for inactive user', {
          userId: user._id,
          usernameOrEmail,
        });
        return null;
      }

      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        this.logger.warn('Invalid password for user', {
          userId: user._id,
          usernameOrEmail,
        });
        return null;
      }

      this.logger.debug('Credentials validated successfully', {
        userId: user._id,
        usernameOrEmail,
      });

      return user;
    } catch (error) {
      this.logger.error('Error validating credentials', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        usernameOrEmail,
      });
      return null;
    }
  }

  // Private helper methods

  private async handlePasswordGrant(
    request: ILoginRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    if (!request.username || !request.password) {
      this.logger.warn('Missing username or password in password grant');
      return {
        success: false,
        error: 'invalid_request',
      };
    }

    const user = await this.validateCredentials(request.username, request.password);
    if (!user) {
      return {
        success: false,
        error: 'invalid_grant',
      };
    }

    // Update user login metadata
    await user.updateLastLogin(ipAddress, userAgent);
    await this.userRepo.incrementUsage(user._id, 1, 0);

    // Parse requested scopes (default to user's scopes)
    const requestedScopes = request.scope ? request.scope.split(' ') : user.scopes;
    const validScopes = this.validateScopes(requestedScopes, user.scopes);

    const tokenData: ITokenGenerationData = {
      userId: user._id,
      scopes: validScopes,
    };
    if (ipAddress) tokenData.ipAddress = ipAddress;
    if (userAgent) tokenData.userAgent = userAgent;

    const tokens = await this.jwtService.generateTokenPair(tokenData);

    this.logger.info('Password grant successful', {
      userId: user._id,
      scopes: validScopes,
    });

    return {
      success: true,
      user,
      tokens,
    };
  }

  private async handleRefreshTokenGrant(
    request: ILoginRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    if (!request.refresh_token) {
      this.logger.warn('Missing refresh_token in refresh token grant');
      return {
        success: false,
        error: 'invalid_request',
      };
    }

    return await this.refreshToken(request.refresh_token, ipAddress, userAgent);
  }

  private async handleClientCredentialsGrant(
    request: ILoginRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    // For client credentials, we would typically validate client_id and client_secret
    // For this implementation, we'll create a system/service user
    this.logger.info('Client credentials grant not fully implemented');
    return {
      success: false,
      error: 'unsupported_grant_type',
    };
  }

  private validateScopes(requestedScopes: string[], userScopes: string[]): string[] {
    return requestedScopes.filter(scope => userScopes.includes(scope));
  }

  private validatePassword(password: string): IPasswordValidation {
    const errors: string[] = [];
    let score = 0;

    if (password.length < DATABASE.AUTH.PASSWORD.MIN_LENGTH) {
      errors.push(`Password must be at least ${DATABASE.AUTH.PASSWORD.MIN_LENGTH} characters long`);
    } else {
      score += 1;
    }

    if (DATABASE.AUTH.PASSWORD.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    } else {
      score += 1;
    }

    if (DATABASE.AUTH.PASSWORD.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    } else {
      score += 1;
    }

    if (DATABASE.AUTH.PASSWORD.REQUIRE_NUMBERS && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    } else {
      score += 1;
    }

    if (DATABASE.AUTH.PASSWORD.REQUIRE_SYMBOLS && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    } else {
      score += 1;
    }

    return {
      isValid: errors.length === 0,
      errors,
      score: Math.min(score, 4),
    };
  }
} 