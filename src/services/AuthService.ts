import { Types } from 'mongoose';
import { 
  IAuthService, 
  IAuthResult, 
  ILoginRequest, 
  IRegistrationRequest, 
  IPasswordValidation,
  ITokenGenerationData 
} from '@/types/auth';
import { IUser } from '@/models/User';
import { IUserRepository } from '@/types/repository';
import { IJWTService } from '@/types/auth';
import { ILogger } from '@/types/interfaces';
import { DATABASE, HTTP_STATUS, MESSAGES, AUTH, OAUTH2 } from '@/constants';

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
      this.logger.info(MESSAGES.AUTH.LOGIN_ATTEMPT_STARTED, {
        grantType: request.grant_type,
        username: request.username,
        ipAddress,
        userAgent,
      });

      switch (request.grant_type) {
        case DATABASE.TOKEN.GRANTS.PASSWORD:
          return await this.handlePasswordGrant(request, ipAddress, userAgent);
        
        case DATABASE.TOKEN.GRANTS.REFRESH_TOKEN:
          return await this.handleRefreshTokenGrant(request, ipAddress, userAgent);
        
        case DATABASE.TOKEN.GRANTS.CLIENT_CREDENTIALS:
          return await this.handleClientCredentialsGrant(request, ipAddress, userAgent);
        
        default:
          this.logger.warn('Unsupported grant type requested', {
            grantType: request.grant_type,
            ipAddress,
          });
          return {
            success: false,
            error: OAUTH2.ERRORS.UNSUPPORTED_GRANT_TYPE,
          };
      }
    } catch (error) {
      this.logger.error('Internal error during login', {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        grantType: request.grant_type,
        ipAddress,
      });
      return {
        success: false,
        error: OAUTH2.ERRORS.SERVER_ERROR,
      };
    }
  }

  async register(
    request: IRegistrationRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    try {
      this.logger.info(MESSAGES.AUTH.REGISTRATION_ATTEMPT_STARTED, {
        email: request.email,
        username: request.username,
        ipAddress,
      });

      // Validate password strength
      const passwordValidation = this.validatePassword(request.password);
      if (!passwordValidation.isValid) {
        this.logger.warn(MESSAGES.AUTH.WEAK_PASSWORD, {
          email: request.email,
          errors: passwordValidation.errors,
        });
        return {
          success: false,
          error: `${OAUTH2.ERRORS.INVALID_REQUEST}: ${passwordValidation.errors.join(', ')}`,
        };
      }

      // Check if user already exists
      const existingUser = await this.userRepo.findByEmailOrUsername(request.email);
      if (existingUser) {
        this.logger.warn(MESSAGES.AUTH.USER_ALREADY_EXISTS, {
          email: request.email,
          username: request.username,
        });
        return {
          success: false,
          error: `${OAUTH2.ERRORS.INVALID_REQUEST}: ${AUTH.ERROR_MESSAGES.USER_ALREADY_EXISTS}`,
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

      this.logger.info(MESSAGES.AUTH.REGISTRATION_SUCCESSFUL, {
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
      this.logger.error('Internal error during registration', {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        email: request.email,
        ipAddress,
      });
      return {
        success: false,
        error: OAUTH2.ERRORS.SERVER_ERROR,
      };
    }
  }

  async refreshToken(refreshToken: string, ipAddress?: string, userAgent?: string): Promise<IAuthResult> {
    try {
      this.logger.info(MESSAGES.AUTH.TOKEN_REFRESH_ATTEMPT, { ipAddress, userAgent });

      const refreshResult = await this.jwtService.verifyRefreshToken(refreshToken);
      if (!refreshResult) {
        this.logger.warn('Invalid refresh token provided', { ipAddress });
        return {
          success: false,
          error: OAUTH2.ERRORS.INVALID_GRANT,
        };
      }

      const user = await this.userRepo.findById(refreshResult.payload.sub);
      if (!user || !user.isActive) {
        this.logger.warn(MESSAGES.AUTH.TOKEN_VALID_USER_INACTIVE, {
          userId: refreshResult.payload.sub,
          userFound: !!user,
          userActive: user?.isActive,
        });
        return {
          success: false,
          error: OAUTH2.ERRORS.INVALID_GRANT,
        };
      }

      // Update login metadata
      await user.updateLastLogin(ipAddress, userAgent);

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
      this.logger.error('Internal error during token refresh', {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        ipAddress,
      });
      return {
        success: false,
        error: OAUTH2.ERRORS.SERVER_ERROR,
      };
    }
  }

  async revokeToken(token: string, tokenType: 'access' | 'refresh'): Promise<boolean> {
    try {
      this.logger.info(MESSAGES.AUTH.TOKEN_REVOCATION_ATTEMPT, { 
        tokenType,
      });

      if (tokenType === DATABASE.TOKEN.TYPES.REFRESH) {
        const revoked = await this.jwtService.revokeRefreshToken(token);
        this.logger.info('Refresh token revocation result', {
          tokenType,
          success: revoked,
        });
        return revoked;
      } else {
        // For access tokens, we can't revoke them as they're stateless
        // In a production system, you might maintain a blacklist
        this.logger.info('Access token revocation requested (stateless tokens cannot be revoked)', {
          tokenType,
        });
        return true; // Return true for OAuth2 compliance
      }

    } catch (error) {
      this.logger.error('Internal error during token revocation', {
        error: error instanceof Error ? error.message : 'unknown',
        stack: error instanceof Error ? error.stack : undefined,
        tokenType,
      });
      return false;
    }
  }

  async validateCredentials(usernameOrEmail: string, password: string): Promise<IUser | null> {
    try {
      const user = await this.userRepo.findByEmailOrUsername(usernameOrEmail);
      if (!user || !user.isActive) {
        this.logger.debug('User not found or inactive during credential validation', {
          identifier: usernameOrEmail,
          userFound: !!user,
          userActive: user?.isActive,
        });
        return null;
      }

      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        this.logger.warn('Invalid password during credential validation', {
          userId: user._id,
          username: user.username,
        });
        return null;
      }

      return user;
    } catch (error) {
      this.logger.error('Error validating credentials', {
        error: error instanceof Error ? error.message : 'unknown',
        identifier: usernameOrEmail,
      });
      return null;
    }
  }

  private async handlePasswordGrant(
    request: ILoginRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    if (!request.username || !request.password) {
      return {
        success: false,
        error: OAUTH2.ERRORS.INVALID_REQUEST,
      };
    }

    const user = await this.validateCredentials(request.username, request.password);
    if (!user) {
      this.logger.warn('Password grant failed: invalid credentials', {
        username: request.username,
        ipAddress,
      });
      return {
        success: false,
        error: OAUTH2.ERRORS.INVALID_GRANT,
      };
    }

    // Validate and filter requested scopes
    const requestedScopes = request.scope ? request.scope.split(' ') : user.scopes.slice();
    const validatedScopes = this.validateScopes(requestedScopes, user.scopes.slice());

    if (validatedScopes.length === 0) {
      this.logger.warn('Password grant failed: no valid scopes', {
        userId: user._id,
        requestedScopes,
        userScopes: user.scopes,
      });
      return {
        success: false,
        error: OAUTH2.ERRORS.INVALID_SCOPE,
      };
    }

    // Update login metadata
    await user.updateLastLogin(ipAddress, userAgent);

    // Generate tokens with validated scopes
    const tokenData: ITokenGenerationData = {
      userId: user._id,
      scopes: validatedScopes,
    };
    if (ipAddress) tokenData.ipAddress = ipAddress;
    if (userAgent) tokenData.userAgent = userAgent;

    const tokens = await this.jwtService.generateTokenPair(tokenData);

    this.logger.info('Password grant successful', {
      userId: user._id,
      scopes: validatedScopes,
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
      return {
        success: false,
        error: OAUTH2.ERRORS.INVALID_REQUEST,
      };
    }

    return await this.refreshToken(request.refresh_token, ipAddress, userAgent);
  }

  private async handleClientCredentialsGrant(
    request: ILoginRequest, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<IAuthResult> {
    // Client credentials grant is not fully implemented yet
    // This would typically validate client_id and client_secret
    this.logger.warn('Client credentials grant requested but not implemented', {
      clientId: request.client_id,
      ipAddress,
    });
    
    return {
      success: false,
      error: OAUTH2.ERRORS.UNSUPPORTED_GRANT_TYPE,
    };
  }

  private validateScopes(requestedScopes: string[], userScopes: string[]): string[] {
    return requestedScopes.filter(scope => userScopes.includes(scope));
  }

  private validatePassword(password: string): IPasswordValidation {
    const errors: string[] = [];
    let score = 0;

    // Check minimum length
    if (password.length < DATABASE.AUTH.PASSWORD.MIN_LENGTH) {
      errors.push(AUTH.PASSWORD_VALIDATION.TOO_SHORT);
    } else {
      score++;
    }

    // Check for uppercase letters
    if (DATABASE.AUTH.PASSWORD.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
      errors.push(AUTH.PASSWORD_VALIDATION.MISSING_UPPERCASE);
    } else if (/[A-Z]/.test(password)) {
      score++;
    }

    // Check for lowercase letters
    if (DATABASE.AUTH.PASSWORD.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
      errors.push(AUTH.PASSWORD_VALIDATION.MISSING_LOWERCASE);
    } else if (/[a-z]/.test(password)) {
      score++;
    }

    // Check for numbers
    if (DATABASE.AUTH.PASSWORD.REQUIRE_NUMBERS && !/\d/.test(password)) {
      errors.push(AUTH.PASSWORD_VALIDATION.MISSING_NUMBERS);
    } else if (/\d/.test(password)) {
      score++;
    }

    // Check for special characters
    if (DATABASE.AUTH.PASSWORD.REQUIRE_SYMBOLS && !/[^a-zA-Z0-9]/.test(password)) {
      errors.push(AUTH.PASSWORD_VALIDATION.MISSING_SYMBOLS);
    } else if (/[^a-zA-Z0-9]/.test(password)) {
      score++;
    }

    const isValid = errors.length === 0 && score >= AUTH.DEFAULTS.PASSWORD_SCORE_THRESHOLD;

    return {
      isValid,
      score,
      errors,
    };
  }
} 