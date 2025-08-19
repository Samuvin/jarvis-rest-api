import { Types } from 'mongoose';
import { BaseRepository } from './BaseRepository';
import { IUserRepository, QueryOptions } from '@/types/repository';
import { ILogger } from '@/types/interfaces';
import { User, IUser } from '@/models/User';
import { DATABASE } from '@/constants';

export class UserRepository extends BaseRepository<IUser> implements IUserRepository {
  constructor(logger: ILogger) {
    super(User, logger);
  }

  async findByEmail(email: string): Promise<IUser | null> {
    try {
      this.logger.debug('Finding user by email', { email });
      const user = await this.model.findOne({ email: email.toLowerCase() });
      this.logger.debug('User found by email', { email, found: !!user });
      return user;
    } catch (error) {
      this.logger.error('Error finding user by email', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        email,
      });
      throw error;
    }
  }

  async findByUsername(username: string): Promise<IUser | null> {
    try {
      this.logger.debug('Finding user by username', { username });
      const user = await this.model.findOne({ username });
      this.logger.debug('User found by username', { username, found: !!user });
      return user;
    } catch (error) {
      this.logger.error('Error finding user by username', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        username,
      });
      throw error;
    }
  }

  async findByEmailOrUsername(emailOrUsername: string): Promise<IUser | null> {
    try {
      this.logger.debug('Finding user by email or username', { emailOrUsername });
      const user = await this.model.findOne({
        $or: [
          { email: emailOrUsername.toLowerCase() },
          { username: emailOrUsername },
        ],
      });
      this.logger.debug('User found by email or username', { emailOrUsername, found: !!user });
      return user;
    } catch (error) {
      this.logger.error('Error finding user by email or username', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        emailOrUsername,
      });
      throw error;
    }
  }

  async findActiveUsers(options?: QueryOptions): Promise<IUser[]> {
    try {
      this.logger.debug('Finding active users', { options });
      const users = await this.find({ isActive: true } as Partial<IUser>, options);
      this.logger.debug('Active users found', { count: users.length, options });
      return users;
    } catch (error) {
      this.logger.error('Error finding active users', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        options,
      });
      throw error;
    }
  }

  async updateLastLogin(
    userId: string | Types.ObjectId, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<void> {
    try {
      this.logger.debug('Updating user last login', { userId, ipAddress, userAgent });
      const updateData: any = {
        'metadata.lastLoginAt': new Date(),
        'metadata.updatedAt': new Date(),
      };

      if (ipAddress) updateData['metadata.ipAddress'] = ipAddress;
      if (userAgent) updateData['metadata.userAgent'] = userAgent;

      await this.model.findByIdAndUpdate(userId, updateData);
      this.logger.info('User last login updated', { userId });
    } catch (error) {
      this.logger.error('Error updating user last login', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        ipAddress,
        userAgent,
      });
      throw error;
    }
  }

  async resetUsage(userId: string | Types.ObjectId): Promise<void> {
    try {
      this.logger.debug('Resetting user usage', { userId });
      await this.model.findByIdAndUpdate(userId, {
        'usage.totalRequests': 0,
        'usage.totalTokens': 0,
        'usage.lastResetAt': new Date(),
        'metadata.updatedAt': new Date(),
      });
      this.logger.info('User usage reset', { userId });
    } catch (error) {
      this.logger.error('Error resetting user usage', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
      });
      throw error;
    }
  }

  async deactivateUser(userId: string | Types.ObjectId): Promise<boolean> {
    try {
      this.logger.debug('Deactivating user', { userId });
      const result = await this.model.findByIdAndUpdate(userId, {
        isActive: false,
        'metadata.updatedAt': new Date(),
      });
      const deactivated = !!result;
      this.logger.info('User deactivation result', { userId, deactivated });
      return deactivated;
    } catch (error) {
      this.logger.error('Error deactivating user', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
      });
      throw error;
    }
  }

  async updatePreferences(
    userId: string | Types.ObjectId, 
    preferences: Partial<IUser['preferences']>
  ): Promise<IUser | null> {
    try {
      this.logger.debug('Updating user preferences', { userId, preferences });
      
      const updateData: any = {
        'metadata.updatedAt': new Date(),
      };
      
      // Update specific preference fields
      Object.keys(preferences).forEach(key => {
        if (preferences[key as keyof IUser['preferences']] !== undefined) {
          updateData[`preferences.${key}`] = preferences[key as keyof IUser['preferences']];
        }
      });

      const user = await this.model.findByIdAndUpdate(userId, updateData, { new: true });
      this.logger.info('User preferences updated', { userId, updated: !!user });
      return user;
    } catch (error) {
      this.logger.error('Error updating user preferences', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        preferences,
      });
      throw error;
    }
  }

  async incrementUsage(
    userId: string | Types.ObjectId, 
    requests: number, 
    tokens: number
  ): Promise<void> {
    try {
      this.logger.debug('Incrementing user usage', { userId, requests, tokens });
      await this.model.findByIdAndUpdate(userId, {
        $inc: {
          'usage.totalRequests': requests,
          'usage.totalTokens': tokens,
        },
        'metadata.updatedAt': new Date(),
      });
      this.logger.debug('User usage incremented', { userId, requests, tokens });
    } catch (error) {
      this.logger.error('Error incrementing user usage', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        requests,
        tokens,
      });
      throw error;
    }
  }

  /**
   * Create user with hashed password
   */
  async createUser(userData: {
    email: string;
    username: string;
    password: string;
    scopes?: string[];
  }): Promise<IUser> {
    try {
      this.logger.debug('Creating user with hashed password', { 
        email: userData.email, 
        username: userData.username 
      });
      
      const passwordHash = await User.hashPassword(userData.password);
      
      const user = await this.create({
        email: userData.email,
        username: userData.username,
        passwordHash,
        scopes: userData.scopes || DATABASE.USER.DEFAULTS.SCOPES,
      } as Partial<IUser>);
      
      this.logger.info('User created successfully', { 
        id: user._id, 
        email: user.email, 
        username: user.username 
      });
      
      return user;
    } catch (error) {
      this.logger.error('Error creating user', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        email: userData.email,
        username: userData.username,
      });
      throw error;
    }
  }
} 