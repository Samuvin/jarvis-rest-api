import { 
  IRepositoryFactory, 
  IUserRepository, 
  IChatSessionRepository, 
  IUploadRepository 
} from '@/types/repository';
import { IRefreshTokenRepository } from './RefreshTokenRepository';
import { ILogger } from '@/types/interfaces';
import { UserRepository } from './UserRepository';
import { ChatSessionRepository } from './ChatSessionRepository';
import { UploadRepository } from './UploadRepository';
import { RefreshTokenRepository } from './RefreshTokenRepository';

/**
 * Repository Factory implementing Factory Pattern
 * Creates repository instances with proper dependency injection
 * Following SOLID principles
 */
export class RepositoryFactory implements IRepositoryFactory {
  private userRepository: IUserRepository | null = null;
  private chatSessionRepository: IChatSessionRepository | null = null;
  private uploadRepository: IUploadRepository | null = null;
  private refreshTokenRepository: IRefreshTokenRepository | null = null;
  
  private logger: ILogger;

  constructor(logger: ILogger) {
    this.logger = logger;
  }

  /**
   * Get or create UserRepository instance (Singleton pattern)
   */
  getUserRepository(): IUserRepository {
    if (!this.userRepository) {
      this.userRepository = new UserRepository(this.logger);
      this.logger.debug('UserRepository instance created');
    }
    return this.userRepository;
  }

  /**
   * Get or create ChatSessionRepository instance (Singleton pattern)  
   */
  getChatSessionRepository(): IChatSessionRepository {
    if (!this.chatSessionRepository) {
      this.chatSessionRepository = new ChatSessionRepository(this.logger);
      this.logger.debug('ChatSessionRepository instance created');
    }
    return this.chatSessionRepository;
  }

  /**
   * Get or create UploadRepository instance (Singleton pattern)
   */
  getUploadRepository(): IUploadRepository {
    if (!this.uploadRepository) {
      this.uploadRepository = new UploadRepository(this.logger);
      this.logger.debug('UploadRepository instance created');
    }
    return this.uploadRepository;
  }

  /**
   * Get or create RefreshTokenRepository instance (Singleton pattern)
   */
  getRefreshTokenRepository(): IRefreshTokenRepository {
    if (!this.refreshTokenRepository) {
      this.refreshTokenRepository = new RefreshTokenRepository(this.logger);
      this.logger.debug('RefreshTokenRepository instance created');
    }
    return this.refreshTokenRepository;
  }

  /**
   * Reset factory state (useful for testing)
   */
  reset(): void {
    this.userRepository = null;
    this.chatSessionRepository = null;
    this.uploadRepository = null;
    this.refreshTokenRepository = null;
    this.logger.debug('RepositoryFactory state reset');
  }
}

// Export singleton factory instance
let repositoryFactory: RepositoryFactory | null = null;

export const createRepositoryFactory = (logger: ILogger): RepositoryFactory => {
  if (!repositoryFactory) {
    repositoryFactory = new RepositoryFactory(logger);
  }
  return repositoryFactory;
}; 