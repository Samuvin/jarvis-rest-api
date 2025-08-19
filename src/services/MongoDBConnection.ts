import mongoose from 'mongoose';
import { IDatabaseConnection, ILogger, IConfig } from '@/types/interfaces';
import { MESSAGES } from '@/constants';

export class MongoDBConnection implements IDatabaseConnection {
  private connected = false;
  
  constructor(
    private config: IConfig,
    private logger: ILogger
  ) {}

  async connect(): Promise<void> {
    try {
      const options = {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        bufferCommands: false,
      };

      await mongoose.connect(this.config.database.mongoUri, options);
      this.connected = true;
      this.logger.info(MESSAGES.SUCCESS.MONGODB_CONNECTED);

      this.setupEventListeners();
    } catch (error) {
      this.logger.error(MESSAGES.ERROR.MONGODB_CONNECTION_ERROR, { 
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.connected) {
        await mongoose.disconnect();
        this.connected = false;
        this.logger.info(MESSAGES.SUCCESS.MONGODB_DISCONNECTED);
      }
    } catch (error) {
      this.logger.error(MESSAGES.ERROR.MONGODB_DISCONNECT_ERROR, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  isConnected(): boolean {
    return this.connected && mongoose.connection.readyState === 1;
  }

  private setupEventListeners(): void {
    mongoose.connection.on('error', (error) => {
      this.connected = false;
      this.logger.error(MESSAGES.ERROR.MONGODB_CONNECTION_ERROR, { 
        error: error.message, 
        stack: error.stack 
      });
    });

    mongoose.connection.on('disconnected', () => {
      this.connected = false;
      this.logger.warn(MESSAGES.WARNING.MONGODB_DISCONNECTED);
    });

    mongoose.connection.on('reconnected', () => {
      this.connected = true;
      this.logger.info(MESSAGES.SUCCESS.MONGODB_RECONNECTED);
    });
  }
} 