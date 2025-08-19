import mongoose from 'mongoose';
import logger from '@/config/logger';
import { MESSAGES, ENV_VARS } from '@/constants';

const connectMongoDB = async (): Promise<void> => {
  try {
    const mongoUri = process.env[ENV_VARS.MONGO_URI];
    
    if (!mongoUri) {
      throw new Error(`${ENV_VARS.MONGO_URI} ${MESSAGES.ERROR.ENVIRONMENT_VARIABLE_MISSING}`);
    }

    const options = {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      bufferCommands: false,
      // Removed bufferMaxEntries as it's deprecated in newer MongoDB versions
    };

    await mongoose.connect(mongoUri, options);

    logger.info(MESSAGES.SUCCESS.MONGODB_CONNECTED);

    // Handle connection events
    mongoose.connection.on('error', (error) => {
      logger.error(MESSAGES.ERROR.MONGODB_CONNECTION_ERROR, { 
        error: error.message, 
        stack: error.stack 
      });
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn(MESSAGES.WARNING.MONGODB_DISCONNECTED);
    });

    mongoose.connection.on('reconnected', () => {
      logger.info(MESSAGES.SUCCESS.MONGODB_RECONNECTED);
    });

  } catch (error) {
    logger.error(MESSAGES.ERROR.MONGODB_CONNECTION_ERROR, { 
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw error;
  }
};

const disconnectMongoDB = async (): Promise<void> => {
  try {
    await mongoose.disconnect();
    logger.info(MESSAGES.SUCCESS.MONGODB_DISCONNECTED);
  } catch (error) {
    logger.error(MESSAGES.ERROR.MONGODB_DISCONNECT_ERROR, {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw error;
  }
};

export { connectMongoDB, disconnectMongoDB }; 