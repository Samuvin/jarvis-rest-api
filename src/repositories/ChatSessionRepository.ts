import { Types } from 'mongoose';
import { BaseRepository } from './BaseRepository';
import { IChatSessionRepository, QueryOptions } from '@/types/repository';
import { ILogger } from '@/types/interfaces';
import { ChatSession, IChatSession } from '@/models/ChatSession';
import { DATABASE } from '@/constants';

export class ChatSessionRepository extends BaseRepository<IChatSession> implements IChatSessionRepository {
  constructor(logger: ILogger) {
    super(ChatSession, logger);
  }

  async findByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IChatSession[]> {
    try {
      this.logger.debug('Finding chat sessions by user ID', { userId, options });
      const sessions = await this.find({ userId } as Partial<IChatSession>, {
        ...options,
        sort: options?.sort || { 'metadata.lastMessageAt': DATABASE.INDEXES.DESCENDING },
      });
      this.logger.debug('Chat sessions found by user ID', { userId, count: sessions.length });
      return sessions;
    } catch (error) {
      this.logger.error('Error finding chat sessions by user ID', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        options,
      });
      throw error;
    }
  }

  async findActiveSessionsByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IChatSession[]> {
    try {
      this.logger.debug('Finding active chat sessions by user ID', { userId, options });
      const sessions = await this.find(
        { userId, status: DATABASE.CHAT.STATUS.ACTIVE } as Partial<IChatSession>,
        {
          ...options,
          sort: options?.sort || { 'metadata.lastMessageAt': DATABASE.INDEXES.DESCENDING },
        }
      );
      this.logger.debug('Active chat sessions found by user ID', { userId, count: sessions.length });
      return sessions;
    } catch (error) {
      this.logger.error('Error finding active chat sessions by user ID', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        options,
      });
      throw error;
    }
  }

  async addMessageToSession(
    sessionId: string | Types.ObjectId,
    message: IChatSession['messages'][0]
  ): Promise<IChatSession | null> {
    try {
      this.logger.debug('Adding message to chat session', { sessionId, messageType: message.type });
      
      const session = await this.model.findById(sessionId);
      if (!session) {
        this.logger.warn('Chat session not found for adding message', { sessionId });
        return null;
      }

      session.addMessage(message.type, message.content, message.metadata);
      await session.save();
      
      this.logger.info('Message added to chat session', { 
        sessionId, 
        messageType: message.type,
        totalMessages: session.messages.length 
      });
      return session;
    } catch (error) {
      this.logger.error('Error adding message to chat session', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        sessionId,
        message,
      });
      throw error;
    }
  }

  async updateSessionStatus(
    sessionId: string | Types.ObjectId,
    status: IChatSession['status']
  ): Promise<IChatSession | null> {
    try {
      this.logger.debug('Updating chat session status', { sessionId, status });
      const session = await this.model.findById(sessionId);
      if (!session) {
        this.logger.warn('Chat session not found for status update', { sessionId });
        return null;
      }

      await session.updateStatus(status);
      this.logger.info('Chat session status updated', { sessionId, status });
      return session;
    } catch (error) {
      this.logger.error('Error updating chat session status', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        sessionId,
        status,
      });
      throw error;
    }
  }

  async findExpiredSessions(): Promise<IChatSession[]> {
    try {
      this.logger.debug('Finding expired chat sessions');
      const expiryTime = DATABASE.CHAT.LIMITS.SESSION_TIMEOUT_HOURS * 60 * 60 * 1000;
      const expiryDate = new Date(Date.now() - expiryTime);
      
      const sessions = await this.model.find({
        status: DATABASE.CHAT.STATUS.ACTIVE,
        'metadata.lastMessageAt': { $lt: expiryDate },
      });
      
      this.logger.debug('Expired chat sessions found', { count: sessions.length });
      return sessions;
    } catch (error) {
      this.logger.error('Error finding expired chat sessions', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async getSessionStats(userId: string | Types.ObjectId): Promise<{
    totalSessions: number;
    activeSessions: number;
    totalMessages: number;
    totalTokens: number;
  }> {
    try {
      this.logger.debug('Getting chat session stats for user', { userId });
      
      const [totalSessions, activeSessions, aggregateStats] = await Promise.all([
        this.count({ userId } as Partial<IChatSession>),
        this.count({ userId, status: DATABASE.CHAT.STATUS.ACTIVE } as Partial<IChatSession>),
        this.model.aggregate([
          { $match: { userId: new Types.ObjectId(userId.toString()) } },
          {
            $group: {
              _id: null,
              totalMessages: { $sum: '$metadata.messageCount' },
              totalTokens: { $sum: '$metadata.totalTokens' },
            },
          },
        ]),
      ]);

      const stats = {
        totalSessions,
        activeSessions,
        totalMessages: aggregateStats[0]?.totalMessages || 0,
        totalTokens: aggregateStats[0]?.totalTokens || 0,
      };

      this.logger.debug('Chat session stats retrieved', { userId, stats });
      return stats;
    } catch (error) {
      this.logger.error('Error getting chat session stats', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
      });
      throw error;
    }
  }
} 