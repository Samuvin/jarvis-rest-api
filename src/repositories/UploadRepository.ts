import { Types } from 'mongoose';
import { BaseRepository } from './BaseRepository';
import { IUploadRepository, QueryOptions } from '@/types/repository';
import { ILogger } from '@/types/interfaces';
import { Upload, IUpload } from '@/models/Upload';
import { DATABASE } from '@/constants';

export class UploadRepository extends BaseRepository<IUpload> implements IUploadRepository {
  constructor(logger: ILogger) {
    super(Upload, logger);
  }

  async findByUserId(userId: string | Types.ObjectId, options?: QueryOptions): Promise<IUpload[]> {
    try {
      this.logger.debug('Finding uploads by user ID', { userId, options });
      const uploads = await this.find({ userId } as Partial<IUpload>, {
        ...options,
        sort: options?.sort || { 'metadata.createdAt': DATABASE.INDEXES.DESCENDING },
      });
      this.logger.debug('Uploads found by user ID', { userId, count: uploads.length });
      return uploads;
    } catch (error) {
      this.logger.error('Error finding uploads by user ID', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        options,
      });
      throw error;
    }
  }

  async findByStatus(status: IUpload['status'], options?: QueryOptions): Promise<IUpload[]> {
    try {
      this.logger.debug('Finding uploads by status', { status, options });
      const uploads = await this.find({ status } as Partial<IUpload>, options);
      this.logger.debug('Uploads found by status', { status, count: uploads.length });
      return uploads;
    } catch (error) {
      this.logger.error('Error finding uploads by status', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        status,
        options,
      });
      throw error;
    }
  }

  async findByType(type: IUpload['type'], options?: QueryOptions): Promise<IUpload[]> {
    try {
      this.logger.debug('Finding uploads by type', { type, options });
      const uploads = await this.find({ type } as Partial<IUpload>, options);
      this.logger.debug('Uploads found by type', { type, count: uploads.length });
      return uploads;
    } catch (error) {
      this.logger.error('Error finding uploads by type', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        type,
        options,
      });
      throw error;
    }
  }

  async findByHash(hash: string): Promise<IUpload | null> {
    try {
      this.logger.debug('Finding upload by hash', { hash });
      const upload = await this.findOne({ 'metadata.hash': hash } as Partial<IUpload>);
      this.logger.debug('Upload found by hash', { hash, found: !!upload });
      return upload;
    } catch (error) {
      this.logger.error('Error finding upload by hash', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        hash,
      });
      throw error;
    }
  }

  async updateStatus(
    uploadId: string | Types.ObjectId,
    status: IUpload['status'],
    error?: string
  ): Promise<IUpload | null> {
    try {
      this.logger.debug('Updating upload status', { uploadId, status, error });
      
      const upload = await this.model.findById(uploadId);
      if (!upload) {
        this.logger.warn('Upload not found for status update', { uploadId });
        return null;
      }

      await upload.updateStatus(status, error);
      this.logger.info('Upload status updated', { uploadId, status });
      return upload;
    } catch (err) {
      this.logger.error('Error updating upload status', {
        error: err instanceof Error ? err.message : 'Unknown error',
        stack: err instanceof Error ? err.stack : undefined,
        uploadId,
        status,
      });
      throw err;
    }
  }

  async markAsProcessed(
    uploadId: string | Types.ObjectId,
    extractedText?: string,
    vectorized?: boolean
  ): Promise<IUpload | null> {
    try {
      this.logger.debug('Marking upload as processed', { uploadId, extractedText: !!extractedText, vectorized });
      
      const upload = await this.model.findById(uploadId);
      if (!upload) {
        this.logger.warn('Upload not found for processing completion', { uploadId });
        return null;
      }

      await upload.markAsProcessed(extractedText, vectorized);
      this.logger.info('Upload marked as processed', { uploadId, vectorized });
      return upload;
    } catch (error) {
      this.logger.error('Error marking upload as processed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        uploadId,
        extractedText: !!extractedText,
        vectorized,
      });
      throw error;
    }
  }

  async findPendingUploads(options?: QueryOptions): Promise<IUpload[]> {
    try {
      this.logger.debug('Finding pending uploads', { options });
      const uploads = await this.findByStatus(DATABASE.UPLOAD.STATUS.PENDING, options);
      this.logger.debug('Pending uploads found', { count: uploads.length });
      return uploads;
    } catch (error) {
      this.logger.error('Error finding pending uploads', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        options,
      });
      throw error;
    }
  }

  async findFailedUploads(options?: QueryOptions): Promise<IUpload[]> {
    try {
      this.logger.debug('Finding failed uploads', { options });
      const uploads = await this.findByStatus(DATABASE.UPLOAD.STATUS.FAILED, options);
      this.logger.debug('Failed uploads found', { count: uploads.length });
      return uploads;
    } catch (error) {
      this.logger.error('Error finding failed uploads', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        options,
      });
      throw error;
    }
  }

  async getUploadStats(userId: string | Types.ObjectId): Promise<{
    totalUploads: number;
    totalSize: number;
    byType: Record<string, number>;
    byStatus: Record<string, number>;
  }> {
    try {
      this.logger.debug('Getting upload stats for user', { userId });
      
      const [totalUploads, aggregateStats] = await Promise.all([
        this.count({ userId } as Partial<IUpload>),
        this.model.aggregate([
          { $match: { userId: new Types.ObjectId(userId.toString()) } },
          {
            $group: {
              _id: null,
              totalSize: { $sum: '$size' },
              byType: {
                $push: {
                  type: '$type',
                  count: 1,
                },
              },
              byStatus: {
                $push: {
                  status: '$status',
                  count: 1,
                },
              },
            },
          },
        ]),
      ]);

      // Process aggregation results
      const result = aggregateStats[0] || {};
      const byType: Record<string, number> = {};
      const byStatus: Record<string, number> = {};

      // Count by type
      (result.byType || []).forEach((item: { type: string }) => {
        byType[item.type] = (byType[item.type] || 0) + 1;
      });

      // Count by status
      (result.byStatus || []).forEach((item: { status: string }) => {
        byStatus[item.status] = (byStatus[item.status] || 0) + 1;
      });

      const stats = {
        totalUploads,
        totalSize: result.totalSize || 0,
        byType,
        byStatus,
      };

      this.logger.debug('Upload stats retrieved', { userId, stats });
      return stats;
    } catch (error) {
      this.logger.error('Error getting upload stats', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        userId,
      });
      throw error;
    }
  }
} 