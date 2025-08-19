import { Model, Document, Types } from 'mongoose';
import { IBaseRepository, QueryOptions } from '@/types/repository';
import { ILogger } from '@/types/interfaces';
import { DATABASE } from '@/constants';

export abstract class BaseRepository<T extends Document> implements IBaseRepository<T> {
  protected model: Model<T>;
  protected logger: ILogger;

  constructor(model: Model<T>, logger: ILogger) {
    this.model = model;
    this.logger = logger;
  }

  async create(data: Partial<T>): Promise<T> {
    try {
      this.logger.debug(`Creating ${this.model.modelName}`, { data });
      const document = new this.model(data);
      const result = await document.save();
      this.logger.info(`${this.model.modelName} created successfully`, { id: result._id });
      return result;
    } catch (error) {
      this.logger.error(`Error creating ${this.model.modelName}`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        data,
      });
      throw error;
    }
  }

  async findById(id: string | Types.ObjectId): Promise<T | null> {
    try {
      this.logger.debug(`Finding ${this.model.modelName} by ID`, { id });
      const result = await this.model.findById(id);
      this.logger.debug(`${this.model.modelName} found by ID`, { id, found: !!result });
      return result;
    } catch (error) {
      this.logger.error(`Error finding ${this.model.modelName} by ID`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        id,
      });
      throw error;
    }
  }

  async findOne(filter: Partial<T>): Promise<T | null> {
    try {
      this.logger.debug(`Finding one ${this.model.modelName}`, { filter });
      const result = await this.model.findOne(filter as any);
      this.logger.debug(`${this.model.modelName} findOne result`, { filter, found: !!result });
      return result;
    } catch (error) {
      this.logger.error(`Error finding one ${this.model.modelName}`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        filter,
      });
      throw error;
    }
  }

  async find(filter: Partial<T>, options?: QueryOptions): Promise<T[]> {
    try {
      this.logger.debug(`Finding ${this.model.modelName} documents`, { filter, options });
      
      let query = this.model.find(filter as any);
      
      if (options) {
        if (options.limit) {
          query = query.limit(Math.min(options.limit, DATABASE.PAGINATION.MAX_LIMIT));
        }
        if (options.skip) {
          query = query.skip(Math.max(options.skip, DATABASE.PAGINATION.DEFAULT_SKIP));
        }
        if (options.sort) {
          query = query.sort(options.sort);
        }
        if (options.select) {
          query = query.select(options.select);
        }
        if (options.populate) {
          query = query.populate(options.populate);
        }
      }
      
      const results = await query.exec();
      this.logger.debug(`Found ${results.length} ${this.model.modelName} documents`, { 
        filter, 
        options, 
        count: results.length 
      });
      return results;
    } catch (error) {
      this.logger.error(`Error finding ${this.model.modelName} documents`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        filter,
        options,
      });
      throw error;
    }
  }

  async updateById(id: string | Types.ObjectId, data: Partial<T>): Promise<T | null> {
    try {
      this.logger.debug(`Updating ${this.model.modelName} by ID`, { id, data });
      const result = await this.model.findByIdAndUpdate(id, data as any, { new: true });
      this.logger.info(`${this.model.modelName} updated`, { id, updated: !!result });
      return result;
    } catch (error) {
      this.logger.error(`Error updating ${this.model.modelName}`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        id,
        data,
      });
      throw error;
    }
  }

  async deleteById(id: string | Types.ObjectId): Promise<boolean> {
    try {
      this.logger.debug(`Deleting ${this.model.modelName} by ID`, { id });
      const result = await this.model.findByIdAndDelete(id);
      const deleted = !!result;
      this.logger.info(`${this.model.modelName} deletion result`, { id, deleted });
      return deleted;
    } catch (error) {
      this.logger.error(`Error deleting ${this.model.modelName}`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        id,
      });
      throw error;
    }
  }

  async count(filter: Partial<T>): Promise<number> {
    try {
      this.logger.debug(`Counting ${this.model.modelName} documents`, { filter });
      const count = await this.model.countDocuments(filter as any);
      this.logger.debug(`Counted ${count} ${this.model.modelName} documents`, { filter, count });
      return count;
    } catch (error) {
      this.logger.error(`Error counting ${this.model.modelName} documents`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        filter,
      });
      throw error;
    }
  }

  /**
   * Helper method for pagination
   */
  protected async paginate(
    filter: Partial<T>,
    page: number = 1,
    limit: number = DATABASE.PAGINATION.DEFAULT_LIMIT,
    options?: QueryOptions
  ): Promise<{
    data: T[];
    total: number;
    page: number;
    limit: number;
    pages: number;
    hasNext: boolean;
    hasPrev: boolean;
  }> {
    const safeLimit = Math.min(limit, DATABASE.PAGINATION.MAX_LIMIT);
    const skip = (page - 1) * safeLimit;
    
    const [data, total] = await Promise.all([
      this.find(filter, { ...options, limit: safeLimit, skip }),
      this.count(filter),
    ]);
    
    const pages = Math.ceil(total / safeLimit);
    
    return {
      data,
      total,
      page,
      limit: safeLimit,
      pages,
      hasNext: page < pages,
      hasPrev: page > 1,
    };
  }
} 