import mongoose, { Schema, Document, Types } from 'mongoose';
import { DATABASE } from '@/constants';

export interface IUpload extends Document {
  _id: mongoose.Types.ObjectId;
  userId: Types.ObjectId;
  filename: string;
  originalName: string;
  mimeType: string;
  size: number;
  type: typeof DATABASE.UPLOAD.TYPES[keyof typeof DATABASE.UPLOAD.TYPES];
  status: typeof DATABASE.UPLOAD.STATUS[keyof typeof DATABASE.UPLOAD.STATUS];
  path: string;
  url?: string;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    processedAt?: Date;
    hash: string;
    dimensions?: {
      width: number;
      height: number;
    };
    duration?: number; // For audio files
    extractedText?: string; // For PDFs
    vectorized?: boolean;
  };
  processing: {
    error?: string;
    retryCount: number;
    lastRetryAt?: Date;
  };
  
  // Instance methods
  updateStatus(status: IUpload['status'], error?: string): Promise<void>;
  markAsProcessed(extractedText?: string, vectorized?: boolean): Promise<void>;
  incrementRetry(): Promise<void>;
  isProcessingExpired(): boolean;
}

const UploadSchema = new Schema<IUpload>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: DATABASE.COLLECTIONS.USERS,
    required: true,
  },
  filename: {
    type: String,
    required: true,
    trim: true,
  },
  originalName: {
    type: String,
    required: true,
    trim: true,
    maxlength: DATABASE.VALIDATION.TEXT.TITLE_MAX_LENGTH,
  },
  mimeType: {
    type: String,
    required: true,
    enum: DATABASE.VALIDATION.FILE.ALLOWED_TYPES,
  },
  size: {
    type: Number,
    required: true,
    min: 0,
    max: DATABASE.VALIDATION.FILE.MAX_SIZE,
  },
  type: {
    type: String,
    enum: Object.values(DATABASE.UPLOAD.TYPES),
    required: true,
  },
  status: {
    type: String,
    enum: Object.values(DATABASE.UPLOAD.STATUS),
    default: DATABASE.UPLOAD.STATUS.PENDING,
  },
  path: {
    type: String,
    required: true,
  },
  url: {
    type: String,
  },
  metadata: {
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
    processedAt: {
      type: Date,
    },
    hash: {
      type: String,
      required: true,
    },
    dimensions: {
      width: {
        type: Number,
        min: 0,
      },
      height: {
        type: Number,
        min: 0,
      },
    },
    duration: {
      type: Number,
      min: 0,
    },
    extractedText: {
      type: String,
      maxlength: DATABASE.VALIDATION.TEXT.MAX_LENGTH,
    },
    vectorized: {
      type: Boolean,
      default: false,
    },
  },
  processing: {
    error: {
      type: String,
    },
    retryCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastRetryAt: {
      type: Date,
    },
  },
}, {
  collection: DATABASE.COLLECTIONS.UPLOADS,
  timestamps: { createdAt: 'metadata.createdAt', updatedAt: 'metadata.updatedAt' },
});

// Indexes for performance
UploadSchema.index({ userId: DATABASE.INDEXES.ASCENDING });
UploadSchema.index({ 'metadata.createdAt': DATABASE.INDEXES.DESCENDING });
UploadSchema.index({ status: DATABASE.INDEXES.ASCENDING });
UploadSchema.index({ type: DATABASE.INDEXES.ASCENDING });
UploadSchema.index({ 'metadata.hash': DATABASE.INDEXES.ASCENDING });
UploadSchema.index({ userId: DATABASE.INDEXES.ASCENDING, status: DATABASE.INDEXES.ASCENDING });

// Instance Methods
UploadSchema.methods.updateStatus = async function(
  status: IUpload['status'], 
  error?: string
): Promise<void> {
  this.status = status;
  this.metadata.updatedAt = new Date();
  
  if (error) {
    this.processing.error = error;
  } else {
    this.processing.error = undefined;
  }
  
  if (status === DATABASE.UPLOAD.STATUS.COMPLETED) {
    this.metadata.processedAt = new Date();
  }
  
  await this.save();
};

UploadSchema.methods.markAsProcessed = async function(
  extractedText?: string, 
  vectorized?: boolean
): Promise<void> {
  this.status = DATABASE.UPLOAD.STATUS.COMPLETED;
  this.metadata.processedAt = new Date();
  this.metadata.updatedAt = new Date();
  
  if (extractedText) {
    this.metadata.extractedText = extractedText;
  }
  
  if (vectorized !== undefined) {
    this.metadata.vectorized = vectorized;
  }
  
  await this.save();
};

UploadSchema.methods.incrementRetry = async function(): Promise<void> {
  this.processing.retryCount += 1;
  this.processing.lastRetryAt = new Date();
  this.metadata.updatedAt = new Date();
  await this.save();
};

UploadSchema.methods.isProcessingExpired = function(): boolean {
  const maxRetries = 3;
  const retryDelayHours = 1;
  const retryDelayMs = retryDelayHours * 60 * 60 * 1000;
  
  if (this.processing.retryCount >= maxRetries) {
    return true;
  }
  
  if (this.processing.lastRetryAt) {
    const timeSinceLastRetry = Date.now() - this.processing.lastRetryAt.getTime();
    return timeSinceLastRetry > retryDelayMs;
  }
  
  return false;
};

// Static method to determine file type from mime type
UploadSchema.statics.getFileType = function(mimeType: string): string {
  if (mimeType.startsWith('image/')) {
    return DATABASE.UPLOAD.TYPES.IMAGE;
  } else if (mimeType.startsWith('audio/')) {
    return DATABASE.UPLOAD.TYPES.AUDIO;
  } else if (mimeType === 'application/pdf') {
    return DATABASE.UPLOAD.TYPES.DOCUMENT;
  }
  return DATABASE.UPLOAD.TYPES.DOCUMENT;
};

// Pre-save middleware
UploadSchema.pre('save', function(next) {
  this.metadata.updatedAt = new Date();
  next();
});

export const Upload = mongoose.model<IUpload>('Upload', UploadSchema); 