import mongoose, { Schema, Document, Types } from 'mongoose';
import { DATABASE } from '@/constants';

export interface IRefreshToken extends Document {
  _id: mongoose.Types.ObjectId;
  userId: Types.ObjectId;
  token: string;
  type: typeof DATABASE.TOKEN.TYPES.REFRESH;
  status: typeof DATABASE.TOKEN.STATUS[keyof typeof DATABASE.TOKEN.STATUS];
  expiresAt: Date;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    revokedAt?: Date;
    lastUsedAt?: Date;
    ipAddress?: string;
    userAgent?: string;
  };
  scopes: string[];
  
  // Instance methods
  isExpired(): boolean;
  isActive(): boolean;
  revoke(): Promise<void>;
  markAsUsed(ipAddress?: string, userAgent?: string): Promise<void>;
}

const RefreshTokenSchema = new Schema<IRefreshToken>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: DATABASE.COLLECTIONS.USERS,
    required: true,
  },
  token: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  type: {
    type: String,
    enum: Object.values(DATABASE.TOKEN.TYPES),
    default: DATABASE.TOKEN.TYPES.REFRESH,
  },
  status: {
    type: String,
    enum: Object.values(DATABASE.TOKEN.STATUS),
    default: DATABASE.TOKEN.STATUS.ACTIVE,
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 },
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
    revokedAt: {
      type: Date,
    },
    lastUsedAt: {
      type: Date,
    },
    ipAddress: {
      type: String,
    },
    userAgent: {
      type: String,
    },
  },
  scopes: [{
    type: String,
    enum: Object.values(DATABASE.USER.SCOPES),
    required: true,
  }],
}, {
  collection: DATABASE.COLLECTIONS.REFRESH_TOKENS,
  timestamps: { createdAt: 'metadata.createdAt', updatedAt: 'metadata.updatedAt' },
});

// Indexes for performance
RefreshTokenSchema.index({ userId: DATABASE.INDEXES.ASCENDING });
RefreshTokenSchema.index({ token: DATABASE.INDEXES.ASCENDING });
RefreshTokenSchema.index({ status: DATABASE.INDEXES.ASCENDING });
RefreshTokenSchema.index({ expiresAt: DATABASE.INDEXES.ASCENDING });
RefreshTokenSchema.index({ userId: DATABASE.INDEXES.ASCENDING, status: DATABASE.INDEXES.ASCENDING });

// Instance Methods
RefreshTokenSchema.methods.isExpired = function(): boolean {
  return new Date() > this.expiresAt;
};

RefreshTokenSchema.methods.isActive = function(): boolean {
  return this.status === DATABASE.TOKEN.STATUS.ACTIVE && !this.isExpired();
};

RefreshTokenSchema.methods.revoke = async function(): Promise<void> {
  this.status = DATABASE.TOKEN.STATUS.REVOKED;
  this.metadata.revokedAt = new Date();
  this.metadata.updatedAt = new Date();
  await this.save();
};

RefreshTokenSchema.methods.markAsUsed = async function(
  ipAddress?: string, 
  userAgent?: string
): Promise<void> {
  this.metadata.lastUsedAt = new Date();
  this.metadata.updatedAt = new Date();
  if (ipAddress) this.metadata.ipAddress = ipAddress;
  if (userAgent) this.metadata.userAgent = userAgent;
  await this.save();
};

// Static method to clean expired tokens
RefreshTokenSchema.statics.cleanExpiredTokens = async function(): Promise<number> {
  const result = await this.deleteMany({
    $or: [
      { expiresAt: { $lt: new Date() } },
      { status: DATABASE.TOKEN.STATUS.EXPIRED },
    ],
  });
  return result.deletedCount || 0;
};

// Pre-save middleware
RefreshTokenSchema.pre('save', function(next) {
  this.metadata.updatedAt = new Date();
  
  // Automatically mark as expired if past expiry date
  if (this.isExpired() && this.status === DATABASE.TOKEN.STATUS.ACTIVE) {
    this.status = DATABASE.TOKEN.STATUS.EXPIRED;
  }
  
  next();
});

export const RefreshToken = mongoose.model<IRefreshToken>('RefreshToken', RefreshTokenSchema); 