import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import { DATABASE } from '@/constants';

export interface IUser extends Document {
  _id: mongoose.Types.ObjectId;
  email: string;
  username: string;
  passwordHash: string;
  scopes: string[];
  isActive: boolean;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    lastLoginAt?: Date;
    ipAddress?: string;
    userAgent?: string;
  };
  preferences: {
    language: string;
    timezone: string;
    theme: typeof DATABASE.USER.THEMES.LIGHT | typeof DATABASE.USER.THEMES.DARK;
  };
  usage: {
    totalRequests: number;
    totalTokens: number;
    lastResetAt: Date;
  };
  
  // Instance methods
  comparePassword(candidatePassword: string): Promise<boolean>;
  hasScope(scope: string): boolean;
  updateLastLogin(ipAddress?: string, userAgent?: string): Promise<void>;
  resetUsage(): Promise<void>;
}

const UserSchema = new Schema<IUser>({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [DATABASE.VALIDATION.EMAIL_REGEX, 'Please enter a valid email'],
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: DATABASE.VALIDATION.USERNAME.MIN_LENGTH,
    maxlength: DATABASE.VALIDATION.USERNAME.MAX_LENGTH,
  },
  passwordHash: {
    type: String,
    required: true,
    minlength: DATABASE.VALIDATION.PASSWORD.HASH_LENGTH,
  },
  scopes: [{
    type: String,
    enum: Object.values(DATABASE.USER.SCOPES),
    required: true,
  }],
  isActive: {
    type: Boolean,
    default: true,
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
    lastLoginAt: {
      type: Date,
    },
    ipAddress: {
      type: String,
    },
    userAgent: {
      type: String,
    },
  },
  preferences: {
    language: {
      type: String,
      default: DATABASE.USER.DEFAULTS.LANGUAGE,
      enum: DATABASE.USER.LANGUAGES,
    },
    timezone: {
      type: String,
      default: DATABASE.USER.DEFAULTS.TIMEZONE,
    },
    theme: {
      type: String,
      enum: Object.values(DATABASE.USER.THEMES),
      default: DATABASE.USER.DEFAULTS.THEME,
    },
  },
  usage: {
    totalRequests: {
      type: Number,
      default: 0,
    },
    totalTokens: {
      type: Number,
      default: 0,
    },
    lastResetAt: {
      type: Date,
      default: Date.now,
    },
  },
}, {
  collection: DATABASE.COLLECTIONS.USERS,
  timestamps: { createdAt: 'metadata.createdAt', updatedAt: 'metadata.updatedAt' },
});

// Indexes for performance
UserSchema.index({ email: DATABASE.INDEXES.ASCENDING });
UserSchema.index({ username: DATABASE.INDEXES.ASCENDING });
UserSchema.index({ 'metadata.createdAt': DATABASE.INDEXES.ASCENDING });
UserSchema.index({ isActive: DATABASE.INDEXES.ASCENDING });

// Instance Methods
UserSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

UserSchema.methods.hasScope = function(scope: string): boolean {
  return this.scopes.includes(scope);
};

UserSchema.methods.updateLastLogin = async function(ipAddress?: string, userAgent?: string): Promise<void> {
  this.metadata.lastLoginAt = new Date();
  if (ipAddress) this.metadata.ipAddress = ipAddress;
  if (userAgent) this.metadata.userAgent = userAgent;
  await this.save();
};

UserSchema.methods.resetUsage = async function(): Promise<void> {
  this.usage.totalRequests = 0;
  this.usage.totalTokens = 0;
  this.usage.lastResetAt = new Date();
  await this.save();
};

// Static Methods
UserSchema.statics.hashPassword = async function(password: string): Promise<string> {
  return bcrypt.hash(password, DATABASE.VALIDATION.PASSWORD.BCRYPT_ROUNDS);
};

// Pre-save middleware
UserSchema.pre('save', function(next) {
  this.metadata.updatedAt = new Date();
  next();
});

export const User = mongoose.model<IUser>('User', UserSchema); 