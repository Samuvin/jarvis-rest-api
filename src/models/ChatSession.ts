import mongoose, { Schema, Document, Types } from 'mongoose';
import { DATABASE } from '@/constants';

export interface IChatMessage {
  id: string;
  type: typeof DATABASE.CHAT.MESSAGE_TYPES[keyof typeof DATABASE.CHAT.MESSAGE_TYPES];
  content: string;
  timestamp: Date;
  metadata?: {
    model?: string;
    tokens?: number;
    processingTime?: number;
    error?: string;
  };
}

export interface IChatSession extends Document {
  _id: mongoose.Types.ObjectId;
  userId: Types.ObjectId;
  title: string;
  status: typeof DATABASE.CHAT.STATUS[keyof typeof DATABASE.CHAT.STATUS];
  model: string;
  messages: IChatMessage[];
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    lastMessageAt: Date;
    totalTokens: number;
    messageCount: number;
  };
  settings: {
    temperature: number;
    maxTokens: number;
    systemPrompt?: string;
  };
  
  // Instance methods
  addMessage(type: IChatMessage['type'], content: string, metadata?: IChatMessage['metadata']): void;
  updateStatus(status: IChatSession['status']): Promise<void>;
  isExpired(): boolean;
  canAddMessage(): boolean;
}

const MessageSchema = new Schema<IChatMessage>({
  id: {
    type: String,
    required: true,
    default: () => new mongoose.Types.ObjectId().toString(),
  },
  type: {
    type: String,
    enum: Object.values(DATABASE.CHAT.MESSAGE_TYPES),
    required: true,
  },
  content: {
    type: String,
    required: true,
    maxlength: DATABASE.CHAT.LIMITS.MAX_MESSAGE_LENGTH,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  metadata: {
    model: {
      type: String,
      enum: Object.values(DATABASE.CHAT.MODELS),
    },
    tokens: {
      type: Number,
      min: 0,
    },
    processingTime: {
      type: Number,
      min: 0,
    },
    error: {
      type: String,
    },
  },
}, { _id: false });

const ChatSessionSchema = new Schema<IChatSession>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: DATABASE.COLLECTIONS.USERS,
    required: true,
  },
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: DATABASE.VALIDATION.TITLE_MAX_LENGTH,
  },
  status: {
    type: String,
    enum: Object.values(DATABASE.CHAT.STATUS),
    default: DATABASE.CHAT.STATUS.ACTIVE,
  },
  model: {
    type: String,
    enum: Object.values(DATABASE.CHAT.MODELS),
    default: DATABASE.CHAT.MODELS.GPT_3_5_TURBO,
  },
  messages: {
    type: [MessageSchema],
    default: [],
    validate: {
      validator: function(messages: IChatMessage[]) {
        return messages.length <= DATABASE.CHAT.LIMITS.MAX_MESSAGES_PER_SESSION;
      },
      message: `Cannot exceed ${DATABASE.CHAT.LIMITS.MAX_MESSAGES_PER_SESSION} messages per session`,
    },
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
    lastMessageAt: {
      type: Date,
      default: Date.now,
    },
    totalTokens: {
      type: Number,
      default: 0,
      min: 0,
    },
    messageCount: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  settings: {
    temperature: {
      type: Number,
      default: 0.7,
      min: 0,
      max: 2,
    },
    maxTokens: {
      type: Number,
      default: 2048,
      min: 1,
      max: 4096,
    },
    systemPrompt: {
      type: String,
      maxlength: DATABASE.CHAT.LIMITS.MAX_MESSAGE_LENGTH,
    },
  },
}, {
  collection: DATABASE.COLLECTIONS.CHAT_SESSIONS,
  timestamps: { createdAt: 'metadata.createdAt', updatedAt: 'metadata.updatedAt' },
});

// Indexes for performance
ChatSessionSchema.index({ userId: DATABASE.INDEXES.ASCENDING });
ChatSessionSchema.index({ 'metadata.createdAt': DATABASE.INDEXES.DESCENDING });
ChatSessionSchema.index({ 'metadata.lastMessageAt': DATABASE.INDEXES.DESCENDING });
ChatSessionSchema.index({ status: DATABASE.INDEXES.ASCENDING });
ChatSessionSchema.index({ userId: DATABASE.INDEXES.ASCENDING, status: DATABASE.INDEXES.ASCENDING });

// Instance Methods
ChatSessionSchema.methods.addMessage = function(
  type: IChatMessage['type'], 
  content: string, 
  metadata?: IChatMessage['metadata']
): void {
  if (!this.canAddMessage()) {
    throw new Error(`Cannot add more messages. Maximum ${DATABASE.CHAT.LIMITS.MAX_MESSAGES_PER_SESSION} messages per session.`);
  }
  
  const message: IChatMessage = {
    id: new mongoose.Types.ObjectId().toString(),
    type,
    content,
    timestamp: new Date(),
    metadata,
  };
  
  this.messages.push(message);
  this.metadata.messageCount = this.messages.length;
  this.metadata.lastMessageAt = new Date();
  this.metadata.updatedAt = new Date();
  
  if (metadata?.tokens) {
    this.metadata.totalTokens += metadata.tokens;
  }
};

ChatSessionSchema.methods.updateStatus = async function(status: IChatSession['status']): Promise<void> {
  this.status = status;
  this.metadata.updatedAt = new Date();
  await this.save();
};

ChatSessionSchema.methods.isExpired = function(): boolean {
  const expiryTime = DATABASE.CHAT.LIMITS.SESSION_TIMEOUT_HOURS * 60 * 60 * 1000; // Convert hours to milliseconds
  const timeSinceLastMessage = Date.now() - this.metadata.lastMessageAt.getTime();
  return timeSinceLastMessage > expiryTime;
};

ChatSessionSchema.methods.canAddMessage = function(): boolean {
  return this.messages.length < DATABASE.CHAT.LIMITS.MAX_MESSAGES_PER_SESSION;
};

// Pre-save middleware
ChatSessionSchema.pre('save', function(next) {
  this.metadata.updatedAt = new Date();
  next();
});

export const ChatSession = mongoose.model<IChatSession>('ChatSession', ChatSessionSchema); 