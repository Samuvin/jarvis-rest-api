# Jarvis API

A ChatGPT-style API with Hugging Face LLMs, RAG capabilities, and cell-based architecture built with Node.js, TypeScript, and Express.

## 🚀 Features

- **Modern Tech Stack**: Node.js + TypeScript + Express
- **Production-Ready Logging**: Winston with structured logging
- **Database Integration**: MongoDB for persistence, Redis for caching
- **Rate Limiting**: IP-based and user-based token bucket implementation
- **Vector Database**: Upstash Vector for RAG (Retrieval-Augmented Generation)
- **Authentication**: JWT + OAuth2 token-based authentication
- **File Upload Support**: PDF, audio, and image processing
- **Health Monitoring**: Comprehensive health checks and metrics
- **Docker Support**: Multi-stage builds with security best practices
- **Cell-Based Architecture**: Scalable deployment strategy

## 📋 API Endpoints

### Health & Status
- `GET /v1/status` - System health check
- `GET /v1/status/ready` - Readiness probe (Kubernetes)
- `GET /v1/status/live` - Liveness probe (Kubernetes)

### Authentication (Coming in Task 3)
- `POST /v1/auth/token` - Generate access token
- `POST /v1/auth/refresh` - Refresh access token
- `POST /v1/auth/revoke` - Revoke access token

### Chat & LLM (Coming in Task 4)
- `POST /v1/chat` - Send query to LLM
- `GET /v1/chat/:sessionId/history` - Get conversation history
- `POST /v1/chat/:sessionId/end` - End chat session
- `DELETE /v1/chat/:sessionId/history` - Delete session history

### File Upload & Vector (Coming in Task 5)
- `POST /v1/upload` - Upload files (PDF/audio/image)
- `GET /v1/upload/:fileId` - Download file
- `DELETE /v1/upload/:fileId` - Delete file
- `POST /v1/vector/query` - Query vector database
- `POST /v1/vector/batch` - Batch insert embeddings
- `DELETE /v1/vector/:vectorId` - Delete embedding

### User & Features (Coming in Task 6)
- `GET /v1/users/me` - Get user info and feature flags
- `GET /v1/features` - Get feature flags

### Usage & Admin (Coming in Tasks 7-8)
- `GET /v1/usage` - Get usage metrics
- `GET /v1/admin/users` - Admin: List users
- `POST /v1/admin/features` - Admin: Manage feature flags
- `GET /v1/admin/metrics` - Admin: System metrics

## 🛠️ Installation & Setup

### Prerequisites
- Node.js 18+
- npm 8+
- Docker & Docker Compose (for containerized development)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd jarvis-api
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Build TypeScript**
   ```bash
   npm run build
   ```

5. **Start development server**
   ```bash
   npm run dev
   ```

### Docker Development

1. **Start all services**
   ```bash
   docker-compose up -d
   ```

2. **View logs**
   ```bash
   docker-compose logs -f api
   ```

3. **Stop services**
   ```bash
   docker-compose down
   ```

## 🔧 Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Server port | `3000` |
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017/jarvis-api` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `UPSTASH_VECTOR_URL` | Upstash Vector database URL | `https://your-db.upstash.io` |
| `UPSTASH_VECTOR_TOKEN` | Upstash Vector access token | `your-token` |
| `HUGGING_FACE_API_KEY` | Hugging Face API key | `hf_your-key` |
| `JWT_SECRET` | JWT signing secret | `your-secret-key` |
| `LOG_LEVEL` | Logging level | `info` |

## 📁 Project Structure

```
src/
├── config/           # Configuration files
│   ├── logger.ts     # Winston logger setup
│   ├── mongodb.ts    # MongoDB connection
│   └── redis.ts      # Redis connection
├── middleware/       # Express middleware
│   ├── errorHandler.ts  # Error handling
│   └── rateLimiter.ts   # Rate limiting
├── routes/           # API route handlers
│   ├── auth.ts       # Authentication routes
│   ├── chat.ts       # Chat/LLM routes
│   ├── status.ts     # Health check routes
│   └── ...           # Other route files
└── server.ts         # Main server entry point
```

## 🧪 Development Scripts

```bash
# Development
npm run dev          # Start with nodemon
npm run build        # Compile TypeScript
npm run start        # Start production server

# Code Quality
npm run lint         # Run ESLint
npm run lint:fix     # Fix ESLint issues
npm run format       # Format with Prettier

# Testing
npm run test         # Run Jest tests
npm run test:watch   # Watch mode testing

# Docker
npm run docker:build  # Build Docker image
npm run docker:run    # Run Docker container
```

## 📊 Logging

The application uses Winston for structured logging with:
- **Console logging** in development
- **File rotation** in production
- **Structured JSON** format
- **Multiple log levels**: error, warn, info, http, debug

Log files are stored in the `logs/` directory:
- `error-YYYY-MM-DD.log` - Error logs only
- `combined-YYYY-MM-DD.log` - All logs
- `access-YYYY-MM-DD.log` - HTTP access logs

## 🔒 Security Features

- **Helmet.js** for security headers
- **Rate limiting** with Redis-backed token bucket
- **CORS** configuration
- **Input validation** with Joi
- **Error handling** without information leakage
- **Docker security** with non-root user

## 🏗️ Architecture

### Cell-Based Deployment
The API is designed for cell-based architecture enabling:
- **Gradual rollouts** with feature flags
- **Fault isolation** between cells
- **A/B testing** capabilities
- **Horizontal scaling**

### Database Strategy
- **MongoDB**: Primary data storage (users, sessions, chat history)
- **Redis**: Caching, rate limiting, feature flags
- **Upstash Vector**: Embeddings for RAG functionality

## 🚀 Production Deployment

### Kubernetes
The application includes:
- Health check endpoints (`/v1/status/ready`, `/v1/status/live`)
- Graceful shutdown handling
- Multi-stage Docker builds
- Resource optimization

### Monitoring
- Structured logging for observability
- Health metrics and status endpoints
- Rate limiting metrics
- Performance monitoring ready

## 📝 Task Progress

✅ **Task 1: Project Setup** - COMPLETED
- [x] Node.js + TypeScript + Express setup
- [x] Winston logging implementation
- [x] ESLint + Prettier configuration
- [x] Docker configuration
- [x] Environment variables setup

🔄 **Next Tasks:**
- Task 2: Database Integration (MongoDB, Redis, Vector DB)
- Task 3: Authentication & Token Endpoints
- Task 4: Chat Endpoints
- Task 5: Upload & Vector Endpoints
- Task 6: User & Feature Flag Endpoints
- Task 7: Rate Limiting & Usage
- Task 8: Health & Admin Endpoints

## 📞 API Testing

The server exposes a health check endpoint immediately:

```bash
# Check if server is running
curl http://localhost:3000/v1/status

# Response example:
{
  "status": "healthy",
  "timestamp": "2024-01-20T10:30:00.000Z",
  "uptime": 150.5,
  "version": "1.0.0",
  "environment": "development",
  "services": {
    "mongodb": "connected",
    "redis": "connected",
    "vectorDb": "not_configured"
  },
  "system": {
    "nodeVersion": "v18.18.0",
    "platform": "linux",
    "memory": {
      "used": 45678912,
      "total": 67108864,
      "percentage": 68
    }
  }
}
```

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

**Status**: Task 1 Complete ✅ | Ready for Task 2: Database Integration 