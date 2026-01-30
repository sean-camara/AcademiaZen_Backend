# AcademiaZen Backend API

> Express.js REST API for the AcademiaZen PWA with Firebase Auth, MongoDB persistence, Web Push notifications, AI proxy, and payment processing.

[![Node.js](https://img.shields.io/badge/Node.js-18.x-green.svg)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.18.2-lightgrey.svg)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-8.10.0-green.svg)](https://www.mongodb.com/)
[![Firebase Admin](https://img.shields.io/badge/Firebase%20Admin-12.7.0-orange.svg)](https://firebase.google.com/)

## 🌟 Features

### Core Services
- **🔐 Firebase Authentication** - JWT token verification with Firebase Admin SDK
- **💾 MongoDB Persistence** - User state, focus sessions, push subscriptions
- **🔔 Web Push Notifications** - VAPID-based push with automatic cleanup
- **🤖 AI Integration** - OpenRouter proxy for DeepSeek chat and quiz generation
- **💳 Payment Processing** - PayMongo integration for premium subscriptions
- **☁️ Cloud Storage** - Cloudflare R2 pre-signed URLs for PDF uploads
- **📊 Focus Analytics** - Session tracking, streaks, and quit pattern analysis

### Security Features
- **Helmet.js** - HTTP security headers
- **Rate Limiting** - IP-based request throttling
- **CORS Protection** - Whitelist-based origin validation
- **JWT Verification** - Firebase token validation on all protected routes
- **Webhook Signatures** - PayMongo webhook HMAC verification
- **Input Sanitization** - Request payload validation and size limits

## 🏗️ Architecture

### Technology Stack
```
Express.js (REST API)
├── Firebase Admin SDK (Auth)
├── Mongoose (MongoDB ODM)
├── web-push (VAPID notifications)
├── AWS SDK (S3/R2 storage)
├── helmet + cors (Security)
└── express-rate-limit (Throttling)
```

### Data Models

#### User Schema
```javascript
{
  uid: String,              // Firebase UID (unique)
  email: String,
  state: {                  // App state (synced from frontend)
    tasks: Array,
    subjects: Array,
    flashcards: Array,
    folders: Array,
    aiReviewers: Array,
    profile: Object,
    settings: Object
  },
  billing: {               // Premium subscription status
    plan: String,          // 'free' | 'premium'
    status: String,        // 'active' | 'canceled' | 'expired'
    interval: String,      // 'monthly' | 'yearly'
    currentPeriodEnd: Date,
    autoRenew: Boolean,
    paymongo: Object       // PayMongo metadata
  },
  createdAt: Date
}
```

#### FocusSession Schema
```javascript
{
  uid: String,
  status: String,           // 'in_progress' | 'completed' | 'abandoned'
  targetType: String,       // 'task' | 'subject' | 'folderItem'
  targetId: String,
  targetLabel: String,
  plannedDurationMinutes: Number,
  actualDurationSeconds: Number,
  startedAt: Date,
  endedAt: Date,
  reflectionType: String,   // 'finished' | 'blocked'
  reflectionText: String
}
```

#### PushSubscription Schema
```javascript
{
  uid: String,
  endpoint: String,         // Unique browser push endpoint
  subscription: Object,     // Full Web Push API subscription object
  createdAt: Date
}
```

## 🚀 Getting Started

### Prerequisites
- **Node.js** 18.x or higher
- **MongoDB** instance (local or Atlas)
- **Firebase Project** with Admin SDK credentials
- **Cloudflare R2** bucket (for PDF storage)
- **OpenRouter API Key** (for AI features)
- **PayMongo Account** (optional, for payments)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd AcademiaZen_Backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Generate VAPID keys for Web Push**
   ```bash
   npm run generate-vapid
   ```
   
   This creates `vapid-keys.json` with your public/private key pair.

4. **Create environment file**
   ```bash
   cp .env.example .env
   ```

5. **Configure environment variables**

   Edit `.env` with your credentials:
   ```env
   # Server
   PORT=3001
   NODE_ENV=production

   # MongoDB
   MONGODB_URI=mongodb://localhost:27017/academiazen
   # Or Atlas: mongodb+srv://<username>:<password>@<cluster>.mongodb.net/<database>

   # Firebase Admin SDK
   FIREBASE_PROJECT_ID=your-project-id
   FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
   FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@your-project.iam.gserviceaccount.com

   # Web Push (VAPID)
   VAPID_PUBLIC_KEY=your_public_key_from_vapid-keys.json
   VAPID_PRIVATE_KEY=your_private_key_from_vapid-keys.json
   VAPID_EMAIL=mailto:admin@yourdomain.com

   # Frontend URLs (CORS)
   FRONTEND_URL=https://yourdomain.com
   FRONTEND_URLS=https://www.yourdomain.com,https://app.yourdomain.com
   ALLOW_VERCEL_PREVIEW=false
   ALLOW_NULL_ORIGIN=false

   # Cloudflare R2 (PDF Storage)
   R2_ACCOUNT_ID=your_cloudflare_account_id
   R2_ACCESS_KEY_ID=your_r2_access_key
   R2_SECRET_ACCESS_KEY=your_r2_secret_key
   R2_BUCKET=academiazen-pdfs
   R2_PUBLIC_BASE_URL=https://r2.yourdomain.com
   R2_SIGNED_URL_TTL=3600

   # AI (OpenRouter)
   OPENROUTER_API_KEY=sk-or-v1-xxxxx
   OPENROUTER_SITE_URL=https://yourdomain.com
   OPENROUTER_APP_TITLE=AcademiaZen
   AI_MODEL_FAST=deepseek/deepseek-chat
   AI_MODEL_DEEP=deepseek/deepseek-reasoner
   ALLOW_FREE_AI=false

   # Billing (PayMongo)
   PAYMONGO_SECRET_KEY=sk_test_xxxxx
   PAYMONGO_PUBLIC_KEY=pk_test_xxxxx
   PAYMONGO_WEBHOOK_SECRET=whsec_xxxxx
   PAYMONGO_SUCCESS_URL=https://yourdomain.com/?billing=success
   PAYMONGO_CANCEL_URL=https://yourdomain.com/?billing=cancel

   # Limits
   MAX_STATE_BYTES=5242880        # 5 MB
   MAX_UPLOAD_BYTES=10485760      # 10 MB
   MAX_AI_PROMPT_CHARS=15000
   ```

6. **Start the server**

   **Development:**
   ```bash
   npm run dev
   ```

   **Production:**
   ```bash
   npm start
   ```

   Server runs at `http://localhost:3001`

### Verify Installation

```bash
# Health check
curl http://localhost:3001/health

# Auth ping
curl http://localhost:3001/api/auth/ping

# Get VAPID public key
curl http://localhost:3001/api/vapid-public-key
```

## 📡 API Endpoints

### Public Endpoints

#### `GET /health`
Health check for monitoring and load balancers.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-30T12:00:00.000Z"
}
```

#### `GET /api/auth/ping`
Frontend API reachability test.

#### `GET /api/vapid-public-key`
Returns VAPID public key for push subscription.

**Response:**
```json
{
  "publicKey": "BNxDf7kqGHdh8..."
}
```

---

### Authentication

All protected endpoints require:
```
Authorization: Bearer <firebase_jwt_token>
```

#### `GET /api/me`
Get current user info and billing status.

**Response:**
```json
{
  "uid": "firebase_uid",
  "email": "user@example.com",
  "billing": {
    "plan": "premium",
    "status": "active",
    "currentPeriodEnd": "2026-02-28T00:00:00.000Z"
  },
  "createdAt": "2026-01-01T00:00:00.000Z"
}
```

---

### User State Management

#### `GET /api/state`
Fetch user's full app state.

#### `PUT /api/state`
Save user's app state (debounced sync from frontend).

**Body:**
```json
{
  "state": {
    "tasks": [...],
    "subjects": [...],
    "flashcards": [...],
    "folders": [...],
    "aiReviewers": [...],
    "profile": {...},
    "settings": {...}
  }
}
```

**State Sanitization:**
- Removes `data` fields from PDF attachments (not stored in DB)
- Truncates large text fields
- Enforces `MAX_STATE_BYTES` limit

#### `DELETE /api/account`
Delete all user data (account deletion).

---

### Push Notifications

#### `POST /api/subscribe`
Register a push subscription.

**Body:**
```json
{
  "subscription": {
    "endpoint": "https://fcm.googleapis.com/...",
    "keys": {
      "p256dh": "...",
      "auth": "..."
    }
  }
}
```

#### `DELETE /api/unsubscribe`
Remove a push subscription.

**Body:**
```json
{
  "endpoint": "https://fcm.googleapis.com/..."
}
```

#### `POST /api/send-notification`
Send a push notification to current user.

**Body:**
```json
{
  "title": "Task Reminder",
  "body": "Physics homework due in 2 hours!",
  "icon": "/icons/icon-192x192.svg",
  "url": "/?page=home",
  "data": { "taskId": "123" }
}
```

#### `POST /api/notify-new-task`
Automatically send notification for tasks due within 3 days.

**Body:**
```json
{
  "task": {
    "id": "123",
    "title": "Physics Homework",
    "dueDate": "2026-02-01T15:00:00Z",
    "subjectId": "physics"
  }
}
```

---

### Focus Sessions

#### `GET /api/focus/summary?targetType=task&targetId=123`
Get focus analytics for a target.

**Response:**
```json
{
  "successRate": 0.75,
  "totalSessions": 8,
  "completedSessions": 6,
  "lastSession": {
    "status": "completed",
    "plannedDurationMinutes": 45
  },
  "streak": 3,
  "quitCount7d": 1
}
```

#### `POST /api/focus/sessions/start`
Start a focus session.

**Body:**
```json
{
  "targetType": "task",
  "targetId": "123",
  "targetLabel": "Physics Homework",
  "plannedDurationMinutes": 45
}
```

#### `POST /api/focus/sessions/complete`
Mark session as completed.

**Body:**
```json
{
  "sessionId": "507f1f77bcf86cd799439011",
  "reflectionText": "Finished all problems successfully"
}
```

#### `POST /api/focus/sessions/abandon`
Mark session as abandoned.

**Body:**
```json
{
  "sessionId": "507f1f77bcf86cd799439011",
  "reflectionText": "Got distracted by phone notifications"
}
```

---

### Cloudflare R2 PDF Storage

#### `POST /api/uploads/presign`
Get pre-signed URL for direct browser upload to R2.

**Body:**
```json
{
  "filename": "lecture-notes.pdf",
  "contentType": "application/pdf",
  "size": 2048576
}
```

**Response:**
```json
{
  "key": "user123/1706611200-abc123-lecture-notes.pdf",
  "uploadUrl": "https://r2.yourdomain.com/...",
  "publicUrl": "https://r2.yourdomain.com/user123/..."
}
```

**Upload Flow:**
1. Frontend calls `/api/uploads/presign`
2. Browser uploads file directly to R2 using `uploadUrl` (PUT request)
3. Frontend saves `key` in state for later retrieval

#### `POST /api/uploads/signed-url`
Get pre-signed download URL for a stored PDF.

**Body:**
```json
{
  "key": "user123/1706611200-abc123-lecture-notes.pdf"
}
```

**Response:**
```json
{
  "url": "https://r2.yourdomain.com/...?signature=..."
}
```

**Security:** Only the file owner (matched by UID prefix in key) can download.

---

### AI Endpoints

#### `POST /api/ai/chat`
Proxy to OpenRouter for AI chat (ZenAI feature).

**Body:**
```json
{
  "prompt": "Explain quantum entanglement in simple terms",
  "mode": "fast"  // or "deep" for DeepSeek Reasoner
}
```

**Response:**
```json
{
  "text": "Quantum entanglement is when two particles..."
}
```

**Rate Limit:** 30 requests/minute  
**Premium Required:** Unless `ALLOW_FREE_AI=true`

#### AI Quiz Generation (Internal)
Used by frontend's Review page to generate quizzes from PDFs.
- Extracts PDF text
- Sends to OpenRouter with structured prompt
- Returns JSON with questions array

---

### Billing (PayMongo)

#### `GET /api/billing/plans`
Get available subscription plans.

**Response:**
```json
{
  "plans": {
    "free": { "id": "free", "label": "Freemium", "amount": 0 },
    "premium": {
      "monthly": {
        "amount": 19900,
        "currency": "PHP",
        "label": "Premium Monthly",
        "interval": "monthly"
      },
      "yearly": {
        "amount": 149000,
        "currency": "PHP",
        "label": "Premium Yearly",
        "interval": "yearly"
      }
    }
  }
}
```

#### `GET /api/billing/status`
Get current user's subscription status.

#### `POST /api/billing/checkout`
Create PayMongo checkout session.

**Body:**
```json
{
  "plan": "premium",
  "interval": "monthly",
  "method": "gcash"  // or "bank"/"qrph"
}
```

**Response:**
```json
{
  "checkoutUrl": "https://checkout.paymongo.com/...",
  "checkoutId": "cs_abc123"
}
```

#### `POST /api/billing/extend`
Manually extend subscription (for auto-renew disabled users).

#### `POST /api/billing/cancel`
Cancel auto-renewal (keeps access until period end).

#### `POST /api/billing/refresh`
Poll checkout status and upgrade if paid.

#### `POST /api/billing/webhook/paymongo`
PayMongo webhook handler (verifies signature, updates billing status).

---

## 🔔 Push Notifications Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Frontend      │     │   Backend        │     │   Push Service  │
│   (Browser)     │     │   (This Server)  │     │   (FCM/WebPush) │
└────────┬────────┘     └────────┬─────────┘     └────────┬────────┘
         │                       │                        │
         │  1. Get VAPID Key     │                        │
         │──────────────────────>│                        │
         │<───── publicKey ──────│                        │
         │                       │                        │
         │  2. Subscribe with    │                        │
         │     Service Worker    │                        │
         │──────────────────────────────────────────────>│
         │<────── subscription object ────────────────────│
         │                       │                        │
         │  3. Send subscription │                        │
         │──────────────────────>│                        │
         │                       │ Store in MongoDB       │
         │                       │                        │
         │                       │  4. Send notification  │
         │                       │──────────────────────>│
         │                       │                        │
         │  5. Push event        │                        │
         │<──────────────────────────────────────────────│
         │   (Service Worker)    │                        │
         │                       │                        │
         │  6. Show notification │                        │
         │     (OS notification) │                        │
         ▼                       ▼                        ▼
```

### Automatic Cleanup
- **410 Gone** responses from push service trigger subscription deletion
- Prevents wasted notifications to uninstalled apps

---

## 🛡️ Security

### Authentication Middleware
```javascript
// requireAuth verifies Firebase JWT
const requireAuth = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const decodedToken = await admin.auth().verifyIdToken(token);
  req.user = { uid: decodedToken.uid, email: decodedToken.email };
  next();
};
```

### Rate Limiting
```javascript
// Global API rate limit
windowMs: 15 * 60 * 1000,  // 15 minutes
limit: 300,                // 300 requests per window

// Checkout-specific (prevent spam)
windowMs: 5 * 60 * 1000,   // 5 minutes
limit: 30
```

### CORS Configuration
```javascript
// Whitelist-based with optional Vercel preview support
allowedOrigins: [
  'http://localhost:5173',
  process.env.FRONTEND_URL,
  ...process.env.FRONTEND_URLS.split(',')
]
```

### Webhook Verification
```javascript
// HMAC SHA-256 signature verification for PayMongo
verifyPaymongoSignature(req) {
  const signature = req.headers['paymongo-signature'];
  const computed = crypto.createHmac('sha256', secret)
    .update(req.rawBody)
    .digest('hex');
  return crypto.timingSafeEqual(signature, computed);
}
```

---

## 🐳 Docker Deployment

### Dockerfile
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3001
CMD ["node", "server.js"]
```

### Build and Run
```bash
docker build -t academiazen-backend .
docker run -p 3001:3001 --env-file .env academiazen-backend
```

### Docker Compose
See root `docker-compose.yml` for full stack deployment with MongoDB.

---

## 🔧 Maintenance

### Database Indexes
```javascript
// User model
uid: { type: String, required: true, unique: true, index: true }

// FocusSession model
{ uid: 1, endedAt: -1 }
{ uid: 1, targetType: 1, targetId: 1, endedAt: -1 }

// PushSubscription model
{ uid: 1, endpoint: 1 }, unique: true
```

### Monitoring Health Check
```bash
# Add to uptime monitor (every 5 minutes)
curl -f https://api.yourdomain.com/health || exit 1
```

### Log Rotation
Use PM2 or systemd for log management:
```bash
pm2 start server.js --name academiazen-backend --log-date-format "YYYY-MM-DD HH:mm:ss"
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
```

---

## 🐛 Troubleshooting

### MongoDB Connection Fails
```bash
# Check MongoDB is running
sudo systemctl status mongod

# Test connection
mongosh "mongodb://localhost:27017/academiazen"

# Check network/firewall for Atlas
curl -I https://cluster0.mongodb.net
```

### Firebase Auth Errors
- Verify `FIREBASE_PRIVATE_KEY` includes `\n` newlines
- Check Firebase console for service account permissions
- Ensure frontend sends valid JWT in `Authorization` header

### Push Notifications Not Sending
- Verify VAPID keys match frontend
- Check subscription stored in MongoDB: `db.pushsubscriptions.find()`
- Test with: `webpush.sendNotification(subscription, payload)`

### AI Requests Fail
- Check OpenRouter API key validity
- Monitor usage at [openrouter.ai/activity](https://openrouter.ai/activity)
- Increase timeout if using DeepSeek Reasoner (30s+)

### PayMongo Webhook Issues
- Use ngrok for local testing: `ngrok http 3001`
- Check webhook signature secret matches
- Test signature: `verifyPaymongoSignature(mockRequest)`

---

## 📄 License

See root LICENSE file.

## 🤝 Contributing

This is an academic project. For questions or contributions, contact the maintainers.

## 📞 Support

For deployment issues, see:
- `/DEPLOYMENT_GUIDE.md` - Production deployment
- `/VPS_SETUP.md` - Server configuration
- Frontend README for client-side setup
  "endpoint": "https://fcm.googleapis.com/fcm/send/...",
  "userId": "optional-user-id"
}
```

### POST `/api/send-notification` (auth required)
Send a push notification.

**Body:**
```json
{
  "title": "Study Reminder",
  "body": "Time to review your flashcards!",
  "icon": "/icons/icon-192x192.svg",
  "url": "/?page=review",
  "userId": "optional-specific-user"
}
```

### POST `/api/schedule-notification` (auth required)
Schedule a notification for later.

**Body:**
```json
{
  "title": "Daily Briefing",
  "body": "You have 3 tasks due today",
  "scheduledTime": "2026-01-06T08:00:00Z",
  "userId": "optional-specific-user"
}
```

## Frontend Integration

Copy the VAPID public key to your frontend. The frontend should:

1. Check if push notifications are supported
2. Request notification permission from user
3. Subscribe using the service worker's `pushManager`
4. Send the subscription to this backend
5. Handle push events in the service worker

See the `AcademiaZen/utils/pushNotifications.ts` for the frontend implementation.

## Production Considerations

- Use a job queue (Bull, Agenda) for scheduled notifications
- Set up HTTPS (required for push notifications)
- Monitor failed notifications and clean up stale subscriptions

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `VAPID_PUBLIC_KEY` | Public key for push subscription | Yes |
| `VAPID_PRIVATE_KEY` | Private key for sending notifications | Yes |
| `VAPID_EMAIL` | Contact email for VAPID | No |
| `PORT` | Server port (default: 3001) | No |
| `FRONTEND_URL` | Frontend URL for CORS | No |
| `MONGODB_URI` | MongoDB Atlas connection string | Yes |
| `FIREBASE_PROJECT_ID` | Firebase project ID (if not using JSON) | Yes |
| `FIREBASE_CLIENT_EMAIL` | Firebase Admin client email | Yes |
| `FIREBASE_PRIVATE_KEY` | Firebase Admin private key | Yes |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Full service account JSON (alternative) | No |
| `OPENROUTER_API_KEY` | OpenRouter API key (sk-or-...) | Yes |
| `AI_MODEL` | Default model ID (fallback) | No |
| `AI_MODEL_FAST` | Fast model (default path) | No |
| `AI_MODEL_DEEP` | Deep analysis model | No |
| `AI_BASE_URL` | OpenRouter base URL override | No |
| `R2_ENDPOINT` | Cloudflare R2 S3 endpoint | Yes (for PDF uploads) |
| `R2_BUCKET` | R2 bucket name | Yes |
| `R2_ACCESS_KEY_ID` | R2 access key ID | Yes |
| `R2_SECRET_ACCESS_KEY` | R2 secret access key | Yes |
| `R2_PUBLIC_BASE_URL` | Optional public base URL | No |
