# AcademiaZen Push Notification Backend

This is the backend server for handling Web Push Notifications for the AcademiaZen PWA.

## How Push Notifications Work

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Frontend      │     │   Backend        │     │   Push Service  │
│   (Browser)     │     │   (This Server)  │     │   (Browser's)   │
└────────┬────────┘     └────────┬─────────┘     └────────┬────────┘
         │                       │                        │
         │  1. Get VAPID Key     │                        │
         │──────────────────────>│                        │
         │<──────────────────────│                        │
         │                       │                        │
         │  2. Subscribe with    │                        │
         │     Service Worker    │                        │
         │──────────────────────────────────────────────>│
         │<──────────────────────────────────────────────│
         │     (subscription)    │                        │
         │                       │                        │
         │  3. Send subscription │                        │
         │     to backend        │                        │
         │──────────────────────>│                        │
         │                       │                        │
         │                       │  4. Send notification  │
         │                       │──────────────────────>│
         │                       │                        │
         │  5. Push event        │                        │
         │<──────────────────────────────────────────────│
         │     (Service Worker)  │                        │
         │                       │                        │
         │  6. Show notification │                        │
         │     (OS notification) │                        │
         ▼                       ▼                        ▼
```

## Setup

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Generate VAPID keys**
   ```bash
   npm run generate-vapid
   ```

3. **Create .env file**
   ```bash
   cp .env.example .env
   ```
   Then add your generated VAPID keys to `.env`

4. **Start the server**
   ```bash
   npm start
   ```

## API Endpoints

### GET `/api/vapid-public-key`
Returns the VAPID public key needed for push subscription.

**Response:**
```json
{
  "publicKey": "BNxDf7..."
}
```

### POST `/api/subscribe`
Register a new push subscription.

**Body:**
```json
{
  "subscription": {
    "endpoint": "https://fcm.googleapis.com/fcm/send/...",
    "keys": {
      "p256dh": "...",
      "auth": "..."
    }
  },
  "userId": "optional-user-id"
}
```

### DELETE `/api/unsubscribe`
Remove a push subscription.

**Body:**
```json
{
  "endpoint": "https://fcm.googleapis.com/fcm/send/...",
  "userId": "optional-user-id"
}
```

### POST `/api/send-notification`
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

### POST `/api/schedule-notification`
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

- Use a database (Redis, MongoDB, PostgreSQL) instead of in-memory storage
- Implement rate limiting
- Add authentication for admin endpoints
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
