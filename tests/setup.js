// Test setup file for backend tests
import { vi } from 'vitest';

// Mock environment variables for tests
process.env.NODE_ENV = 'test';
process.env.PORT = '3002';
process.env.MONGODB_URI = 'mongodb://localhost:27017/academiazen_test';
process.env.VAPID_PUBLIC_KEY = 'test-public-key';
process.env.VAPID_PRIVATE_KEY = 'test-private-key';
process.env.VAPID_SUBJECT = 'mailto:test@test.com';

// Mock firebase-admin
vi.mock('firebase-admin', () => ({
  default: {
    initializeApp: vi.fn(),
    credential: {
      cert: vi.fn()
    },
    auth: vi.fn(() => ({
      verifyIdToken: vi.fn().mockResolvedValue({
        uid: 'test-user-id',
        email: 'test@example.com'
      })
    }))
  },
  initializeApp: vi.fn(),
  credential: {
    cert: vi.fn()
  },
  auth: vi.fn(() => ({
    verifyIdToken: vi.fn().mockResolvedValue({
      uid: 'test-user-id',
      email: 'test@example.com'
    })
  }))
}));

// Mock web-push
vi.mock('web-push', () => ({
  default: {
    setVapidDetails: vi.fn(),
    sendNotification: vi.fn().mockResolvedValue({ statusCode: 201 })
  },
  setVapidDetails: vi.fn(),
  sendNotification: vi.fn().mockResolvedValue({ statusCode: 201 })
}));

// Global test utilities
global.testUtils = {
  createMockUser: (overrides = {}) => ({
    uid: 'test-user-id',
    email: 'test@example.com',
    state: {
      tasks: [],
      subjects: [],
      flashcards: [],
      folders: [{ id: 'general', name: 'General', items: [] }],
      profile: { firstName: 'Test', lastName: 'User', quoteEnabled: true },
      settings: {
        focusDuration: 25,
        notifications: true,
        deadlineAlerts: true,
        ambience: 'silent',
        weeklyFocusGoal: 600
      },
      quizProgress: null,
      aiChat: [],
      updatedAt: new Date().toISOString()
    },
    createdAt: new Date(),
    lastActivity: new Date(),
    ...overrides
  }),

  createMockTask: (overrides = {}) => ({
    id: 'task-' + Date.now(),
    text: 'Test Task',
    completed: false,
    createdAt: new Date().toISOString(),
    subjectId: null,
    subtasks: [],
    deadline: null,
    deadlineReminder: false,
    ...overrides
  })
};

console.log('[Test Setup] Backend test environment initialized');
