import { describe, it, expect, vi } from 'vitest';

// Since we can't directly import functions from server.js (it starts the server),
// we'll recreate the utility functions here for testing
// In a real project, you'd extract these to a separate utils file

const MAX_PDF_TEXT_CHARS = 5000;
const MAX_AI_CHAT_MESSAGES = 60;
const MAX_AI_CHAT_CHARS = 8000;

function isValidState(state) {
  if (!state || typeof state !== 'object') return false;
  if (!Array.isArray(state.tasks)) return false;
  if (!Array.isArray(state.subjects)) return false;
  if (!Array.isArray(state.flashcards)) return false;
  if (!Array.isArray(state.folders)) return false;
  if (state.aiChat && !Array.isArray(state.aiChat)) return false;
  if (!state.profile || !state.settings) return false;
  return true;
}

function sanitizeStateForStorage(state) {
  const sanitized = JSON.parse(JSON.stringify(state));
  if (typeof sanitized.updatedAt !== 'string' || !sanitized.updatedAt) {
    sanitized.updatedAt = new Date().toISOString();
  }

  if (Array.isArray(sanitized.tasks)) {
    sanitized.tasks = sanitized.tasks.map(task => {
      if (task?.pdfAttachment) {
        if (task.pdfAttachment.data) delete task.pdfAttachment.data;
        if (task.pdfAttachment.url) delete task.pdfAttachment.url;
        if (task.pdfAttachment.text && task.pdfAttachment.text.length > MAX_PDF_TEXT_CHARS) {
          task.pdfAttachment.text = task.pdfAttachment.text.slice(0, MAX_PDF_TEXT_CHARS);
        }
      }
      return task;
    });
  }

  if (Array.isArray(sanitized.aiChat)) {
    const trimmed = sanitized.aiChat.slice(-MAX_AI_CHAT_MESSAGES).map(message => {
      if (!message || typeof message !== 'object') return null;
      const text = typeof message.text === 'string' ? message.text : '';
      const role = message.role === 'ai' ? 'ai' : 'user';
      const refs = Array.isArray(message.refs) ? message.refs.filter(r => typeof r === 'string').slice(0, 20) : [];
      const createdAt = typeof message.createdAt === 'string' ? message.createdAt : '';
      return {
        role,
        text: text.length > MAX_AI_CHAT_CHARS ? text.slice(0, MAX_AI_CHAT_CHARS) : text,
        refs,
        createdAt,
      };
    }).filter(Boolean);
    sanitized.aiChat = trimmed;
  }

  return sanitized;
}

describe('State Validation', () => {
  describe('isValidState', () => {
    it('should return true for valid state', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: { firstName: 'Test' },
        settings: { focusDuration: 25 }
      };
      expect(isValidState(state)).toBe(true);
    });

    it('should return false for null state', () => {
      expect(isValidState(null)).toBe(false);
    });

    it('should return false for undefined state', () => {
      expect(isValidState(undefined)).toBe(false);
    });

    it('should return false for non-object state', () => {
      expect(isValidState('string')).toBe(false);
      expect(isValidState(123)).toBe(false);
      expect(isValidState([])).toBe(false);
    });

    it('should return false when tasks is not an array', () => {
      const state = {
        tasks: 'not an array',
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      expect(isValidState(state)).toBe(false);
    });

    it('should return false when subjects is not an array', () => {
      const state = {
        tasks: [],
        subjects: {},
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      expect(isValidState(state)).toBe(false);
    });

    it('should return false when flashcards is not an array', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: null,
        folders: [],
        profile: {},
        settings: {}
      };
      expect(isValidState(state)).toBe(false);
    });

    it('should return false when folders is not an array', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: 'folders',
        profile: {},
        settings: {}
      };
      expect(isValidState(state)).toBe(false);
    });

    it('should return false when aiChat exists but is not an array', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        aiChat: {},
        profile: {},
        settings: {}
      };
      expect(isValidState(state)).toBe(false);
    });

    it('should return true when aiChat is undefined', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      expect(isValidState(state)).toBe(true);
    });

    it('should return true when aiChat is an array', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        aiChat: [],
        profile: {},
        settings: {}
      };
      expect(isValidState(state)).toBe(true);
    });

    it('should return false when profile is missing', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        settings: {}
      };
      expect(isValidState(state)).toBe(false);
    });

    it('should return false when settings is missing', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {}
      };
      expect(isValidState(state)).toBe(false);
    });
  });

  describe('sanitizeStateForStorage', () => {
    it('should add updatedAt if missing', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.updatedAt).toBeDefined();
      expect(typeof sanitized.updatedAt).toBe('string');
    });

    it('should preserve existing updatedAt', () => {
      const timestamp = '2024-01-15T10:30:00.000Z';
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {},
        updatedAt: timestamp
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.updatedAt).toBe(timestamp);
    });

    it('should remove pdfAttachment.data from tasks', () => {
      const state = {
        tasks: [{
          id: '1',
          text: 'Test',
          pdfAttachment: {
            name: 'test.pdf',
            data: 'base64datahere',
            text: 'extracted text'
          }
        }],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.tasks[0].pdfAttachment.data).toBeUndefined();
      expect(sanitized.tasks[0].pdfAttachment.name).toBe('test.pdf');
      expect(sanitized.tasks[0].pdfAttachment.text).toBe('extracted text');
    });

    it('should remove pdfAttachment.url from tasks', () => {
      const state = {
        tasks: [{
          id: '1',
          text: 'Test',
          pdfAttachment: {
            name: 'test.pdf',
            url: 'http://example.com/file.pdf'
          }
        }],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.tasks[0].pdfAttachment.url).toBeUndefined();
    });

    it('should truncate long pdfAttachment.text', () => {
      const longText = 'a'.repeat(10000);
      const state = {
        tasks: [{
          id: '1',
          text: 'Test',
          pdfAttachment: {
            name: 'test.pdf',
            text: longText
          }
        }],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.tasks[0].pdfAttachment.text.length).toBe(MAX_PDF_TEXT_CHARS);
    });

    it('should limit aiChat messages', () => {
      const messages = Array.from({ length: 100 }, (_, i) => ({
        role: i % 2 === 0 ? 'user' : 'ai',
        text: `Message ${i}`,
        refs: [],
        createdAt: new Date().toISOString()
      }));
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {},
        aiChat: messages
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.aiChat.length).toBe(MAX_AI_CHAT_MESSAGES);
    });

    it('should truncate long aiChat message text', () => {
      const longText = 'b'.repeat(10000);
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {},
        aiChat: [{
          role: 'user',
          text: longText,
          refs: [],
          createdAt: new Date().toISOString()
        }]
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.aiChat[0].text.length).toBe(MAX_AI_CHAT_CHARS);
    });

    it('should normalize aiChat message roles', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {},
        aiChat: [
          { role: 'ai', text: 'AI response', refs: [], createdAt: '' },
          { role: 'user', text: 'User message', refs: [], createdAt: '' },
          { role: 'invalid', text: 'Invalid role', refs: [], createdAt: '' }
        ]
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.aiChat[0].role).toBe('ai');
      expect(sanitized.aiChat[1].role).toBe('user');
      expect(sanitized.aiChat[2].role).toBe('user'); // Invalid roles default to 'user'
    });

    it('should filter out invalid refs', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {},
        aiChat: [{
          role: 'ai',
          text: 'Response',
          refs: ['valid', 123, null, 'also-valid', undefined],
          createdAt: ''
        }]
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.aiChat[0].refs).toEqual(['valid', 'also-valid']);
    });

    it('should filter out invalid aiChat messages', () => {
      const state = {
        tasks: [],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {},
        aiChat: [
          { role: 'user', text: 'Valid', refs: [], createdAt: '' },
          null,
          'invalid',
          { role: 'ai', text: 'Also valid', refs: [], createdAt: '' }
        ]
      };
      const sanitized = sanitizeStateForStorage(state);
      expect(sanitized.aiChat.length).toBe(2);
    });

    it('should not mutate original state', () => {
      const state = {
        tasks: [{ id: '1', text: 'Test', pdfAttachment: { data: 'data' } }],
        subjects: [],
        flashcards: [],
        folders: [],
        profile: {},
        settings: {}
      };
      const original = JSON.parse(JSON.stringify(state));
      sanitizeStateForStorage(state);
      expect(state).toEqual(original);
    });
  });
});
