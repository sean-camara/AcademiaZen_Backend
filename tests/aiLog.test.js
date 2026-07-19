const { AILog } = require('../models/AILog');

describe('AI request log schema', () => {
  it('accepts the streaming chat endpoint used by the API', () => {
    const log = new AILog({ uid: 'test-user', endpoint: 'chat-stream' });

    expect(log.validateSync()).toBeUndefined();
  });

  it('rejects unknown endpoint values', () => {
    const log = new AILog({ uid: 'test-user', endpoint: 'unknown-endpoint' });

    expect(log.validateSync()?.errors.endpoint).toBeDefined();
  });
});
