const { deleteAccount } = require('../services/accountDeletion');

describe('account deletion orchestration', () => {
  it('deletes objects, application records, then the identity', async () => {
    const order = [];
    await deleteAccount({
      uid: 'user-1',
      deleteObjects: async () => order.push('objects'),
      deleteDocuments: async () => order.push('documents'),
      deleteIdentity: async () => order.push('identity'),
    });
    expect(order).toEqual(['objects', 'documents', 'identity']);
  });

  it('keeps the identity usable for retry when object deletion fails', async () => {
    const deleteDocuments = vi.fn();
    const deleteIdentity = vi.fn();
    await expect(deleteAccount({
      uid: 'user-1',
      deleteObjects: async () => { throw new Error('storage unavailable'); },
      deleteDocuments,
      deleteIdentity,
    })).rejects.toThrow('storage unavailable');
    expect(deleteDocuments).not.toHaveBeenCalled();
    expect(deleteIdentity).not.toHaveBeenCalled();
  });

  it('requires a concrete user ID', async () => {
    await expect(deleteAccount({ uid: '', deleteObjects: vi.fn(), deleteDocuments: vi.fn(), deleteIdentity: vi.fn() }))
      .rejects.toThrow('uid is required');
  });
});
