interface AccountDeletionDependencies {
  uid: string;
  deleteObjects: (uid: string) => Promise<void>;
  deleteDocuments: (uid: string) => Promise<void>;
  deleteIdentity: (uid: string) => Promise<void>;
}

async function deleteAccount({
  uid,
  deleteObjects,
  deleteDocuments,
  deleteIdentity,
}: AccountDeletionDependencies): Promise<void> {
  if (!uid) throw new Error('uid is required');
  await deleteObjects(uid);
  await deleteDocuments(uid);
  await deleteIdentity(uid);
}

export { deleteAccount };
