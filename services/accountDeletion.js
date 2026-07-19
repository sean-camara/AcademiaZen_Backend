async function deleteAccount({ uid, deleteObjects, deleteDocuments, deleteIdentity }) {
  if (!uid) throw new Error('uid is required');
  await deleteObjects(uid);
  await deleteDocuments(uid);
  await deleteIdentity(uid);
}

module.exports = { deleteAccount };
