import mongoose, { type Model, Schema } from 'mongoose';

interface AIQuotaLockDocument {
  _id: string;
  owner: string;
  lockedUntil: Date;
}

const AIQuotaLockSchema = new Schema<AIQuotaLockDocument>({
  _id: { type: String, required: true },
  owner: { type: String, required: true },
  lockedUntil: { type: Date, required: true },
}, { versionKey: false, timestamps: true });

const existingModel = mongoose.models.AIQuotaLock as Model<AIQuotaLockDocument> | undefined;
const AIQuotaLock = existingModel || mongoose.model<AIQuotaLockDocument>('AIQuotaLock', AIQuotaLockSchema);

export { AIQuotaLock };
