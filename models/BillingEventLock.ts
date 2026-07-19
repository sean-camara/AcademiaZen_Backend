import mongoose, { type Model, Schema } from 'mongoose';

interface BillingEventLockDocument {
  _id: string;
  owner: string;
  lockedUntil: Date;
}

const BillingEventLockSchema = new Schema<BillingEventLockDocument>({
  _id: { type: String, required: true },
  owner: { type: String, required: true },
  lockedUntil: { type: Date, required: true },
}, { versionKey: false, timestamps: true });

const existingModel = mongoose.models.BillingEventLock as Model<BillingEventLockDocument> | undefined;
const BillingEventLock = existingModel
  || mongoose.model<BillingEventLockDocument>('BillingEventLock', BillingEventLockSchema);

export { BillingEventLock };
