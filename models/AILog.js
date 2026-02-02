const mongoose = require('mongoose');

/**
 * AI Request Log Schema
 * Tracks all AI API calls for monitoring, debugging, and cost analysis
 */
const AILogSchema = new mongoose.Schema({
  // User identification
  uid: { type: String, required: true, index: true },
  
  // Request details
  endpoint: { type: String, required: true, enum: ['chat', 'reviewer', 'other'] },
  model: { type: String, default: '' },
  mode: { type: String, default: '' }, // 'fast', 'deep', etc.
  
  // Token usage (from API response)
  promptTokens: { type: Number, default: 0 },
  completionTokens: { type: Number, default: 0 },
  totalTokens: { type: Number, default: 0 },
  
  // Cost tracking (in USD, estimated)
  estimatedCost: { type: Number, default: 0 },
  
  // Request metadata
  promptLength: { type: Number, default: 0 }, // Character count
  responseLength: { type: Number, default: 0 }, // Character count
  
  // Status
  success: { type: Boolean, default: true },
  errorCode: { type: String, default: '' },
  errorMessage: { type: String, default: '' },
  
  // Performance
  responseTimeMs: { type: Number, default: 0 },
  
  // User tier at time of request
  userTier: { type: String, enum: ['free', 'premium'], default: 'free' },
  
  // Timestamp
  createdAt: { type: Date, default: Date.now, index: true },
}, { 
  timestamps: false, // We manage createdAt manually for indexing
  // TTL: Auto-delete logs older than 90 days to save storage
  expireAfterSeconds: 90 * 24 * 60 * 60,
});

// Compound indexes for common queries
AILogSchema.index({ uid: 1, createdAt: -1 });
AILogSchema.index({ uid: 1, endpoint: 1, createdAt: -1 });
AILogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 }); // TTL index

const AILog = mongoose.model('AILog', AILogSchema);

module.exports = { AILog };
