import mongoose from 'mongoose';

const securityLogSchema = new mongoose.Schema({
  eventType: {
    type: String,
    required: true,
    enum: [
      'AUTH_ATTEMPT',
      'AUTH_SUCCESS',
      'AUTH_FAILURE',
      'KEY_EXCHANGE_ATTEMPT',
      'KEY_EXCHANGE_SUCCESS',
      'KEY_EXCHANGE_FAILURE',
      'DECRYPT_FAILURE',
      'REPLAY_DETECTED',
      'INVALID_SIGNATURE',
      'METADATA_ACCESS'
    ]
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  details: {
    type: mongoose.Schema.Types.Mixed
  },
  ipAddress: {
    type: String
  },
  timestamp: {
    type: Date,
    default: Date.now,
    required: true
  }
}, {
  timestamps: true
});

// Index for efficient log queries
securityLogSchema.index({ eventType: 1, timestamp: -1 });
securityLogSchema.index({ userId: 1, timestamp: -1 });

export const SecurityLog = mongoose.model('SecurityLog', securityLogSchema);

