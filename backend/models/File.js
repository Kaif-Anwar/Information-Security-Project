import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fileName: {
    type: String,
    required: true
  },
  fileType: {
    type: String,
    required: true
  },
  fileSize: {
    type: Number,
    required: true
  },
  // Note: encryptedChunks are now stored separately in FileChunk collection
  // This field is kept for backward compatibility but won't be used for new uploads
  encryptedChunks: [{
    ciphertext: String,
    iv: String,
    authTag: String,
    chunkIndex: Number
  }],
  totalChunks: {
    type: Number,
    required: true
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for file retrieval
fileSchema.index({ senderId: 1, receiverId: 1, uploadedAt: -1 });

export const File = mongoose.model('File', fileSchema);

