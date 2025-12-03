import mongoose from 'mongoose';

const fileChunkSchema = new mongoose.Schema({
  fileId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true,
    index: true
  },
  chunkIndex: {
    type: Number,
    required: true
  },
  ciphertext: {
    type: String,
    required: true
  },
  iv: {
    type: String,
    required: true
  },
  authTag: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

// Index for efficient chunk retrieval
fileChunkSchema.index({ fileId: 1, chunkIndex: 1 }, { unique: true });

export const FileChunk = mongoose.model('FileChunk', fileChunkSchema);

