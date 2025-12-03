import express from 'express';
import multer from 'multer';
import mongoose from 'mongoose';
import { File } from '../models/File.js';
import { FileChunk } from '../models/FileChunk.js';
import { logSecurityEvent } from '../middleware/securityLogger.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();
const upload = multer();

const parseFormData = (req, res, next) => {
  if (req.is('multipart/form-data')) {
    return upload.none()(req, res, next);
  }
  next();
};

/**
 * POST /api/files/upload
 * Upload encrypted file chunks
 */
router.post('/upload', requireAuth, async (req, res) => {
  try {
    console.log('File upload request received');
    console.log('Request body keys:', Object.keys(req.body));
    console.log('Content-Type:', req.get('Content-Type'));
    
    const { receiverId, fileName, fileType, fileSize, totalChunks, chunks } = req.body;
    const senderId = req.userId;

    console.log('Parsed fields:', {
      hasReceiverId: !!receiverId,
      hasFileName: !!fileName,
      hasFileType: !!fileType,
      hasFileSize: !!fileSize,
      hasTotalChunks: !!totalChunks,
      hasChunks: !!chunks,
      chunksType: typeof chunks,
      chunksIsArray: Array.isArray(chunks)
    });

    if (!receiverId || !fileName || !fileType || !fileSize || !totalChunks || !chunks) {
      console.error('Missing required fields:', {
        receiverId: !!receiverId,
        fileName: !!fileName,
        fileType: !!fileType,
        fileSize: !!fileSize,
        totalChunks: !!totalChunks,
        chunks: !!chunks
      });
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Parse chunks (they come as JSON string from FormData, or already as array from JSON)
    let encryptedChunks;
    try {
      if (typeof chunks === 'string') {
        encryptedChunks = JSON.parse(chunks);
      } else if (Array.isArray(chunks)) {
        encryptedChunks = chunks;
      } else {
        throw new Error('Chunks must be a string or array');
      }
      console.log('Parsed chunks, count:', encryptedChunks.length);
    } catch (parseError) {
      console.error('Error parsing chunks:', parseError);
      return res.status(400).json({ error: 'Invalid chunks format: ' + parseError.message });
    }

    // Validate chunks structure
    if (!Array.isArray(encryptedChunks) || encryptedChunks.length === 0) {
      console.error('Invalid chunks: not an array or empty');
      return res.status(400).json({ error: 'Chunks must be a non-empty array' });
    }

    // Validate each chunk has required fields
    for (let i = 0; i < encryptedChunks.length; i++) {
      const chunk = encryptedChunks[i];
      if (!chunk.ciphertext || !chunk.iv || !chunk.authTag || typeof chunk.chunkIndex !== 'number') {
        console.error('Invalid chunk at index', i, chunk);
        return res.status(400).json({ error: `Invalid chunk structure at index ${i}` });
      }
    }

    console.log('Creating file record...');
    console.log('senderId type:', typeof senderId, 'value:', senderId);
    console.log('receiverId type:', typeof receiverId, 'value:', receiverId);
    
    // Ensure IDs are valid ObjectIds (Mongoose will auto-convert, but let's validate)
    if (!mongoose.Types.ObjectId.isValid(senderId)) {
      console.error('Invalid senderId:', senderId);
      return res.status(400).json({ error: 'Invalid sender ID format' });
    }
    if (!mongoose.Types.ObjectId.isValid(receiverId)) {
      console.error('Invalid receiverId:', receiverId);
      return res.status(400).json({ error: 'Invalid receiver ID format' });
    }
    console.log('ObjectIds validated');
    
    // Create file record (without chunks to avoid size limit)
    // Explicitly set encryptedChunks to empty array to ensure it's not included
    const fileData = {
      senderId,
      receiverId,
      fileName,
      fileType,
      fileSize: parseInt(fileSize),
      totalChunks: parseInt(totalChunks),
      uploadedAt: new Date(),
      encryptedChunks: [] // Explicitly set to empty array
    };
    
    console.log('File data to save:', {
      senderId: fileData.senderId,
      receiverId: fileData.receiverId,
      fileName: fileData.fileName,
      fileType: fileData.fileType,
      fileSize: fileData.fileSize,
      totalChunks: fileData.totalChunks,
      encryptedChunksLength: fileData.encryptedChunks.length
    });
    
    const file = new File(fileData);

    console.log('Saving file to database...');
    try {
      await file.save();
      console.log('File saved successfully, ID:', file._id.toString());
    } catch (saveError) {
      console.error('Error saving file document:', saveError);
      console.error('File document size estimate:', JSON.stringify(fileData).length, 'bytes');
      throw saveError;
    }
    
    // Store chunks separately to avoid MongoDB 16MB document limit
    console.log('Storing chunks separately...');
    console.log('Total chunks to store:', encryptedChunks.length);
    
    // Store chunks one at a time to avoid any potential issues
    for (let i = 0; i < encryptedChunks.length; i++) {
      const chunk = encryptedChunks[i];
      try {
        console.log(`Storing chunk ${i + 1}/${encryptedChunks.length} (index: ${chunk.chunkIndex})`);
        console.log(`Chunk sizes - ciphertext: ${chunk.ciphertext?.length || 0}, iv: ${chunk.iv?.length || 0}, authTag: ${chunk.authTag?.length || 0}`);
        
        await FileChunk.create({
          fileId: file._id,
          chunkIndex: chunk.chunkIndex,
          ciphertext: chunk.ciphertext,
          iv: chunk.iv,
          authTag: chunk.authTag
        });
        console.log(`✓ Chunk ${i + 1} stored successfully`);
      } catch (chunkError) {
        console.error(`✗ Error storing chunk ${i + 1}:`, chunkError);
        throw new Error(`Failed to store chunk ${i + 1}: ${chunkError.message}`);
      }
    }
    
    console.log('All chunks stored successfully');

    await logSecurityEvent('METADATA_ACCESS', senderId, {
      action: 'file_upload',
      fileId: file._id.toString(),
      receiverId
    }, req.ip);

    res.status(201).json({
      message: 'File uploaded successfully',
      fileId: file._id.toString()
    });
  } catch (error) {
    console.error('File upload error:', error);
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    // Provide more specific error messages
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: 'Validation error', 
        details: error.message 
      });
    }
    
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

/**
 * GET /api/files/list
 * List files for the authenticated user
 * NOTE: This must come before /:fileId route to avoid route conflicts
 */
router.get('/list', requireAuth, async (req, res) => {
  try {
    const userId = req.userId;
    const { limit = 50 } = req.query;

    console.log('Fetching files list for user:', userId);

    const files = await File.find({
      $or: [
        { senderId: userId },
        { receiverId: userId }
      ]
    })
      .sort({ uploadedAt: -1 })
      .limit(parseInt(limit))
      .populate('senderId', 'username _id')
      .populate('receiverId', 'username _id')
      .select('fileName fileType fileSize totalChunks senderId receiverId uploadedAt');

    console.log('Found files:', files.length);

    await logSecurityEvent('METADATA_ACCESS', userId, {
      action: 'list_files',
      count: files.length
    }, req.ip);

    res.json({
      files: files.map(file => ({
        fileId: file._id.toString(),
        fileName: file.fileName,
        fileType: file.fileType,
        fileSize: file.fileSize,
        senderId: file.senderId._id ? file.senderId._id.toString() : file.senderId.toString(),
        senderUsername: file.senderId.username || 'Unknown',
        receiverId: file.receiverId._id ? file.receiverId._id.toString() : file.receiverId.toString(),
        receiverUsername: file.receiverId.username || 'Unknown',
        uploadedAt: file.uploadedAt
      }))
    });
  } catch (error) {
    console.error('List files error:', error);
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

/**
 * GET /api/files/:fileId
 * Get encrypted file for download
 */
router.get('/:fileId', requireAuth, async (req, res) => {
  try {
    const { fileId } = req.params;
    const userId = req.userId;

    const file = await File.findById(fileId)
      .populate('senderId', 'username')
      .populate('receiverId', 'username');

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Verify user has access (sender or receiver)
    if (file.senderId._id.toString() !== userId && file.receiverId._id.toString() !== userId) {
      await logSecurityEvent('METADATA_ACCESS', userId, {
        action: 'unauthorized_file_access',
        fileId
      }, req.ip);
      return res.status(403).json({ error: 'Access denied' });
    }

    await logSecurityEvent('METADATA_ACCESS', userId, {
      action: 'file_download',
      fileId
    }, req.ip);

    // Fetch chunks from separate collection
    const chunks = await FileChunk.find({ fileId: file._id })
      .sort({ chunkIndex: 1 })
      .select('ciphertext iv authTag chunkIndex');
    
    // Convert to array format expected by frontend
    const encryptedChunks = chunks.map(chunk => ({
      ciphertext: chunk.ciphertext,
      iv: chunk.iv,
      authTag: chunk.authTag,
      chunkIndex: chunk.chunkIndex
    }));

    // If no chunks found in separate collection, try legacy encryptedChunks field
    if (encryptedChunks.length === 0 && file.encryptedChunks && file.encryptedChunks.length > 0) {
      console.log('Using legacy encryptedChunks field');
      encryptedChunks.push(...file.encryptedChunks);
    }

    res.json({
      fileId: file._id.toString(),
      fileName: file.fileName,
      fileType: file.fileType,
      fileSize: file.fileSize,
      encryptedChunks,
      totalChunks: file.totalChunks,
      senderId: file.senderId._id.toString(),
      senderUsername: file.senderId.username,
      uploadedAt: file.uploadedAt
    });
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;

