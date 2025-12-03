/**
 * File Encryption Service - Handles encrypted file upload/download
 */
import { encryptAESGCM, decryptAESGCM, generateIV, arrayBufferToBase64, base64ToArrayBuffer } from '../utils/crypto.js';
import { filesAPI } from './api.js';

const CHUNK_SIZE = 1024 * 1024; // 1MB chunks

export class FileEncryptionService {
  constructor(sessionKey) {
    this.sessionKey = sessionKey;
  }

  /**
   * Encrypt and upload file
   */
  async uploadFile(receiverId, file) {
    try {
      const chunks = [];
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

      // Read and encrypt file in chunks
      for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);

        // Read chunk as ArrayBuffer
        const chunkBuffer = await chunk.arrayBuffer();
        const chunkText = arrayBufferToBase64(new Uint8Array(chunkBuffer));

        // Encrypt chunk
        const iv = generateIV();
        const { ciphertext, iv: ivBase64, authTag } = await encryptAESGCM(chunkText, this.sessionKey, iv);

        chunks.push({
          ciphertext,
          iv: ivBase64,
          authTag,
          chunkIndex: i
        });
      }

      // Upload encrypted chunks to server
      const payload = {
        receiverId,
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size,
        totalChunks,
        chunks
      };

      const response = await filesAPI.upload(payload);

      return {
        success: true,
        fileId: response.fileId
      };
    } catch (error) {
      console.error('Error uploading file:', error);
      throw error;
    }
  }

  /**
   * Download and decrypt file
   */
  async downloadFile(fileId) {
    try {
      console.log('Downloading file:', fileId);
      
      // Get file metadata and encrypted chunks
      const fileData = await filesAPI.download(fileId);
      console.log('File data received:', {
        fileName: fileData.fileName,
        fileType: fileData.fileType,
        totalChunks: fileData.encryptedChunks?.length || 0
      });

      if (!fileData.encryptedChunks || fileData.encryptedChunks.length === 0) {
        throw new Error('No encrypted chunks found in file data');
      }

      // Validate chunk data structure
      for (let i = 0; i < fileData.encryptedChunks.length; i++) {
        const chunk = fileData.encryptedChunks[i];
        if (!chunk.ciphertext || !chunk.iv || !chunk.authTag) {
          throw new Error(`Chunk ${i} is missing required fields (ciphertext, iv, or authTag)`);
        }
        // Ensure all fields are strings (not objects or other types)
        if (typeof chunk.ciphertext !== 'string' || typeof chunk.iv !== 'string' || typeof chunk.authTag !== 'string') {
          console.warn(`Chunk ${i} has non-string fields, converting...`);
          chunk.ciphertext = String(chunk.ciphertext);
          chunk.iv = String(chunk.iv);
          chunk.authTag = String(chunk.authTag);
        }
      }

      // Decrypt chunks
      const decryptedChunks = [];
      for (let i = 0; i < fileData.encryptedChunks.length; i++) {
        const chunk = fileData.encryptedChunks[i];
        console.log(`Decrypting chunk ${i + 1}/${fileData.encryptedChunks.length} (index: ${chunk.chunkIndex})`);
        console.log(`Chunk data lengths - ciphertext: ${chunk.ciphertext?.length || 0}, iv: ${chunk.iv?.length || 0}, authTag: ${chunk.authTag?.length || 0}`);
        
        try {
          const decryptedChunk = await decryptAESGCM(
            chunk.ciphertext,
            chunk.iv,
            chunk.authTag,
            this.sessionKey
          );
          
          // Validate that decrypted chunk is valid base64
          if (!decryptedChunk || typeof decryptedChunk !== 'string') {
            throw new Error(`Invalid decrypted chunk at index ${chunk.chunkIndex}`);
          }
          
          console.log(`Decrypted chunk ${chunk.chunkIndex} length: ${decryptedChunk.length}`);
          console.log(`First 50 chars of decrypted chunk: ${decryptedChunk.substring(0, 50)}`);
          console.log(`Last 50 chars of decrypted chunk: ${decryptedChunk.substring(Math.max(0, decryptedChunk.length - 50))}`);
          
          // Check for invalid characters
          const invalidChars = decryptedChunk.match(/[^A-Za-z0-9+/=]/g);
          if (invalidChars) {
            console.error(`Invalid characters found in chunk ${chunk.chunkIndex}:`, invalidChars.slice(0, 20));
            throw new Error(`Decrypted chunk ${chunk.chunkIndex} contains invalid base64 characters: ${invalidChars.slice(0, 10).join(', ')}`);
          }
          
          // Test if it's valid base64
          try {
            atob(decryptedChunk);
            console.log(`✓ Chunk ${chunk.chunkIndex} is valid base64`);
          } catch (e) {
            console.error(`Invalid base64 in decrypted chunk ${chunk.chunkIndex}:`, e);
            console.error(`Chunk preview (first 200 chars):`, decryptedChunk.substring(0, 200));
            throw new Error(`Decrypted chunk ${chunk.chunkIndex} is not valid base64: ${e.message}`);
          }
          
          decryptedChunks.push({
            data: decryptedChunk,
            index: chunk.chunkIndex
          });
          console.log(`✓ Chunk ${i + 1} decrypted and validated successfully`);
        } catch (chunkError) {
          console.error(`Error decrypting chunk ${chunk.chunkIndex}:`, chunkError);
          throw new Error(`Failed to decrypt chunk ${chunk.chunkIndex}: ${chunkError.message}`);
        }
      }

      // Sort chunks by index
      decryptedChunks.sort((a, b) => a.index - b.index);
      console.log('All chunks decrypted and sorted');

      // Clean each chunk before combining (remove any whitespace that might have been introduced)
      // Also remove padding from all chunks except the last one
      // This is necessary because each chunk is a complete base64 string with its own padding,
      // but when combined, only the last chunk should have padding
      const cleanedChunks = decryptedChunks.map((c, idx) => {
        let cleaned = c.data.replace(/\s/g, ''); // Remove any whitespace
        
        // Remove padding from all chunks except the last one
        // Padding in base64 is only valid at the very end of the complete string
        if (idx < decryptedChunks.length - 1) {
          // Remove all '=' padding from intermediate chunks
          cleaned = cleaned.replace(/=+$/, '');
        }
        
        return {
          data: cleaned,
          index: c.index
        };
      });
      
      // Combine chunks
      const combinedBase64 = cleanedChunks.map(c => c.data).join('');
      console.log('Combined base64 length:', combinedBase64.length);
      console.log('First 100 chars of combined:', combinedBase64.substring(0, 100));
      console.log('Last 100 chars of combined:', combinedBase64.substring(Math.max(0, combinedBase64.length - 100)));
      
      // Check for invalid padding - '=' should only be at the very end
      const allEquals = combinedBase64.match(/=/g);
      if (allEquals) {
        const equalsAtEnd = (combinedBase64.slice(-2).match(/=/g) || []).length;
        console.log(`Found ${allEquals.length} '=' characters total, ${equalsAtEnd} at the end`);
        if (allEquals.length > equalsAtEnd) {
          console.warn(`⚠ Warning: Found ${allEquals.length} '=' characters, but only ${equalsAtEnd} at the end`);
          console.warn('This suggests chunks may have been incorrectly concatenated or have padding in the middle');
          // Find where the '=' characters are
          const equalsPositions = [];
          for (let i = 0; i < combinedBase64.length; i++) {
            if (combinedBase64[i] === '=') {
              equalsPositions.push(i);
            }
          }
          console.warn('Positions of all "=" characters:', equalsPositions.slice(0, 10), '...');
        }
      }
      
      // Check for invalid characters in combined string (but don't fail, let base64ToArrayBuffer handle it)
      const invalidCharsCombined = combinedBase64.match(/[^A-Za-z0-9+/=]/g);
      if (invalidCharsCombined) {
        console.warn('Found invalid characters in combined base64:', invalidCharsCombined.length, 'characters');
        console.warn('First few invalid chars:', invalidCharsCombined.slice(0, 20).map(c => `'${c}' (${c.charCodeAt(0)})`));
      }
      
      // Validate combined base64 before converting (test on sample)
      try {
        // Test decode on a sample to ensure format is correct
        const sampleSize = Math.min(10000, combinedBase64.length);
        atob(combinedBase64.substring(0, sampleSize));
        console.log('✓ Combined base64 sample validation passed');
      } catch (e) {
        console.error('Invalid combined base64 sample:', e);
        console.error('Combined base64 preview (first 500 chars):', combinedBase64.substring(0, 500));
        throw new Error(`Combined base64 sample is invalid: ${e.message}`);
      }
      
      console.log('Converting combined base64 to ArrayBuffer...');
      const fileBuffer = base64ToArrayBuffer(combinedBase64);
      console.log('File buffer created, size:', fileBuffer.byteLength);

      // Create blob and download
      const blob = new Blob([fileBuffer], { type: fileData.fileType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileData.fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      console.log('✓ File downloaded successfully');
      return {
        success: true,
        fileName: fileData.fileName
      };
    } catch (error) {
      console.error('Error downloading file:', error);
      console.error('Error details:', {
        name: error.name,
        message: error.message,
        stack: error.stack
      });
      throw error;
    }
  }
}

