/**
 * Test script for Replay Attack Detection and Invalid Signature Logging
 * 
 * Tests:
 * 1. Replay attack detection (duplicate nonce, sequence number, old timestamp, future timestamp)
 * 2. Invalid signature logging (server-side verification and client-side reporting)
 */

import axios from 'axios';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { connectDB } from './config/database.js';
import { User } from './models/User.js';
import { Message } from './models/Message.js';
import { SecurityLog } from './models/SecurityLog.js';
import bcrypt from 'bcryptjs';

dotenv.config();

const API_BASE_URL = process.env.API_URL || 'http://localhost:3001/api';

// Test configuration
const TEST_CONFIG = {
  user1: {
    username: 'test_user1_' + Date.now(),
    password: 'testpass123',
    userId: null,
    authHeader: null
  },
  user2: {
    username: 'test_user2_' + Date.now(),
    password: 'testpass123',
    userId: null,
    authHeader: null
  }
};

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logTest(name) {
  log(`\n${'='.repeat(60)}`, colors.cyan);
  log(`TEST: ${name}`, colors.cyan);
  log('='.repeat(60), colors.cyan);
}

function logSuccess(message) {
  log(`✅ ${message}`, colors.green);
}

function logError(message) {
  log(`❌ ${message}`, colors.red);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, colors.blue);
}

// Helper function to create axios instance with auth
function createApiClient(userId) {
  return axios.create({
    baseURL: API_BASE_URL,
    headers: {
      'Content-Type': 'application/json',
      'x-user-id': userId
    }
  });
}

// Setup: Create test users
async function setupTestUsers() {
  logTest('SETUP: Creating Test Users');
  
  try {
    // Create user1
    const passwordHash1 = await bcrypt.hash(TEST_CONFIG.user1.password, 10);
    const publicKey1 = JSON.stringify({
      encryption: 'test_encryption_key_1',
      signing: 'test_signing_key_1'
    });
    
    const user1 = new User({
      username: TEST_CONFIG.user1.username,
      passwordHash: passwordHash1,
      publicKey: publicKey1
    });
    await user1.save();
    TEST_CONFIG.user1.userId = user1._id.toString();
    TEST_CONFIG.user1.authHeader = TEST_CONFIG.user1.userId;
    logSuccess(`User 1 created: ${TEST_CONFIG.user1.username} (ID: ${TEST_CONFIG.user1.userId})`);

    // Create user2
    const passwordHash2 = await bcrypt.hash(TEST_CONFIG.user2.password, 10);
    const publicKey2 = JSON.stringify({
      encryption: 'test_encryption_key_2',
      signing: 'test_signing_key_2'
    });
    
    const user2 = new User({
      username: TEST_CONFIG.user2.username,
      passwordHash: passwordHash2,
      publicKey: publicKey2
    });
    await user2.save();
    TEST_CONFIG.user2.userId = user2._id.toString();
    TEST_CONFIG.user2.authHeader = TEST_CONFIG.user2.userId;
    logSuccess(`User 2 created: ${TEST_CONFIG.user2.username} (ID: ${TEST_CONFIG.user2.userId})`);

    return true;
  } catch (error) {
    logError(`Failed to create test users: ${error.message}`);
    return false;
  }
}

// Test 1: Replay Attack - Duplicate Nonce
async function testReplayAttackDuplicateNonce() {
  logTest('REPLAY ATTACK: Duplicate Nonce Detection');
  
  const api = createApiClient(TEST_CONFIG.user1.userId);
  const receiverId = TEST_CONFIG.user2.userId;
  const nonce = 'test_nonce_' + Date.now();
  const sequenceNumber = 1;
  const timestamp = Date.now();

  try {
    // Send first message (should succeed)
    const message1 = {
      receiverId,
      ciphertext: 'encrypted_message_1',
      iv: 'test_iv_1',
      authTag: 'test_auth_tag_1',
      sequenceNumber,
      nonce,
      timestamp
    };

    const response1 = await api.post('/messages/send', message1);
    logSuccess(`First message sent successfully: ${response1.data.messageId}`);

    // Try to send same message again with same nonce (should fail)
    const message2 = {
      receiverId,
      ciphertext: 'encrypted_message_2',
      iv: 'test_iv_2',
      authTag: 'test_auth_tag_2',
      sequenceNumber: 2,
      nonce, // Same nonce!
      timestamp: Date.now()
    };

    try {
      await api.post('/messages/send', message2);
      logError('Replay attack NOT detected - duplicate nonce was accepted!');
      return false;
    } catch (error) {
      if (error.response && error.response.status === 409) {
        logSuccess('Replay attack detected: Duplicate nonce rejected (409 Conflict)');
        
        // Verify log was created
        const logs = await SecurityLog.find({
          eventType: 'REPLAY_DETECTED',
          userId: TEST_CONFIG.user1.userId,
          'details.reason': 'Duplicate nonce detected'
        }).sort({ timestamp: -1 }).limit(1);
        
        if (logs.length > 0) {
          logSuccess(`Security log created: ${logs[0]._id}`);
          logInfo(`Log details: ${JSON.stringify(logs[0].details, null, 2)}`);
          return true;
        } else {
          logError('Replay attack detected but no security log was created!');
          return false;
        }
      } else {
        logError(`Unexpected error: ${error.message}`);
        return false;
      }
    }
  } catch (error) {
    logError(`Test failed: ${error.message}`);
    if (error.response) {
      logError(`Response: ${JSON.stringify(error.response.data, null, 2)}`);
    }
    return false;
  }
}

// Test 2: Replay Attack - Duplicate Sequence Number
async function testReplayAttackDuplicateSequence() {
  logTest('REPLAY ATTACK: Duplicate Sequence Number Detection');
  
  const api = createApiClient(TEST_CONFIG.user1.userId);
  const receiverId = TEST_CONFIG.user2.userId;
  const sequenceNumber = 100;
  const timestamp = Date.now();

  try {
    // Send first message
    const message1 = {
      receiverId,
      ciphertext: 'encrypted_message_1',
      iv: 'test_iv_1',
      authTag: 'test_auth_tag_1',
      sequenceNumber,
      nonce: 'unique_nonce_1_' + Date.now(),
      timestamp
    };

    await api.post('/messages/send', message1);
    logSuccess('First message sent successfully');

    // Try to send message with same sequence number
    const message2 = {
      receiverId,
      ciphertext: 'encrypted_message_2',
      iv: 'test_iv_2',
      authTag: 'test_auth_tag_2',
      sequenceNumber, // Same sequence number!
      nonce: 'unique_nonce_2_' + Date.now(),
      timestamp: Date.now()
    };

    try {
      await api.post('/messages/send', message2);
      logError('Replay attack NOT detected - duplicate sequence number was accepted!');
      return false;
    } catch (error) {
      if (error.response && error.response.status === 409) {
        logSuccess('Replay attack detected: Duplicate sequence number rejected (409 Conflict)');
        
        const logs = await SecurityLog.find({
          eventType: 'REPLAY_DETECTED',
          userId: TEST_CONFIG.user1.userId,
          'details.reason': 'Duplicate sequence number detected'
        }).sort({ timestamp: -1 }).limit(1);
        
        if (logs.length > 0) {
          logSuccess(`Security log created: ${logs[0]._id}`);
          return true;
        } else {
          logError('Replay attack detected but no security log was created!');
          return false;
        }
      } else {
        logError(`Unexpected error: ${error.message}`);
        return false;
      }
    }
  } catch (error) {
    logError(`Test failed: ${error.message}`);
    return false;
  }
}

// Test 3: Replay Attack - Old Timestamp
async function testReplayAttackOldTimestamp() {
  logTest('REPLAY ATTACK: Old Timestamp Detection');
  
  const api = createApiClient(TEST_CONFIG.user1.userId);
  const receiverId = TEST_CONFIG.user2.userId;
  const oldTimestamp = Date.now() - (6 * 60 * 1000); // 6 minutes ago (older than 5 min limit)

  try {
    const message = {
      receiverId,
      ciphertext: 'encrypted_message',
      iv: 'test_iv',
      authTag: 'test_auth_tag',
      sequenceNumber: 200,
      nonce: 'unique_nonce_' + Date.now(),
      timestamp: oldTimestamp
    };

    try {
      await api.post('/messages/send', message);
      logError('Replay attack NOT detected - old timestamp was accepted!');
      return false;
    } catch (error) {
      if (error.response && error.response.status === 409) {
        logSuccess('Replay attack detected: Old timestamp rejected (409 Conflict)');
        
        const logs = await SecurityLog.find({
          eventType: 'REPLAY_DETECTED',
          userId: TEST_CONFIG.user1.userId,
          'details.reason': 'Message timestamp too old'
        }).sort({ timestamp: -1 }).limit(1);
        
        if (logs.length > 0) {
          logSuccess(`Security log created: ${logs[0]._id}`);
          return true;
        } else {
          logError('Replay attack detected but no security log was created!');
          return false;
        }
      } else {
        logError(`Unexpected error: ${error.message}`);
        return false;
      }
    }
  } catch (error) {
    logError(`Test failed: ${error.message}`);
    return false;
  }
}

// Test 4: Replay Attack - Future Timestamp
async function testReplayAttackFutureTimestamp() {
  logTest('REPLAY ATTACK: Future Timestamp Detection');
  
  const api = createApiClient(TEST_CONFIG.user1.userId);
  const receiverId = TEST_CONFIG.user2.userId;
  const futureTimestamp = Date.now() + (2 * 60 * 1000); // 2 minutes in future

  try {
    const message = {
      receiverId,
      ciphertext: 'encrypted_message',
      iv: 'test_iv',
      authTag: 'test_auth_tag',
      sequenceNumber: 300,
      nonce: 'unique_nonce_' + Date.now(),
      timestamp: futureTimestamp
    };

    try {
      await api.post('/messages/send', message);
      logError('Replay attack NOT detected - future timestamp was accepted!');
      return false;
    } catch (error) {
      if (error.response && error.response.status === 409) {
        logSuccess('Replay attack detected: Future timestamp rejected (409 Conflict)');
        
        const logs = await SecurityLog.find({
          eventType: 'REPLAY_DETECTED',
          userId: TEST_CONFIG.user1.userId,
          'details.reason': 'Message timestamp in future'
        }).sort({ timestamp: -1 }).limit(1);
        
        if (logs.length > 0) {
          logSuccess(`Security log created: ${logs[0]._id}`);
          return true;
        } else {
          logError('Replay attack detected but no security log was created!');
          return false;
        }
      } else {
        logError(`Unexpected error: ${error.message}`);
        return false;
      }
    }
  } catch (error) {
    logError(`Test failed: ${error.message}`);
    return false;
  }
}

// Test 5: Invalid Signature - Client-side Reporting (Messages)
async function testInvalidSignatureClientReportingMessages() {
  logTest('INVALID SIGNATURE: Client-side Reporting (Messages)');
  
  const api = createApiClient(TEST_CONFIG.user1.userId);

  try {
    const report = {
      context: 'message_verification',
      reason: 'Signature verification failed - invalid signature format',
      signature: 'invalid_signature_base64',
      data: 'test_message_data'
    };

    const response = await api.post('/messages/invalid-signature', report);
    logSuccess(`Invalid signature reported: ${response.data.message}`);

    // Verify log was created
    const logs = await SecurityLog.find({
      eventType: 'INVALID_SIGNATURE',
      userId: TEST_CONFIG.user1.userId,
      'details.context': 'message_verification'
    }).sort({ timestamp: -1 }).limit(1);

    if (logs.length > 0) {
      logSuccess(`Security log created: ${logs[0]._id}`);
      logInfo(`Log details: ${JSON.stringify(logs[0].details, null, 2)}`);
      return true;
    } else {
      logError('Invalid signature reported but no security log was created!');
      return false;
    }
  } catch (error) {
    logError(`Test failed: ${error.message}`);
    if (error.response) {
      logError(`Response: ${JSON.stringify(error.response.data, null, 2)}`);
    }
    return false;
  }
}

// Test 6: Invalid Signature - Client-side Reporting (Key Exchange)
async function testInvalidSignatureClientReportingKeyExchange() {
  logTest('INVALID SIGNATURE: Client-side Reporting (Key Exchange)');
  
  const api = createApiClient(TEST_CONFIG.user1.userId);

  try {
    const report = {
      context: 'key_exchange_initiate',
      reason: 'Signature verification failed - signature does not match',
      signature: 'invalid_signature_base64',
      data: 'key_exchange_data',
      otherUserId: TEST_CONFIG.user2.userId
    };

    const response = await api.post('/key-exchange/invalid-signature', report);
    logSuccess(`Invalid signature reported: ${response.data.message}`);

    // Verify log was created
    const logs = await SecurityLog.find({
      eventType: 'INVALID_SIGNATURE',
      userId: TEST_CONFIG.user1.userId,
      'details.context': 'key_exchange_initiate'
    }).sort({ timestamp: -1 }).limit(1);

    if (logs.length > 0) {
      logSuccess(`Security log created: ${logs[0]._id}`);
      logInfo(`Log details: ${JSON.stringify(logs[0].details, null, 2)}`);
      return true;
    } else {
      logError('Invalid signature reported but no security log was created!');
      return false;
    }
  } catch (error) {
    logError(`Test failed: ${error.message}`);
    if (error.response) {
      logError(`Response: ${JSON.stringify(error.response.data, null, 2)}`);
    }
    return false;
  }
}

// Test 7: Invalid Signature - Server-side Verification (Key Exchange with invalid timestamp)
async function testInvalidSignatureServerSideTimestamp() {
  logTest('INVALID SIGNATURE: Server-side Verification (Invalid Timestamp)');
  
  const api = createApiClient(TEST_CONFIG.user1.userId);
  const receiverId = TEST_CONFIG.user2.userId;

  try {
    // Try key exchange with invalid (old) timestamp
    const oldTimestamp = Date.now() - (6 * 60 * 1000); // 6 minutes ago
    
    const keyExchange = {
      receiverId,
      publicKey: 'test_public_key',
      ephemeralPublicKey: 'test_ephemeral_key',
      signature: 'test_signature',
      timestamp: oldTimestamp, // Invalid timestamp
      nonce: 'test_nonce_' + Date.now()
    };

    try {
      await api.post('/key-exchange/initiate', keyExchange);
      logError('Invalid signature NOT detected - old timestamp was accepted!');
      return false;
    } catch (error) {
      if (error.response && error.response.status === 400) {
        logSuccess('Invalid signature detected: Invalid timestamp rejected (400 Bad Request)');
        
        // Verify log was created
        const logs = await SecurityLog.find({
          eventType: 'INVALID_SIGNATURE',
          userId: TEST_CONFIG.user1.userId,
          'details.context': 'key_exchange_initiate',
          'details.reason': 'Invalid timestamp'
        }).sort({ timestamp: -1 }).limit(1);

        if (logs.length > 0) {
          logSuccess(`Security log created: ${logs[0]._id}`);
          return true;
        } else {
          logError('Invalid signature detected but no security log was created!');
          return false;
        }
      } else {
        logError(`Unexpected error: ${error.message}`);
        return false;
      }
    }
  } catch (error) {
    logError(`Test failed: ${error.message}`);
    return false;
  }
}

// Cleanup: Remove test data
async function cleanup() {
  logTest('CLEANUP: Removing Test Data');
  
  try {
    // Remove test users
    await User.deleteMany({
      username: { $in: [TEST_CONFIG.user1.username, TEST_CONFIG.user2.username] }
    });
    logSuccess('Test users removed');

    // Remove test messages
    await Message.deleteMany({
      $or: [
        { senderId: TEST_CONFIG.user1.userId },
        { senderId: TEST_CONFIG.user2.userId },
        { receiverId: TEST_CONFIG.user1.userId },
        { receiverId: TEST_CONFIG.user2.userId }
      ]
    });
    logSuccess('Test messages removed');

    // Note: We keep security logs for verification
    logInfo('Security logs preserved for verification');
    
    return true;
  } catch (error) {
    logError(`Cleanup failed: ${error.message}`);
    return false;
  }
}

// Summary: Show all security logs created during tests
async function showSecurityLogsSummary() {
  logTest('SECURITY LOGS SUMMARY');
  
  try {
    const replayLogs = await SecurityLog.find({
      eventType: 'REPLAY_DETECTED',
      userId: { $in: [TEST_CONFIG.user1.userId, TEST_CONFIG.user2.userId] }
    }).sort({ timestamp: -1 });

    const invalidSigLogs = await SecurityLog.find({
      eventType: 'INVALID_SIGNATURE',
      userId: { $in: [TEST_CONFIG.user1.userId, TEST_CONFIG.user2.userId] }
    }).sort({ timestamp: -1 });

    logInfo(`\nReplay Attack Logs: ${replayLogs.length}`);
    replayLogs.forEach((log, index) => {
      console.log(`  ${index + 1}. ${log.details.reason} - ${log.timestamp}`);
    });

    logInfo(`\nInvalid Signature Logs: ${invalidSigLogs.length}`);
    invalidSigLogs.forEach((log, index) => {
      console.log(`  ${index + 1}. ${log.details.context} - ${log.details.reason} - ${log.timestamp}`);
    });

    return true;
  } catch (error) {
    logError(`Failed to show summary: ${error.message}`);
    return false;
  }
}

// Main test runner
async function runTests() {
  log('\n' + '='.repeat(60), colors.cyan);
  log('SECURITY LOGGING TEST SUITE', colors.cyan);
  log('Testing Replay Attack Detection & Invalid Signature Logging', colors.cyan);
  log('='.repeat(60) + '\n', colors.cyan);

  try {
    // Connect to database
    await connectDB();
    logSuccess('Connected to database');

    // Setup
    const setupSuccess = await setupTestUsers();
    if (!setupSuccess) {
      logError('Setup failed. Exiting.');
      process.exit(1);
    }

    // Run tests
    const results = {
      passed: 0,
      failed: 0,
      tests: []
    };

    // Replay Attack Tests
    results.tests.push({ name: 'Replay Attack - Duplicate Nonce', result: await testReplayAttackDuplicateNonce() });
    results.tests.push({ name: 'Replay Attack - Duplicate Sequence', result: await testReplayAttackDuplicateSequence() });
    results.tests.push({ name: 'Replay Attack - Old Timestamp', result: await testReplayAttackOldTimestamp() });
    results.tests.push({ name: 'Replay Attack - Future Timestamp', result: await testReplayAttackFutureTimestamp() });

    // Invalid Signature Tests
    results.tests.push({ name: 'Invalid Signature - Client Reporting (Messages)', result: await testInvalidSignatureClientReportingMessages() });
    results.tests.push({ name: 'Invalid Signature - Client Reporting (Key Exchange)', result: await testInvalidSignatureClientReportingKeyExchange() });
    results.tests.push({ name: 'Invalid Signature - Server-side Timestamp', result: await testInvalidSignatureServerSideTimestamp() });

    // Count results
    results.tests.forEach(test => {
      if (test.result) {
        results.passed++;
      } else {
        results.failed++;
      }
    });

    // Show summary
    await showSecurityLogsSummary();

    // Final results
    logTest('TEST RESULTS');
    logInfo(`Total Tests: ${results.tests.length}`);
    logSuccess(`Passed: ${results.passed}`);
    if (results.failed > 0) {
      logError(`Failed: ${results.failed}`);
    }

    results.tests.forEach(test => {
      if (test.result) {
        logSuccess(`✓ ${test.name}`);
      } else {
        logError(`✗ ${test.name}`);
      }
    });

    // Cleanup
    await cleanup();

    // Exit
    if (results.failed === 0) {
      log('\n✅ ALL TESTS PASSED!', colors.green);
      process.exit(0);
    } else {
      log('\n❌ SOME TESTS FAILED', colors.red);
      process.exit(1);
    }
  } catch (error) {
    logError(`Fatal error: ${error.message}`);
    console.error(error);
    process.exit(1);
  }
}

// Run tests
runTests();

