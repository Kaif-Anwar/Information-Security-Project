/**
 * Comprehensive Key Exchange Test Script
 * Creates users, tests key exchange, and logs everything
 */

import axios from 'axios';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { connectDB } from './config/database.js';
import { User } from './models/User.js';
import bcrypt from 'bcryptjs';

dotenv.config();

const API_BASE_URL = process.env.API_URL || 'http://localhost:3001/api';

// Test configuration
const TEST_USERS = {
  user1: {
    username: `test_user1_${Date.now()}`,
    password: 'testpass123',
    userId: null,
    publicKey: null,
    token: null
  },
  user2: {
    username: `test_user2_${Date.now()}`,
    password: 'testpass123',
    userId: null,
    publicKey: null,
    token: null
  }
};

// Logging
const log = {
  info: (msg) => console.log(`ℹ️  ${msg}`),
  success: (msg) => console.log(`✅ ${msg}`),
  error: (msg) => console.log(`❌ ${msg}`),
  warn: (msg) => console.log(`⚠️  ${msg}`),
  debug: (msg) => console.log(`🔍 ${msg}`),
  section: (msg) => {
    console.log(`\n${'='.repeat(70)}`);
    console.log(`📋 ${msg}`);
    console.log('='.repeat(70));
  }
};

// Cleanup function
async function cleanup() {
  log.section('CLEANUP');
  try {
    for (const userKey of ['user1', 'user2']) {
      if (TEST_USERS[userKey].userId) {
        await User.findByIdAndDelete(TEST_USERS[userKey].userId);
        log.info(`Deleted ${userKey}: ${TEST_USERS[userKey].username}`);
      }
    }
  } catch (error) {
    log.error(`Cleanup error: ${error.message}`);
  }
}

// Step 1: Create test users
async function createUsers() {
  log.section('STEP 1: CREATING TEST USERS');
  
  for (const userKey of ['user1', 'user2']) {
    const user = TEST_USERS[userKey];
    try {
      const passwordHash = await bcrypt.hash(user.password, 10);
      const publicKey = JSON.stringify({
        encryption: `test_encryption_key_${userKey}_base64_encoded`,
        signing: `test_signing_key_${userKey}_base64_encoded`
      });
      
      const newUser = new User({
        username: user.username,
        passwordHash: passwordHash,
        publicKey: publicKey
      });
      
      await newUser.save();
      user.userId = newUser._id.toString();
      user.publicKey = publicKey;
      
      log.success(`${userKey} created: ${user.username} (ID: ${user.userId})`);
    } catch (error) {
      log.error(`Failed to create ${userKey}: ${error.message}`);
      throw error;
    }
  }
  
  return TEST_USERS;
}

// Step 2: Login as both users
async function loginUsers() {
  log.section('STEP 2: LOGGING IN USERS');
  
  for (const userKey of ['user1', 'user2']) {
    const user = TEST_USERS[userKey];
    try {
      log.debug(`Logging in ${userKey}: ${user.username}`);
      
      const response = await axios.post(`${API_BASE_URL}/auth/login`, {
        username: user.username,
        password: user.password
      });
      
      if (response.data.userId) {
        user.userId = response.data.userId;
        log.success(`${userKey} logged in successfully (ID: ${user.userId})`);
        log.debug(`Response: ${JSON.stringify(response.data, null, 2)}`);
      } else {
        throw new Error('No userId in response');
      }
    } catch (error) {
      log.error(`Login failed for ${userKey}: ${error.response?.data?.error || error.message}`);
      if (error.response) {
        log.debug(`Status: ${error.response.status}`);
        log.debug(`Response: ${JSON.stringify(error.response.data, null, 2)}`);
      }
      throw error;
    }
  }
}

// Step 3: Test key exchange initiation
async function testKeyExchange() {
  log.section('STEP 3: TESTING KEY EXCHANGE');
  
  const sender = TEST_USERS.user1;
  const receiver = TEST_USERS.user2;
  
  log.info(`Sender: ${sender.username} (${sender.userId})`);
  log.info(`Receiver: ${receiver.username} (${receiver.userId})`);
  
  // Create axios instance with auth header
  const apiClient = axios.create({
    baseURL: API_BASE_URL,
    headers: {
      'Content-Type': 'application/json',
      'x-user-id': sender.userId
    }
  });
  
  // Add request interceptor to log what's being sent
  apiClient.interceptors.request.use(
    (config) => {
      log.debug('REQUEST INTERCEPTOR:');
      log.debug(`  URL: ${config.url}`);
      log.debug(`  Method: ${config.method}`);
      log.debug(`  Headers: ${JSON.stringify(config.headers, null, 2)}`);
      log.debug(`  Data: ${JSON.stringify(config.data, null, 2)}`);
      return config;
    },
    (error) => {
      log.error(`Request interceptor error: ${error.message}`);
      return Promise.reject(error);
    }
  );
  
  // Add response interceptor to log responses
  apiClient.interceptors.response.use(
    (response) => {
      log.debug('RESPONSE INTERCEPTOR:');
      log.debug(`  Status: ${response.status}`);
      log.debug(`  Headers: ${JSON.stringify(response.headers, null, 2)}`);
      log.debug(`  Data: ${JSON.stringify(response.data, null, 2)}`);
      return response;
    },
    (error) => {
      log.error('RESPONSE ERROR INTERCEPTOR:');
      if (error.response) {
        log.error(`  Status: ${error.response.status}`);
        log.error(`  Headers: ${JSON.stringify(error.response.headers, null, 2)}`);
        log.error(`  Data: ${JSON.stringify(error.response.data, null, 2)}`);
      } else {
        log.error(`  Error: ${error.message}`);
      }
      return Promise.reject(error);
    }
  );
  
  // Prepare key exchange payload
  const payload = {
    receiverId: receiver.userId,
    publicKey: 'test_public_key_base64_encoded_string',
    ephemeralPublicKey: 'test_ephemeral_public_key_base64_encoded_string',
    signature: 'test_signature_base64_encoded_string',
    timestamp: Date.now(),
    nonce: 'test_nonce_base64_encoded_string'
  };
  
  log.info('Attempting key exchange initiation...');
  log.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);
  log.debug(`Auth Header (x-user-id): ${sender.userId}`);
  
  try {
    const response = await apiClient.post('/key-exchange/initiate', payload);
    
    log.success('✅ KEY EXCHANGE SUCCEEDED!');
    log.debug(`Response: ${JSON.stringify(response.data, null, 2)}`);
    return response.data;
  } catch (error) {
    log.error('❌ KEY EXCHANGE FAILED!');
    
    if (error.response) {
      log.error(`Status Code: ${error.response.status}`);
      log.error(`Error Message: ${error.response.data?.error || 'Unknown error'}`);
      
      // Detailed error analysis
      if (error.response.status === 401) {
        log.warn('401 Unauthorized - This means:');
        log.warn('  1. Auth header (x-user-id) was NOT received by server, OR');
        log.warn('  2. Auth header was received but signature verification failed');
        log.warn('  Check server logs to see which one!');
      }
      
      log.debug(`Full error response: ${JSON.stringify(error.response.data, null, 2)}`);
    } else if (error.request) {
      log.error('No response received from server');
      log.error(`Request: ${JSON.stringify(error.request, null, 2)}`);
    } else {
      log.error(`Request setup error: ${error.message}`);
    }
    
    throw error;
  }
}

// Step 4: Test without auth header (should fail)
async function testWithoutHeader() {
  log.section('STEP 4: TESTING WITHOUT AUTH HEADER (Should Fail)');
  
  const sender = TEST_USERS.user1;
  const receiver = TEST_USERS.user2;
  
  const apiClient = axios.create({
    baseURL: API_BASE_URL,
    headers: {
      'Content-Type': 'application/json'
      // NO x-user-id header
    }
  });
  
  const payload = {
    receiverId: receiver.userId,
    publicKey: 'test_public_key',
    ephemeralPublicKey: 'test_ephemeral',
    signature: 'test_signature',
    timestamp: Date.now(),
    nonce: 'test_nonce'
  };
  
  try {
    await apiClient.post('/key-exchange/initiate', payload);
    log.error('❌ Request succeeded without header - THIS IS A BUG!');
  } catch (error) {
    if (error.response?.status === 401) {
      log.success('✅ Correctly rejected request without auth header');
    } else {
      log.error(`Unexpected error: ${error.message}`);
    }
  }
}

// Step 5: Test with different header formats
async function testHeaderFormats() {
  log.section('STEP 5: TESTING DIFFERENT HEADER FORMATS');
  
  const sender = TEST_USERS.user1;
  const receiver = TEST_USERS.user2;
  
  const formats = [
    { name: 'lowercase x-user-id', header: 'x-user-id', value: sender.userId },
    { name: 'uppercase X-User-Id', header: 'X-User-Id', value: sender.userId },
    { name: 'mixed case X-User-ID', header: 'X-User-ID', value: sender.userId }
  ];
  
  for (const format of formats) {
    log.info(`Testing with ${format.name}...`);
    
    const apiClient = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
        [format.header]: format.value
      }
    });
    
    const payload = {
      receiverId: receiver.userId,
      publicKey: 'test_key',
      ephemeralPublicKey: 'test_ephemeral',
      signature: 'test_signature',
      timestamp: Date.now(),
      nonce: 'test_nonce'
    };
    
    try {
      await apiClient.post('/key-exchange/initiate', payload);
      log.success(`✅ ${format.name} worked!`);
    } catch (error) {
      if (error.response?.status === 401) {
        log.warn(`⚠️  ${format.name} failed with 401`);
      } else {
        log.error(`❌ ${format.name} failed: ${error.message}`);
      }
    }
  }
}

// Main test runner
async function runTests() {
  log.section('KEY EXCHANGE COMPREHENSIVE TEST');
  log.info(`API Base URL: ${API_BASE_URL}`);
  log.info(`Timestamp: ${new Date().toISOString()}`);
  
  try {
    // Connect to database
    await connectDB();
    log.success('Connected to database');
    
    // Run tests
    await createUsers();
    await loginUsers();
    await testKeyExchange();
    await testWithoutHeader();
    await testHeaderFormats();
    
    log.section('TEST SUMMARY');
    log.success('All tests completed!');
    log.info('Check the logs above for detailed information.');
    log.info('If key exchange failed, check:');
    log.info('  1. Server terminal logs for auth middleware output');
    log.info('  2. Whether CORS is blocking the header');
    log.info('  3. Whether the header format is correct');
    
  } catch (error) {
    log.error(`Test suite failed: ${error.message}`);
    console.error('Full error:', error);
  } finally {
    await cleanup();
    await mongoose.connection.close();
    log.info('Database connection closed');
  }
}

// Run the tests
runTests()
  .then(() => {
    log.success('Test script completed');
    process.exit(0);
  })
  .catch((error) => {
    log.error(`Test script failed: ${error.message}`);
    process.exit(1);
  });

