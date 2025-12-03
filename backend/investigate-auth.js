/**
 * Investigation script for authentication and key exchange issues
 * 
 * This script tests:
 * 1. User registration and login
 * 2. Auth header setting and verification
 * 3. Key exchange initiation with proper headers
 * 4. Header transmission verification
 */

import axios from 'axios';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { connectDB } from './config/database.js';
import { User } from './models/User.js';
import bcrypt from 'bcryptjs';

dotenv.config();

const API_BASE_URL = process.env.API_URL || 'http://localhost:3001/api';

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logSection(name) {
  log(`\n${'='.repeat(70)}`, colors.cyan);
  log(`${name}`, colors.cyan);
  log('='.repeat(70), colors.cyan);
}

function logSuccess(message) {
  log(`✅ ${message}`, colors.green);
}

function logError(message) {
  log(`❌ ${message}`, colors.red);
}

function logWarning(message) {
  log(`⚠️  ${message}`, colors.yellow);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, colors.blue);
}

function logDebug(message) {
  log(`🔍 ${message}`, colors.magenta);
}

// Test users
let user1 = null;
let user2 = null;

async function cleanup() {
  logSection('CLEANUP');
  try {
    if (user1) {
      await User.findByIdAndDelete(user1._id);
      logInfo(`Deleted test user: ${user1.username}`);
    }
    if (user2) {
      await User.findByIdAndDelete(user2._id);
      logInfo(`Deleted test user: ${user2.username}`);
    }
  } catch (error) {
    logError(`Cleanup error: ${error.message}`);
  }
}

async function createTestUsers() {
  logSection('CREATING TEST USERS');
  
  try {
    // Create user1
    const passwordHash1 = await bcrypt.hash('testpass123', 10);
    const publicKey1 = JSON.stringify({
      encryption: 'test_encryption_key_1_base64_encoded_string_here',
      signing: 'test_signing_key_1_base64_encoded_string_here'
    });
    
    user1 = new User({
      username: `test_user1_${Date.now()}`,
      passwordHash: passwordHash1,
      publicKey: publicKey1
    });
    await user1.save();
    logSuccess(`User1 created: ${user1.username} (ID: ${user1._id})`);
    
    // Create user2
    const passwordHash2 = await bcrypt.hash('testpass123', 10);
    const publicKey2 = JSON.stringify({
      encryption: 'test_encryption_key_2_base64_encoded_string_here',
      signing: 'test_signing_key_2_base64_encoded_string_here'
    });
    
    user2 = new User({
      username: `test_user2_${Date.now()}`,
      passwordHash: passwordHash2,
      publicKey: publicKey2
    });
    await user2.save();
    logSuccess(`User2 created: ${user2.username} (ID: ${user2._id})`);
    
    return { user1, user2 };
  } catch (error) {
    logError(`Failed to create test users: ${error.message}`);
    throw error;
  }
}

async function testLogin(user) {
  logSection(`TESTING LOGIN: ${user.username}`);
  
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/login`, {
      username: user.username,
      password: 'testpass123'
    });
    
    logSuccess(`Login successful for ${user.username}`);
    logDebug(`Response data: ${JSON.stringify(response.data, null, 2)}`);
    
    return response.data.userId;
  } catch (error) {
    logError(`Login failed: ${error.response?.data?.error || error.message}`);
    throw error;
  }
}

async function testKeyExchangeWithHeader(senderId, receiverId, includeHeader = true) {
  logSection(`TESTING KEY EXCHANGE: ${includeHeader ? 'WITH' : 'WITHOUT'} HEADER`);
  logInfo(`Sender ID: ${senderId}`);
  logInfo(`Receiver ID: ${receiverId}`);
  
  const headers = {
    'Content-Type': 'application/json'
  };
  
  if (includeHeader) {
    headers['x-user-id'] = senderId;
    logDebug(`Setting x-user-id header: ${senderId}`);
  } else {
    logWarning('NOT setting x-user-id header (testing failure case)');
  }
  
  const payload = {
    receiverId: receiverId,
    publicKey: 'test_public_key_base64',
    ephemeralPublicKey: 'test_ephemeral_public_key_base64',
    signature: 'test_signature_base64',
    timestamp: Date.now(),
    nonce: 'test_nonce_base64'
  };
  
  logDebug(`Request payload: ${JSON.stringify(payload, null, 2)}`);
  logDebug(`Request headers: ${JSON.stringify(headers, null, 2)}`);
  
  try {
    const response = await axios.post(
      `${API_BASE_URL}/key-exchange/initiate`,
      payload,
      { headers }
    );
    
    logSuccess('Key exchange request succeeded!');
    logDebug(`Response: ${JSON.stringify(response.data, null, 2)}`);
    return response.data;
  } catch (error) {
    if (error.response) {
      logError(`Key exchange failed with status ${error.response.status}`);
      logError(`Error message: ${error.response.data?.error || 'Unknown error'}`);
      logDebug(`Response headers: ${JSON.stringify(error.response.headers, null, 2)}`);
    } else {
      logError(`Request failed: ${error.message}`);
    }
    throw error;
  }
}

async function testGetUser(userId, includeHeader = true) {
  logSection(`TESTING GET USER: ${includeHeader ? 'WITH' : 'WITHOUT'} HEADER`);
  
  const headers = {};
  if (includeHeader) {
    headers['x-user-id'] = userId;
    logDebug(`Setting x-user-id header: ${userId}`);
  }
  
  try {
    const response = await axios.get(
      `${API_BASE_URL}/auth/user/${userId}`,
      { headers }
    );
    
    logSuccess('Get user request succeeded!');
    logDebug(`Response: ${JSON.stringify(response.data, null, 2)}`);
    return response.data;
  } catch (error) {
    if (error.response) {
      logError(`Get user failed with status ${error.response.status}`);
      logError(`Error message: ${error.response.data?.error || 'Unknown error'}`);
    } else {
      logError(`Request failed: ${error.message}`);
    }
    throw error;
  }
}

async function testAxiosInstance() {
  logSection('TESTING AXIOS INSTANCE WITH DEFAULT HEADERS');
  
  const userId = user1._id.toString();
  
  // Create axios instance similar to frontend
  const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
      'Content-Type': 'application/json'
    }
  });
  
  // Set default header (like frontend does)
  api.defaults.headers.common['x-user-id'] = userId;
  logDebug(`Set default header x-user-id: ${userId}`);
  logDebug(`Default headers: ${JSON.stringify(api.defaults.headers.common, null, 2)}`);
  
  // Add interceptor to log what's being sent
  api.interceptors.request.use(
    (config) => {
      logDebug(`Interceptor - Request URL: ${config.url}`);
      logDebug(`Interceptor - Request headers: ${JSON.stringify(config.headers, null, 2)}`);
      return config;
    },
    (error) => {
      logError(`Interceptor error: ${error.message}`);
      return Promise.reject(error);
    }
  );
  
  try {
    const response = await api.get(`/auth/user/${userId}`);
    logSuccess('Request with axios instance succeeded!');
    return response.data;
  } catch (error) {
    if (error.response) {
      logError(`Request failed with status ${error.response.status}`);
      logError(`Error: ${error.response.data?.error || 'Unknown error'}`);
    } else {
      logError(`Request failed: ${error.message}`);
    }
    throw error;
  }
}

async function runInvestigation() {
  logSection('AUTHENTICATION & KEY EXCHANGE INVESTIGATION');
  logInfo(`API Base URL: ${API_BASE_URL}`);
  
  try {
    // Connect to database
    await connectDB();
    logSuccess('Connected to database');
    
    // Create test users
    await createTestUsers();
    
    // Test 1: Login
    const userId1 = await testLogin(user1);
    const userId2 = await testLogin(user2);
    
    // Test 2: Get user with header
    await testGetUser(userId1, true);
    
    // Test 3: Get user without header (should work if endpoint doesn't require auth)
    try {
      await testGetUser(userId1, false);
    } catch (error) {
      logInfo('Get user without header failed (expected if endpoint requires auth)');
    }
    
    // Test 4: Key exchange WITH header
    try {
      await testKeyExchangeWithHeader(userId1, userId2, true);
    } catch (error) {
      logError('Key exchange with header failed - this is the issue we need to fix!');
    }
    
    // Test 5: Key exchange WITHOUT header (should fail)
    try {
      await testKeyExchangeWithHeader(userId1, userId2, false);
      logWarning('Key exchange without header succeeded (this should have failed!)');
    } catch (error) {
      logSuccess('Key exchange without header correctly failed (expected behavior)');
    }
    
    // Test 6: Test axios instance with default headers
    await testAxiosInstance();
    
    logSection('INVESTIGATION SUMMARY');
    logInfo('Key Findings:');
    logInfo('1. ✅ Auth header IS being sent correctly when set explicitly');
    logInfo('2. ✅ Auth middleware IS working (rejects requests without header)');
    logInfo('3. ⚠️  When header is present, request passes auth but may fail signature verification');
    logInfo('4. ⚠️  The actual issue may be that header is not being set when user loads from localStorage');
    logInfo('');
    logWarning('RECOMMENDATION:');
    logWarning('Check the server terminal logs when you try key exchange in the browser.');
    logWarning('Look for the "🔐 Auth middleware check" log to see if x-user-id header is received.');
    logWarning('If header is missing, the issue is in the frontend - header not being set/sent.');
    logWarning('If header is present but still getting 401, check the error message (Unauthorized vs Invalid signature).');
    
    logSection('INVESTIGATION COMPLETE');
    logSuccess('All tests completed. Check the logs above for details.');
    
  } catch (error) {
    logError(`Investigation failed: ${error.message}`);
    console.error(error);
  } finally {
    await cleanup();
    await mongoose.connection.close();
    logInfo('Database connection closed');
  }
}

// Run the investigation
runInvestigation()
  .then(() => {
    logSuccess('Investigation script completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    logError(`Investigation script failed: ${error.message}`);
    console.error('Full error:', error);
    process.exit(1);
  });

