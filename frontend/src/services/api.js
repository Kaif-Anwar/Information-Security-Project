/**
 * API Service for backend communication
 */
import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';

// Security: Enforce HTTPS in production
if (import.meta.env.PROD && !API_BASE_URL.startsWith('https://')) {
  console.error('SECURITY WARNING: API URL must use HTTPS in production!');
  throw new Error('HTTPS is required for all API communication in production');
}

// Warn if using HTTP in non-localhost environments
if (!API_BASE_URL.startsWith('https://') && !API_BASE_URL.includes('localhost') && !API_BASE_URL.includes('127.0.0.1')) {
  console.warn('SECURITY WARNING: Using HTTP instead of HTTPS. This is insecure!');
}

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Store current user ID for auth header
let currentUserId = null;

// Add user ID to headers for authentication
export const setAuthHeader = (userId) => {
  currentUserId = userId;
  api.defaults.headers.common['x-user-id'] = userId;
  console.log('Auth header set for userId:', userId);
};

export const clearAuthHeader = () => {
  currentUserId = null;
  delete api.defaults.headers.common['x-user-id'];
  console.log('Auth header cleared');
};

// Debug function to check current auth state
export const getAuthState = () => {
  return {
    currentUserId,
    headerSet: !!api.defaults.headers.common['x-user-id'],
    headerValue: api.defaults.headers.common['x-user-id']
  };
};

// Request interceptor to ensure auth header is always included
api.interceptors.request.use(
  (config) => {
    // Always ensure x-user-id header is set if we have a current user
    // Check multiple sources: currentUserId, defaults.headers.common, and localStorage as last resort
    let userIdToUse = currentUserId || api.defaults.headers.common['x-user-id'];
    
    // Last resort: try to get from localStorage if still missing
    if (!userIdToUse && typeof window !== 'undefined') {
      try {
        const savedUser = localStorage.getItem('user');
        if (savedUser) {
          const userData = JSON.parse(savedUser);
          if (userData?.userId) {
            userIdToUse = userData.userId;
            // Set it for future requests
            currentUserId = userData.userId;
            api.defaults.headers.common['x-user-id'] = userData.userId;
            console.log('🔐 Request interceptor - Recovered userId from localStorage:', userData.userId);
          }
        }
      } catch (e) {
        // Ignore localStorage errors
      }
    }
    
    if (userIdToUse) {
      config.headers['x-user-id'] = userIdToUse;
      // Also update currentUserId if it was missing but found in defaults
      if (!currentUserId && api.defaults.headers.common['x-user-id']) {
        currentUserId = api.defaults.headers.common['x-user-id'];
      }
      console.log('🔐 Request interceptor - Setting x-user-id header:', {
        url: config.url,
        userId: userIdToUse,
        method: config.method,
        source: currentUserId === userIdToUse ? 'currentUserId' : 
                api.defaults.headers.common['x-user-id'] === userIdToUse ? 'defaults.headers' : 'localStorage'
      });
    } else {
      console.error('❌ CRITICAL: Request missing x-user-id header!', {
        url: config.url,
        method: config.method,
        currentUserId: currentUserId,
        defaultsHeader: api.defaults.headers.common['x-user-id'],
        allHeaders: Object.keys(config.headers)
      });
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  register: async (username, password, publicKey) => {
    const response = await api.post('/auth/register', {
      username,
      password,
      publicKey
    });
    return response.data;
  },

  login: async (username, password) => {
    const response = await api.post('/auth/login', {
      username,
      password
    });
    return response.data;
  },

  getUser: async (userId) => {
    const response = await api.get(`/auth/user/${userId}`);
    return response.data;
  }
};

// Key Exchange API
export const keyExchangeAPI = {
  initiate: async (receiverId, publicKey, ephemeralPublicKey, signature, timestamp, nonce) => {
    const response = await api.post('/key-exchange/initiate', {
      receiverId,
      publicKey,
      ephemeralPublicKey,
      signature,
      timestamp,
      nonce
    });
    return response.data;
  },

  respond: async (senderId, ephemeralPublicKey, signature, timestamp, nonce) => {
    const response = await api.post('/key-exchange/respond', {
      senderId,
      ephemeralPublicKey,
      signature,
      timestamp,
      nonce
    });
    return response.data;
  },

  confirm: async (otherUserId, keyConfirmation, signature, timestamp) => {
    const response = await api.post('/key-exchange/confirm', {
      otherUserId,
      keyConfirmation,
      signature,
      timestamp
    });
    return response.data;
  },

  logInvalidSignature: async (context, reason, signature, data, otherUserId) => {
    const response = await api.post('/key-exchange/invalid-signature', {
      context,
      reason,
      signature,
      data,
      otherUserId
    });
    return response.data;
  }
};

// Messages API
export const messagesAPI = {
  send: async (receiverId, ciphertext, iv, authTag, sequenceNumber, nonce, timestamp) => {
    const response = await api.post('/messages/send', {
      receiverId,
      ciphertext,
      iv,
      authTag,
      sequenceNumber,
      nonce,
      timestamp
    });
    return response.data;
  },

  receive: async (peerId, limit = 50, before = null) => {
    const params = { limit };
    if (before) params.before = before;
    if (peerId) params.peerId = peerId;
    const response = await api.get('/messages/receive', { params });
    return response.data;
  },

  logDecryptFailure: async (messageId, reason) => {
    const response = await api.post('/messages/decrypt-failure', {
      messageId,
      reason
    });
    return response.data;
  },

  logInvalidSignature: async (context, reason, signature, data) => {
    const response = await api.post('/messages/invalid-signature', {
      context,
      reason,
      signature,
      data
    });
    return response.data;
  }
};

// Files API
export const filesAPI = {
  upload: async (payload) => {
    const response = await api.post('/files/upload', payload);
    return response.data;
  },

  download: async (fileId) => {
    const response = await api.get(`/files/${fileId}`);
    return response.data;
  },

  list: async (limit = 50) => {
    const response = await api.get('/files/list', { params: { limit } });
    return response.data;
  }
};

export default api;

