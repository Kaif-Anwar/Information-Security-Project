import { useState, useEffect } from 'react';
import Auth from './components/Auth.jsx';
import Chat from './components/Chat.jsx';
import { getPrivateKey } from './utils/storage.js';
import { importECCPrivateKey, importECDAPrivateKey } from './utils/crypto.js';
import { setAuthHeader, clearAuthHeader, getAuthState } from './services/api.js';

function App() {
  const [user, setUser] = useState(null);
  const [encryptionKeyPair, setEncryptionKeyPair] = useState(null);
  const [signingKeyPair, setSigningKeyPair] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in (from localStorage)
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        const userData = JSON.parse(savedUser);
        setUser(userData);
        // Set auth header for API requests IMMEDIATELY and verify
        if (userData.userId) {
          setAuthHeader(userData.userId);
          console.log('🔐 App - Auth header set from localStorage for userId:', userData.userId);
          // Verify it was set correctly
          setTimeout(() => {
            const authState = getAuthState();
            console.log('🔐 App - Auth state after setting:', authState);
            if (!authState.currentUserId) {
              console.error('❌ CRITICAL: Auth header was not set correctly!');
              // Try setting again
              setAuthHeader(userData.userId);
            }
          }, 100);
        } else {
          console.error('❌ User data loaded but userId is missing!');
        }
        loadUserKeys(userData);
      } catch (error) {
        console.error('Error loading saved user:', error);
        setLoading(false);
      }
    } else {
      setLoading(false);
    }
  }, []);

  const loadUserKeys = async (userData) => {
    try {
      // In a real app, you'd prompt for password to decrypt keys
      // For now, we'll assume keys are in memory from registration
      setLoading(false);
    } catch (error) {
      console.error('Error loading keys:', error);
      setLoading(false);
    }
  };

  const handleLogin = async (userData) => {
    setUser(userData);
    localStorage.setItem('user', JSON.stringify(userData));
    
    // Set auth header for API requests
    if (userData.userId) {
      setAuthHeader(userData.userId);
    }
    
    // If keys are provided (from registration), store them
    if (userData.encryptionKeyPair && userData.signingKeyPair) {
      setEncryptionKeyPair(userData.encryptionKeyPair);
      setSigningKeyPair(userData.signingKeyPair);
    }
  };

  const handleLogout = () => {
    setUser(null);
    setEncryptionKeyPair(null);
    setSigningKeyPair(null);
    localStorage.removeItem('user');
    clearAuthHeader();
  };

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      }}>
        <div style={{
          textAlign: 'center',
          color: 'white'
        }}>
          <div style={{
            fontSize: '24px',
            marginBottom: '16px',
            animation: 'spin 1s linear infinite'
          }}>⏳</div>
          <div style={{ fontSize: '18px', fontWeight: '500' }}>Loading...</div>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Auth onLogin={handleLogin} />;
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
    }}>
      <div style={{
        backgroundColor: 'var(--background-white)',
        boxShadow: 'var(--shadow-lg)',
        borderBottom: '1px solid var(--border-color)',
        padding: '16px 24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <div style={{
            fontSize: '24px',
            background: 'linear-gradient(135deg, var(--primary-blue) 0%, var(--primary-blue-light) 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            fontWeight: '700'
          }}>
            🔐 Secure E2EE
          </div>
          <div style={{
            height: '24px',
            width: '1px',
            backgroundColor: 'var(--border-color)'
          }}></div>
          <div>
            <div style={{
              fontSize: '14px',
              fontWeight: '600',
              color: 'var(--text-primary)'
            }}>
              {user.username}
            </div>
            <div style={{
              fontSize: '12px',
              color: 'var(--text-secondary)'
            }}>
              ID: {user.userId.substring(0, 8)}...
            </div>
          </div>
        </div>
        <button
          onClick={handleLogout}
          style={{
            padding: '8px 16px',
            backgroundColor: 'var(--error-red)',
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            cursor: 'pointer',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'all 0.2s',
            boxShadow: 'var(--shadow-sm)'
          }}
          onMouseEnter={(e) => {
            e.target.style.backgroundColor = '#dc2626';
            e.target.style.transform = 'translateY(-1px)';
            e.target.style.boxShadow = 'var(--shadow-md)';
          }}
          onMouseLeave={(e) => {
            e.target.style.backgroundColor = 'var(--error-red)';
            e.target.style.transform = 'translateY(0)';
            e.target.style.boxShadow = 'var(--shadow-sm)';
          }}
        >
          🚪 Logout
        </button>
      </div>
      {encryptionKeyPair && signingKeyPair ? (
        <Chat user={user} encryptionKeyPair={encryptionKeyPair} signingKeyPair={signingKeyPair} />
      ) : (
        <div style={{
          textAlign: 'center',
          padding: '80px 20px',
          color: 'white'
        }}>
          <div style={{
            fontSize: '48px',
            marginBottom: '16px'
          }}>🔑</div>
          <p style={{
            fontSize: '18px',
            marginBottom: '24px',
            opacity: 0.9
          }}>
            Keys not loaded. Please register a new account to generate keys.
          </p>
          <button
            onClick={handleLogout}
            style={{
              padding: '12px 24px',
              backgroundColor: 'white',
              color: 'var(--primary-blue)',
              border: 'none',
              borderRadius: '8px',
              fontSize: '16px',
              fontWeight: '600',
              cursor: 'pointer',
              boxShadow: 'var(--shadow-lg)',
              transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => {
              e.target.style.transform = 'translateY(-2px)';
              e.target.style.boxShadow = 'var(--shadow-xl)';
            }}
            onMouseLeave={(e) => {
              e.target.style.transform = 'translateY(0)';
              e.target.style.boxShadow = 'var(--shadow-lg)';
            }}
          >
            Go to Login
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
