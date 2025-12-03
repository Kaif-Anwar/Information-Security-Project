import { useState, useEffect, useRef, useCallback } from 'react';
import { MessagingService } from '../services/messaging.js';
import { FileEncryptionService } from '../services/fileEncryption.js';
import { KeyExchangeManager } from '../services/keyExchange.js';
import { authAPI, filesAPI, setAuthHeader, getAuthState } from '../services/api.js';

export default function Chat({ user, encryptionKeyPair, signingKeyPair }) {
  const [messages, setMessages] = useState([]);
  const [files, setFiles] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [receiverId, setReceiverId] = useState('');
  const [receiverUsername, setReceiverUsername] = useState('');
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('not-started');
  const [messagingService, setMessagingService] = useState(null);
  const [keyManager, setKeyManager] = useState(null);
  const [fileService, setFileService] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [copied, setCopied] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const messagesEndRef = useRef(null);

  // Ensure auth header is set when component mounts or user changes
  useEffect(() => {
    if (user?.userId) {
      setAuthHeader(user.userId);
      console.log('🔐 Chat component - Auth header set for userId:', user.userId);
    }
  }, [user?.userId]);

  useEffect(() => {
    if (encryptionKeyPair && signingKeyPair) {
      const km = new KeyExchangeManager(user.userId, signingKeyPair, encryptionKeyPair);
      const msgService = new MessagingService(km, user.userId);
      setKeyManager(km);
      setMessagingService(msgService);
    }
  }, [encryptionKeyPair, signingKeyPair, user.userId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const refreshMessages = useCallback(async () => {
    if (!messagingService || !receiverId || keyExchangeStatus !== 'completed') return;
    try {
      const received = await messagingService.receiveMessages(receiverId);
      setMessages(received);
    } catch (error) {
      console.error('Receive messages error:', error);
    }
  }, [messagingService, receiverId, keyExchangeStatus]);

  const refreshFiles = useCallback(async () => {
    if (!receiverId || keyExchangeStatus !== 'completed') return;
    try {
      const filesList = await filesAPI.list(100);
      // Filter files for this conversation
      const conversationFiles = filesList.files.filter(file => 
        (file.senderId === user.userId && file.receiverId === receiverId) ||
        (file.senderId === receiverId && file.receiverId === user.userId)
      );
      setFiles(conversationFiles);
    } catch (error) {
      console.error('Fetch files error:', error);
    }
  }, [receiverId, keyExchangeStatus, user.userId]);

  useEffect(() => {
    if (keyExchangeStatus === 'completed') {
      refreshMessages();
      refreshFiles();
    }
  }, [keyExchangeStatus, receiverId, refreshMessages, refreshFiles]);

  const handleStartConversation = async () => {
    if (!receiverId || !receiverUsername) {
      alert('Please enter receiver ID and username');
      return;
    }

    try {
      // Ensure auth header is set before making any API calls
      if (user?.userId) {
        setAuthHeader(user.userId);
        console.log('🔐 Ensuring auth header is set for userId:', user.userId);
        // Verify it was set
        const authState = getAuthState();
        console.log('🔐 Current auth state:', authState);
        if (!authState.currentUserId) {
          console.error('❌ Failed to set auth header!');
          alert('Authentication error. Please refresh and log in again.');
          return;
        }
      } else {
        console.error('❌ User ID not available for auth header');
        alert('User authentication error. Please log in again.');
        return;
      }

      // Get receiver's public key
      const receiverData = await authAPI.getUser(receiverId);
      
      if (!receiverData) {
        alert('Receiver not found');
        return;
      }

      setMessages([]); // Clear messages until key exchange completes
      setKeyExchangeStatus('initiating');
      
      // Parse receiver's public keys
      let receiverKeys;
      try {
        receiverKeys = JSON.parse(receiverData.publicKey);
        console.log('Receiver public keys parsed:', {
          hasEncryption: !!receiverKeys.encryption,
          hasSigning: !!receiverKeys.signing,
          encryptionLength: receiverKeys.encryption?.length || 0
        });
      } catch (e) {
        console.error('Failed to parse receiver public keys:', e);
        alert('Failed to parse receiver public keys: ' + e.message);
        setKeyExchangeStatus('failed');
        return;
      }
      
      if (!receiverKeys.encryption) {
        alert('Receiver encryption public key is missing');
        setKeyExchangeStatus('failed');
        return;
      }
      
      // Initiate key exchange
      if (keyManager) {
        console.log('Initiating key exchange with receiver:', receiverId);
        await keyManager.initiateKeyExchange(
          receiverId,
          receiverKeys.encryption
        );
        setKeyExchangeStatus('completed');
        
        // Initialize file service with session key
        const sessionKey = keyManager.getSessionKey(receiverId);
        if (sessionKey) {
          setFileService(new FileEncryptionService(sessionKey));
        }

        await refreshMessages();
      }
    } catch (error) {
      console.error('Key exchange error:', error);
      alert('Key exchange failed: ' + error.message);
      setKeyExchangeStatus('failed');
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() || !receiverId) {
      return;
    }

    try {
      await messagingService.sendMessage(receiverId, newMessage);
      setNewMessage('');
      await refreshMessages();
    } catch (error) {
      console.error('Send message error:', error);
      alert('Failed to send message: ' + error.message);
    }
  };

  const handleRefreshMessages = async () => {
    await refreshMessages();
    await refreshFiles();
  };

  const handleFileUpload = async () => {
    if (!selectedFile || !receiverId || !fileService) {
      alert('Please select a file and ensure key exchange is complete');
      return;
    }

    try {
      await fileService.uploadFile(receiverId, selectedFile);
      setUploadSuccess(true);
      setSelectedFile(null);
      // Refresh files to show the new upload
      await refreshFiles();
      // Hide success message after 3 seconds
      setTimeout(() => setUploadSuccess(false), 3000);
    } catch (error) {
      console.error('File upload error:', error);
      alert('File upload failed: ' + error.message);
    }
  };

  const handleFileDownload = async (fileId, fileName) => {
    if (!fileService) {
      alert('File service not initialized');
      return;
    }

    try {
      await fileService.downloadFile(fileId);
      // File download is handled by fileService (creates download link)
    } catch (error) {
      console.error('File download error:', error);
      alert('File download failed: ' + error.message);
    }
  };

  const handleCopyUserId = async () => {
    try {
      await navigator.clipboard.writeText(user.userId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = user.userId;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getStatusColor = (status) => {
    switch(status) {
      case 'completed': return 'var(--success-green)';
      case 'initiating': return 'var(--warning-orange)';
      case 'failed': return 'var(--error-red)';
      default: return 'var(--text-secondary)';
    }
  };

  const getStatusIcon = (status) => {
    switch(status) {
      case 'completed': return '✅';
      case 'initiating': return '⏳';
      case 'failed': return '❌';
      default: return '🔒';
    }
  };

  return (
    <div style={{
      maxWidth: '1200px',
      margin: '0 auto',
      padding: '24px',
      minHeight: 'calc(100vh - 80px)'
    }}>
      {/* User ID Display Card */}
      <div style={{
        backgroundColor: 'var(--background-white)',
        borderRadius: '16px',
        boxShadow: 'var(--shadow-lg)',
        padding: '20px 24px',
        marginBottom: '24px',
        border: '1px solid var(--border-color)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          flex: 1,
          minWidth: '200px'
        }}>
          <div style={{
            fontSize: '28px'
          }}>👤</div>
          <div>
            <div style={{
              fontSize: '12px',
              color: 'var(--text-secondary)',
              fontWeight: '500',
              marginBottom: '4px',
              textTransform: 'uppercase',
              letterSpacing: '0.5px'
            }}>
              Your User ID
            </div>
            <div style={{
              fontSize: '18px',
              fontWeight: '700',
              color: 'var(--text-primary)',
              fontFamily: 'monospace',
              wordBreak: 'break-all'
            }}>
              {user.userId}
            </div>
          </div>
        </div>
        <button
          onClick={handleCopyUserId}
          style={{
            padding: '12px 24px',
            backgroundColor: copied ? 'var(--success-green)' : 'var(--primary-blue)',
            color: 'white',
            border: 'none',
            borderRadius: '10px',
            fontSize: '14px',
            fontWeight: '600',
            cursor: 'pointer',
            transition: 'all 0.2s',
            boxShadow: 'var(--shadow-md)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            whiteSpace: 'nowrap'
          }}
          onMouseEnter={(e) => {
            if (!copied) {
              e.target.style.backgroundColor = 'var(--primary-blue-dark)';
              e.target.style.transform = 'translateY(-1px)';
              e.target.style.boxShadow = 'var(--shadow-lg)';
            }
          }}
          onMouseLeave={(e) => {
            if (!copied) {
              e.target.style.backgroundColor = 'var(--primary-blue)';
              e.target.style.transform = 'translateY(0)';
              e.target.style.boxShadow = 'var(--shadow-md)';
            }
          }}
        >
          {copied ? (
            <>
              <span>✅</span>
              <span>Copied!</span>
            </>
          ) : (
            <>
              <span>📋</span>
              <span>Copy ID</span>
            </>
          )}
        </button>
      </div>

      {/* Start Conversation Card */}
      <div style={{
        backgroundColor: 'var(--background-white)',
        borderRadius: '16px',
        boxShadow: 'var(--shadow-lg)',
        padding: '24px',
        marginBottom: '24px',
        border: '1px solid var(--border-color)'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          marginBottom: '20px'
        }}>
          <div style={{
            fontSize: '24px'
          }}>🔐</div>
          <h2 style={{
            fontSize: '24px',
            fontWeight: '700',
            color: 'var(--text-primary)',
            margin: 0
          }}>
            Start Secure Conversation
          </h2>
        </div>

        <div style={{
          display: 'flex',
          gap: '12px',
          marginBottom: '16px',
          flexWrap: 'wrap'
        }}>
          <input
            type="text"
            placeholder="Receiver User ID"
            value={receiverId}
            onChange={(e) => setReceiverId(e.target.value)}
            style={{
              flex: '1',
              minWidth: '200px',
              padding: '12px 16px',
              border: '2px solid var(--border-color)',
              borderRadius: '8px',
              fontSize: '15px',
              transition: 'all 0.2s',
              outline: 'none'
            }}
            onFocus={(e) => e.target.style.borderColor = 'var(--primary-blue)'}
            onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
          />
          <input
            type="text"
            placeholder="Receiver Username"
            value={receiverUsername}
            onChange={(e) => setReceiverUsername(e.target.value)}
            style={{
              flex: '1',
              minWidth: '200px',
              padding: '12px 16px',
              border: '2px solid var(--border-color)',
              borderRadius: '8px',
              fontSize: '15px',
              transition: 'all 0.2s',
              outline: 'none'
            }}
            onFocus={(e) => e.target.style.borderColor = 'var(--primary-blue)'}
            onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
          />
          <button
            onClick={handleStartConversation}
            disabled={keyExchangeStatus === 'initiating'}
            style={{
              padding: '12px 24px',
              backgroundColor: keyExchangeStatus === 'initiating' ? 'var(--text-secondary)' : 'var(--primary-blue)',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              fontSize: '15px',
              fontWeight: '600',
              cursor: keyExchangeStatus === 'initiating' ? 'not-allowed' : 'pointer',
              transition: 'all 0.2s',
              boxShadow: 'var(--shadow-md)',
              whiteSpace: 'nowrap'
            }}
            onMouseEnter={(e) => {
              if (keyExchangeStatus !== 'initiating') {
                e.target.style.backgroundColor = 'var(--primary-blue-dark)';
                e.target.style.transform = 'translateY(-1px)';
                e.target.style.boxShadow = 'var(--shadow-lg)';
              }
            }}
            onMouseLeave={(e) => {
              if (keyExchangeStatus !== 'initiating') {
                e.target.style.backgroundColor = 'var(--primary-blue)';
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = 'var(--shadow-md)';
              }
            }}
          >
            {keyExchangeStatus === 'initiating' ? '⏳ Initiating...' : '🚀 Start Conversation'}
          </button>
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '12px',
          backgroundColor: 'var(--background-light)',
          borderRadius: '8px',
          fontSize: '14px',
          fontWeight: '500'
        }}>
          <span>{getStatusIcon(keyExchangeStatus)}</span>
          <span style={{ color: getStatusColor(keyExchangeStatus) }}>
            Key Exchange: {keyExchangeStatus.charAt(0).toUpperCase() + keyExchangeStatus.slice(1)}
          </span>
        </div>
      </div>

      {/* Messages Section */}
      {receiverId && (
        <div style={{
          backgroundColor: 'var(--background-white)',
          borderRadius: '16px',
          boxShadow: 'var(--shadow-lg)',
          padding: '24px',
          border: '1px solid var(--border-color)'
        }}>
          {keyExchangeStatus !== 'completed' ? (
            <div style={{
              textAlign: 'center',
              padding: '60px 40px',
              color: 'var(--text-secondary)'
            }}>
              <div style={{ fontSize: '64px', marginBottom: '20px' }}>🔒</div>
              <h3 style={{
                fontSize: '20px',
                fontWeight: '700',
                color: 'var(--text-primary)',
                margin: 0,
                marginBottom: '12px'
              }}>
                {keyExchangeStatus === 'initiating' ? 'Establishing secure connection...' : 'Key exchange required'}
              </h3>
              <p style={{
                fontSize: '16px',
                margin: 0,
                lineHeight: '1.6'
              }}>
                {keyExchangeStatus === 'initiating' 
                  ? 'Please wait while we establish a secure encrypted channel with the receiver.'
                  : 'Please complete key exchange to access conversation history and send messages.'}
              </p>
            </div>
          ) : (
            <>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '20px',
                paddingBottom: '16px',
                borderBottom: '2px solid var(--border-color)'
              }}>
                <div>
                  <h3 style={{
                    fontSize: '20px',
                    fontWeight: '700',
                    color: 'var(--text-primary)',
                    margin: 0,
                    marginBottom: '4px'
                  }}>
                    💬 Messages with {receiverUsername || receiverId}
                  </h3>
                  <p style={{
                    fontSize: '14px',
                    color: 'var(--text-secondary)',
                    margin: 0
                  }}>
                    End-to-end encrypted conversation
                  </p>
                </div>
                <button
                  onClick={handleRefreshMessages}
                  style={{
                    padding: '10px 20px',
                    backgroundColor: 'var(--success-green)',
                    color: 'white',
                    border: 'none',
                    borderRadius: '8px',
                    fontSize: '14px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    boxShadow: 'var(--shadow-sm)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}
                  onMouseEnter={(e) => {
                    e.target.style.backgroundColor = '#059669';
                    e.target.style.transform = 'translateY(-1px)';
                    e.target.style.boxShadow = 'var(--shadow-md)';
                  }}
                  onMouseLeave={(e) => {
                    e.target.style.backgroundColor = 'var(--success-green)';
                    e.target.style.transform = 'translateY(0)';
                    e.target.style.boxShadow = 'var(--shadow-sm)';
                  }}
                >
                  🔄 Refresh
                </button>
              </div>

          {/* Upload Success Message */}
          {uploadSuccess && (
            <div style={{
              padding: '12px 16px',
              backgroundColor: 'var(--success-green)',
              color: 'white',
              borderRadius: '8px',
              marginBottom: '16px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              animation: 'fadeIn 0.3s ease-in'
            }}>
              <span>✅</span>
              <span>File uploaded successfully!</span>
            </div>
          )}
          
          {/* Messages Container */}
          <div style={{
            height: '500px',
            overflowY: 'auto',
            border: '2px solid var(--border-color)',
            borderRadius: '12px',
            padding: '16px',
            marginBottom: '20px',
            backgroundColor: 'var(--background-light)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px'
          }}>
            {messages.length === 0 && files.length === 0 ? (
              <div style={{
                textAlign: 'center',
                padding: '40px',
                color: 'var(--text-secondary)'
              }}>
                <div style={{ fontSize: '48px', marginBottom: '16px' }}>💭</div>
                <p style={{ fontSize: '16px', margin: 0 }}>No messages yet. Send a message to start!</p>
              </div>
            ) : (
              // Combine messages and files, sort by timestamp
              [...messages.map(msg => ({ ...msg, type: 'message', sortTime: new Date(msg.timestamp).getTime() })),
               ...files.map(file => ({ ...file, type: 'file', sortTime: new Date(file.uploadedAt).getTime(), messageId: file.fileId }))]
                .sort((a, b) => a.sortTime - b.sortTime)
                .map((item) => {
                  // Render file
                  if (item.type === 'file') {
                    const fileSizeKB = (item.fileSize / 1024).toFixed(2);
                    const isSender = item.senderId === user.userId;
                    return (
                      <div
                        key={item.fileId}
                        style={{
                          maxWidth: '70%',
                          marginLeft: isSender ? 'auto' : '0',
                          marginRight: isSender ? '0' : 'auto',
                          padding: '12px 16px',
                          backgroundColor: isSender
                            ? 'linear-gradient(135deg, var(--primary-blue) 0%, var(--primary-blue-light) 100%)'
                            : 'var(--background-white)',
                          background: isSender
                            ? 'linear-gradient(135deg, var(--primary-blue) 0%, var(--primary-blue-light) 100%)'
                            : 'var(--background-white)',
                          color: isSender ? 'white' : 'var(--text-primary)',
                          borderRadius: '16px',
                          boxShadow: 'var(--shadow-sm)',
                          border: isSender ? 'none' : '1px solid var(--border-color)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '8px'
                        }}
                      >
                        <div style={{
                          fontWeight: '600',
                          marginBottom: '6px',
                          fontSize: '14px',
                          opacity: 0.9
                        }}>
                          {isSender ? 'You' : item.senderUsername} 📎
                        </div>
                        <div style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '12px',
                          flexWrap: 'wrap'
                        }}>
                          <div style={{
                            fontSize: '24px'
                          }}>
                            📄
                          </div>
                          <div style={{
                            flex: 1,
                            minWidth: '150px'
                          }}>
                            <div style={{
                              fontSize: '15px',
                              fontWeight: '600',
                              marginBottom: '4px',
                              wordBreak: 'break-word'
                            }}>
                              {item.fileName}
                            </div>
                            <div style={{
                              fontSize: '12px',
                              opacity: 0.8
                            }}>
                              {fileSizeKB} KB • {item.fileType.split('/')[1]?.toUpperCase() || 'FILE'}
                            </div>
                          </div>
                          <button
                            onClick={() => handleFileDownload(item.fileId, item.fileName)}
                            style={{
                              padding: '8px 16px',
                              backgroundColor: isSender ? 'rgba(255, 255, 255, 0.2)' : 'var(--primary-blue)',
                              color: 'white',
                              border: 'none',
                              borderRadius: '8px',
                              fontSize: '13px',
                              fontWeight: '600',
                              cursor: 'pointer',
                              transition: 'all 0.2s',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '6px'
                            }}
                            onMouseEnter={(e) => {
                              e.target.style.opacity = '0.9';
                              e.target.style.transform = 'scale(1.05)';
                            }}
                            onMouseLeave={(e) => {
                              e.target.style.opacity = '1';
                              e.target.style.transform = 'scale(1)';
                            }}
                          >
                            ⬇️ Download
                          </button>
                        </div>
                        <div style={{
                          fontSize: '11px',
                          marginTop: '4px',
                          opacity: 0.7
                        }}>
                          {new Date(item.uploadedAt).toLocaleString()}
                        </div>
                      </div>
                    );
                  }
                  
                  // Render message
                  return (
                    <div
                      key={item.messageId}
                      style={{
                        maxWidth: '70%',
                        marginLeft: item.senderId === user.userId ? 'auto' : '0',
                        marginRight: item.senderId === user.userId ? '0' : 'auto',
                        padding: '12px 16px',
                        backgroundColor: item.senderId === user.userId 
                          ? 'linear-gradient(135deg, var(--primary-blue) 0%, var(--primary-blue-light) 100%)'
                          : 'var(--background-white)',
                        background: item.senderId === user.userId 
                          ? 'linear-gradient(135deg, var(--primary-blue) 0%, var(--primary-blue-light) 100%)'
                          : 'var(--background-white)',
                        color: item.senderId === user.userId ? 'white' : 'var(--text-primary)',
                        borderRadius: '16px',
                        boxShadow: 'var(--shadow-sm)',
                        border: item.senderId === user.userId ? 'none' : '1px solid var(--border-color)'
                      }}
                    >
                      <div style={{
                        fontWeight: '600',
                        marginBottom: '6px',
                        fontSize: '14px',
                        opacity: 0.9
                      }}>
                        {item.senderId === user.userId ? 'You' : item.senderUsername}
                      </div>
                      <div style={{
                        fontSize: '15px',
                        lineHeight: '1.5',
                        wordBreak: 'break-word'
                      }}>
                        {item.plaintext}
                      </div>
                      <div style={{
                        fontSize: '11px',
                        marginTop: '8px',
                        opacity: 0.7
                      }}>
                        {new Date(item.timestamp).toLocaleString()}
                      </div>
                    </div>
                  );
                })
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Send Message Input */}
          <div style={{
            display: 'flex',
            gap: '12px',
            marginBottom: '24px'
          }}>
            <input
              type="text"
              placeholder="Type your encrypted message..."
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
              disabled={keyExchangeStatus !== 'completed'}
              style={{
                flex: 1,
                padding: '14px 18px',
                border: '2px solid var(--border-color)',
                borderRadius: '12px',
                fontSize: '15px',
                transition: 'all 0.2s',
                outline: 'none',
                backgroundColor: keyExchangeStatus !== 'completed' ? 'var(--background-light)' : 'white'
              }}
              onFocus={(e) => {
                if (keyExchangeStatus === 'completed') {
                  e.target.style.borderColor = 'var(--primary-blue)';
                }
              }}
              onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
            />
            <button
              onClick={handleSendMessage}
              disabled={keyExchangeStatus !== 'completed' || !newMessage.trim()}
              style={{
                padding: '14px 28px',
                backgroundColor: keyExchangeStatus !== 'completed' || !newMessage.trim() 
                  ? 'var(--text-secondary)' 
                  : 'var(--primary-blue)',
                color: 'white',
                border: 'none',
                borderRadius: '12px',
                fontSize: '15px',
                fontWeight: '600',
                cursor: keyExchangeStatus !== 'completed' || !newMessage.trim() 
                  ? 'not-allowed' 
                  : 'pointer',
                transition: 'all 0.2s',
                boxShadow: 'var(--shadow-md)',
                whiteSpace: 'nowrap'
              }}
              onMouseEnter={(e) => {
                if (keyExchangeStatus === 'completed' && newMessage.trim()) {
                  e.target.style.backgroundColor = 'var(--primary-blue-dark)';
                  e.target.style.transform = 'translateY(-1px)';
                  e.target.style.boxShadow = 'var(--shadow-lg)';
                }
              }}
              onMouseLeave={(e) => {
                if (keyExchangeStatus === 'completed' && newMessage.trim()) {
                  e.target.style.backgroundColor = 'var(--primary-blue)';
                  e.target.style.transform = 'translateY(0)';
                  e.target.style.boxShadow = 'var(--shadow-md)';
                }
              }}
            >
              📤 Send
            </button>
          </div>

          {/* File Upload Section */}
          <div style={{
            padding: '20px',
            backgroundColor: 'var(--background-light)',
            borderRadius: '12px',
            border: '1px solid var(--border-color)'
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              marginBottom: '16px'
            }}>
              <div style={{ fontSize: '20px' }}>📎</div>
              <h4 style={{
                fontSize: '18px',
                fontWeight: '600',
                color: 'var(--text-primary)',
                margin: 0
              }}>
                Send Encrypted File
              </h4>
            </div>
            <div style={{
              display: 'flex',
              gap: '12px',
              alignItems: 'center',
              flexWrap: 'wrap'
            }}>
              <label style={{
                padding: '12px 20px',
                backgroundColor: 'var(--primary-blue)',
                color: 'white',
                borderRadius: '8px',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '600',
                transition: 'all 0.2s',
                boxShadow: 'var(--shadow-sm)',
                display: 'inline-block'
              }}
              onMouseEnter={(e) => {
                e.target.style.backgroundColor = 'var(--primary-blue-dark)';
                e.target.style.transform = 'translateY(-1px)';
                e.target.style.boxShadow = 'var(--shadow-md)';
              }}
              onMouseLeave={(e) => {
                e.target.style.backgroundColor = 'var(--primary-blue)';
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = 'var(--shadow-sm)';
              }}
              >
                📁 Choose File
                <input
                  type="file"
                  onChange={(e) => setSelectedFile(e.target.files[0])}
                  style={{ display: 'none' }}
                  disabled={keyExchangeStatus !== 'completed'}
                />
              </label>
              {selectedFile && (() => {
                const sizeInKB = Math.round(selectedFile.size * 100 / 1024) / 100;
                return (
                  <div style={{
                    padding: '10px 16px',
                    backgroundColor: 'white',
                    borderRadius: '8px',
                    border: '1px solid var(--border-color)',
                    fontSize: '14px',
                    color: 'var(--text-primary)',
                    flex: 1,
                    minWidth: '200px'
                  }}>
                    <strong>{selectedFile.name}</strong> ({sizeInKB} KB)
                  </div>
                );
              })()}
              <button
                onClick={handleFileUpload}
                disabled={!selectedFile || keyExchangeStatus !== 'completed'}
                style={{
                  padding: '12px 24px',
                  backgroundColor: !selectedFile || keyExchangeStatus !== 'completed'
                    ? 'var(--text-secondary)'
                    : 'var(--success-green)',
                  color: 'white',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: !selectedFile || keyExchangeStatus !== 'completed'
                    ? 'not-allowed'
                    : 'pointer',
                  transition: 'all 0.2s',
                  boxShadow: 'var(--shadow-sm)',
                  whiteSpace: 'nowrap'
                }}
                onMouseEnter={(e) => {
                  if (selectedFile && keyExchangeStatus === 'completed') {
                    e.target.style.backgroundColor = '#059669';
                    e.target.style.transform = 'translateY(-1px)';
                    e.target.style.boxShadow = 'var(--shadow-md)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (selectedFile && keyExchangeStatus === 'completed') {
                    e.target.style.backgroundColor = 'var(--success-green)';
                    e.target.style.transform = 'translateY(0)';
                    e.target.style.boxShadow = 'var(--shadow-sm)';
                  }
                }}
              >
                🔒 Upload Encrypted
              </button>
            </div>
          </div>
          </>
          )}
        </div>
      )}
    </div>
  );
}
