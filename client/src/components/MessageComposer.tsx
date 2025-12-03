import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useCrypto } from '../context/CryptoContext';

interface LocalMessage {
  id: string;
  sessionId: string;
  ciphertext: string;
  iv: string;
  plaintext?: string;
  direction: 'outbound' | 'inbound';
  timestamp: number;
}

export const MessageComposer = () => {
  const { userId } = useAuth();
  const { encryptMessage, decryptMessage } = useCrypto();
  const [sessionId, setSessionId] = useState('');
  const [body, setBody] = useState('');
  const [messages, setMessages] = useState<LocalMessage[]>([]);
  const [status, setStatus] = useState<string | null>(null);

  const handleEncrypt = async () => {
    if (!sessionId || !body) {
      setStatus('Provide session ID and message body');
      return;
    }
    try {
      const { ciphertext, iv } = await encryptMessage(sessionId, body);
      const payload: LocalMessage = {
        id: crypto.randomUUID(),
        sessionId,
        ciphertext,
        iv,
        plaintext: body,
        direction: 'outbound',
        timestamp: Date.now(),
      };
      setMessages((prev) => [payload, ...prev]);
      setBody('');
      setStatus('Encrypted with AES-256-GCM');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Encryption failed');
    }
  };

  const handleDecrypt = async (message: LocalMessage) => {
    try {
      const plaintext = await decryptMessage(
        message.sessionId,
        message.ciphertext,
        message.iv,
      );
      setMessages((prev) =>
        prev.map((item) =>
          item.id === message.id ? { ...item, plaintext } : item,
        ),
      );
      setStatus('Decryption successful');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Decryption failed');
    }
  };

  return (
    <section className="panel">
      <header>
        <h2>Encrypted Messaging</h2>
        <p>
          Compose text messages that encrypt locally with AES-256-GCM before
          hitting the transport/channel.
        </p>
      </header>
      <div className="stack gap-sm">
        <label htmlFor="sessionPicker">
          Session ID
          <input
            id="sessionPicker"
            value={sessionId}
            onChange={(event) => setSessionId(event.target.value)}
            placeholder="session from console"
          />
        </label>
        <textarea
          placeholder="Hello Bob, here is the secret…"
          value={body}
          onChange={(event) => setBody(event.target.value)}
        />
        <button type="button" onClick={handleEncrypt} disabled={!userId}>
          Encrypt & queue
        </button>
        {status && <p className="status">{status}</p>}
        <ul className="message-list">
          {messages.map((message) => (
            <li key={message.id}>
              <header>
                <strong>{message.sessionId}</strong> ·{' '}
                {new Date(message.timestamp).toLocaleTimeString()}
              </header>
              <p className="ciphertext">Ciphertext: {message.ciphertext}</p>
              <p className="ciphertext">IV: {message.iv}</p>
              {message.plaintext ? (
                <p className="plaintext">Plaintext: {message.plaintext}</p>
              ) : (
                <button
                  type="button"
                  className="ghost"
                  onClick={() => handleDecrypt(message)}
                >
                  Decrypt
                </button>
              )}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
};

