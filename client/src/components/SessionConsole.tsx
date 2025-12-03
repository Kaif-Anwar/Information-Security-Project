import { useMemo, useState } from 'react';
import { useCrypto } from '../context/CryptoContext';
import { hkdf } from '../services/crypto/webCrypto';
import { bufferToBase64 } from '../utils/buffer';

export const SessionConsole = () => {
  const { sessionMap, storeSession } = useCrypto();
  const [sessionId, setSessionId] = useState('');
  const [peerId, setPeerId] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const sessions = useMemo(
    () => Object.values(sessionMap),
    [sessionMap],
  );

  const handleCreateSession = async () => {
    if (!sessionId || !peerId) {
      setStatus('Session ID and peer ID are required');
      return;
    }
    setBusy(true);
    setStatus(null);
    try {
      const sharedSecret = window.crypto.getRandomValues(new Uint8Array(32));
      const info = `session:${sessionId}:${peerId}`;
      const { key, salt } = await hkdf(sharedSecret.buffer, info);
      await storeSession({
        sessionId,
        peerId,
        hkdfInfo: info,
        salt: bufferToBase64(salt.buffer),
        exportedKey: '',
        derivedKey: key,
        createdAt: new Date().toISOString(),
      });
      setStatus(`Derived session key ${sessionId}`);
      setSessionId('');
      setPeerId('');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Session failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <header>
        <h2>Session Console</h2>
        <p>
          Simulate Diffie-Hellman output to derive AES session keys (HKDF +
          SHA-256) before wiring to the backend relay.
        </p>
      </header>
      <div className="stack gap-sm">
        <label htmlFor="sessionId">
          Session ID
          <input
            id="sessionId"
            value={sessionId}
            onChange={(event) => setSessionId(event.target.value)}
            placeholder="chat-session-123"
          />
        </label>
        <label htmlFor="peerId">
          Peer ID
          <input
            id="peerId"
            value={peerId}
            onChange={(event) => setPeerId(event.target.value)}
            placeholder="alice/bob"
          />
        </label>
        <button
          type="button"
          onClick={handleCreateSession}
          disabled={busy || !sessionId || !peerId}
        >
          {busy ? 'Deriving…' : 'Derive Session Key'}
        </button>
        {status && <p className="status">{status}</p>}
        <details>
          <summary>Cached Sessions ({sessions.length})</summary>
          <ul className="session-list">
            {sessions.map((session) => (
              <li key={session.sessionId}>
                <strong>{session.sessionId}</strong> ↔ {session.peerId} (
                {new Date(session.createdAt).toLocaleString()})
              </li>
            ))}
          </ul>
        </details>
      </div>
    </section>
  );
};

