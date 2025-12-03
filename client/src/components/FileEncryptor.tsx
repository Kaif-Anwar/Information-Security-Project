import { useState } from 'react';
import { useCrypto } from '../context/CryptoContext';
import { aesEncrypt } from '../services/crypto/webCrypto';
import { bufferToBase64 } from '../utils/buffer';

interface EncryptedChunkView {
  id: string;
  order: number;
  iv: string;
  ciphertext: string;
}

export const FileEncryptor = () => {
  const { loadSession } = useCrypto();
  const [sessionId, setSessionId] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [chunks, setChunks] = useState<EncryptedChunkView[]>([]);
  const [chunkSize, setChunkSize] = useState(512 * 1024);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleEncryptFile = async () => {
    if (!file || !sessionId) {
      setStatus('Select a file and session ID');
      return;
    }
    setBusy(true);
    setStatus(null);
    try {
      const session = await loadSession(sessionId);
      if (!session?.derivedKey) {
        throw new Error('Session key not found');
      }
      const buffer = await file.arrayBuffer();
      const totalChunks = Math.ceil(buffer.byteLength / chunkSize);
      const nextChunks: EncryptedChunkView[] = [];
      for (let index = 0; index < totalChunks; index += 1) {
        const start = index * chunkSize;
        const end = Math.min(buffer.byteLength, start + chunkSize);
        const chunkBuffer = buffer.slice(start, end);
        const { ciphertext, iv } = await aesEncrypt(
          session.derivedKey,
          chunkBuffer,
        );
        nextChunks.push({
          id: crypto.randomUUID(),
          order: index,
          iv: bufferToBase64(iv.buffer),
          ciphertext: bufferToBase64(ciphertext),
        });
      }
      setChunks(nextChunks);
      setStatus(`Encrypted ${nextChunks.length} chunk(s)`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Encryption failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <header>
        <h2>Encrypted File Sharing</h2>
        <p>Encrypt files client-side before upload using AES-256-GCM per chunk.</p>
      </header>
      <div className="stack gap-sm">
        <label htmlFor="fileSession">
          Session ID
          <input
            id="fileSession"
            value={sessionId}
            onChange={(event) => setSessionId(event.target.value)}
          />
        </label>
        <label htmlFor="fileInput">
          File
          <input
            id="fileInput"
            type="file"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
        </label>
        <label htmlFor="chunkSize">
          Chunk size (bytes)
          <input
            id="chunkSize"
            type="number"
            min={64 * 1024}
            step={64 * 1024}
            value={chunkSize}
            onChange={(event) => setChunkSize(Number(event.target.value))}
          />
        </label>
        <button
          type="button"
          onClick={handleEncryptFile}
          disabled={busy || !file || !sessionId}
        >
          {busy ? 'Encrypting…' : 'Encrypt File'}
        </button>
        {status && <p className="status">{status}</p>}
        <details>
          <summary>Encrypted chunks ({chunks.length})</summary>
          <ul className="chunk-list">
            {chunks.map((chunk) => (
              <li key={chunk.id}>
                Chunk #{chunk.order} – IV {chunk.iv.slice(0, 16)}… Ciphertext{' '}
                {chunk.ciphertext.slice(0, 32)}…
              </li>
            ))}
          </ul>
        </details>
      </div>
    </section>
  );
};

