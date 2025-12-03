import { useState, type FormEvent } from 'react';
import { useCrypto } from '../context/CryptoContext';

export const KeyManagementCard = () => {
  const {
    publicKey,
    algorithm,
    vaultStatus,
    generateIdentityKeys,
    unlockPrivateKey,
    lockVault,
  } = useCrypto();
  const [selectedAlgo, setSelectedAlgo] = useState<'RSA' | 'ECC'>(algorithm);
  const [passphrase, setPassphrase] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleGenerate = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await generateIdentityKeys({
        algorithm: selectedAlgo,
        passphrase,
      });
      setMessage(`Generated new ${selectedAlgo} key pair`);
    } catch (error) {
      setMessage(
        error instanceof Error ? error.message : 'Failed to generate keys',
      );
    } finally {
      setBusy(false);
    }
  };

  const handleUnlock = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await unlockPrivateKey(passphrase);
      setMessage('Vault unlocked');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unlock failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <header>
        <h2>Key Management</h2>
        <p>
          Generate RSA/ECC keys and keep private key encrypted with a
          passphrase-derived AES key in IndexedDB.
        </p>
      </header>
      <form onSubmit={handleGenerate} className="stack gap-sm">
        <label htmlFor="algorithm">
          Algorithm
          <select
            id="algorithm"
            value={selectedAlgo}
            onChange={(event) =>
              setSelectedAlgo(event.target.value as 'RSA' | 'ECC')
            }
          >
            <option value="ECC">ECC (P-256)</option>
            <option value="RSA">RSA-3072</option>
          </select>
        </label>
        <label htmlFor="passphrase">
          Vault passphrase
          <input
            id="passphrase"
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            placeholder="Enter strong passphrase"
          />
        </label>
        <div className="row">
          <button type="submit" disabled={busy || !passphrase}>
            {busy ? 'Working…' : 'Generate / Rotate Keys'}
          </button>
          <button
            type="button"
            className="ghost"
            disabled={busy || !passphrase}
            onClick={handleUnlock}
          >
            Unlock Vault
          </button>
          <button
            type="button"
            className="ghost"
            onClick={lockVault}
            disabled={busy || vaultStatus === 'missing'}
          >
            Lock
          </button>
        </div>
        <p>
          Vault status: <strong>{vaultStatus}</strong>
        </p>
        {publicKey && (
          <details>
            <summary>Public key (Base64)</summary>
            <textarea value={publicKey} readOnly rows={4} />
          </details>
        )}
        {message && <p className="status">{message}</p>}
      </form>
    </section>
  );
};

