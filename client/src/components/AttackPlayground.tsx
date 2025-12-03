import { useState } from 'react';

interface AttackLog {
  id: string;
  type: 'MITM' | 'Replay';
  description: string;
  mitigated: boolean;
  timestamp: number;
}

export const AttackPlayground = () => {
  const [logs, setLogs] = useState<AttackLog[]>([]);
  const [message, setMessage] = useState('');

  const simulateMitm = () => {
    const log: AttackLog = {
      id: crypto.randomUUID(),
      type: 'MITM',
      description:
        message ||
        'Intercepted unsigned DH exchange. Attack succeeds without signatures.',
      mitigated: false,
      timestamp: Date.now(),
    };
    setLogs((prev) => [log, ...prev]);
  };

  const simulateMitmMitigated = () => {
    const log: AttackLog = {
      id: crypto.randomUUID(),
      type: 'MITM',
      description:
        message ||
        'Digital signatures verified. MITM attempt detected and rejected.',
      mitigated: true,
      timestamp: Date.now(),
    };
    setLogs((prev) => [log, ...prev]);
  };

  const simulateReplay = () => {
    const log: AttackLog = {
      id: crypto.randomUUID(),
      type: 'Replay',
      description:
        message ||
        'Replayed ciphertext blocked via nonce/timestamp/sequence checks.',
      mitigated: true,
      timestamp: Date.now(),
    };
    setLogs((prev) => [log, ...prev]);
  };

  return (
    <section className="panel">
      <header>
        <h2>Attack Playground</h2>
        <p>
          Draft attack scenarios to document MITM and replay demonstrations before
          implementing automation scripts.
        </p>
      </header>
      <textarea
        placeholder="Describe the attack or notes…"
        value={message}
        onChange={(event) => setMessage(event.target.value)}
      />
      <div className="row">
        <button type="button" onClick={simulateMitm}>
          MITM (no signatures)
        </button>
        <button type="button" onClick={simulateMitmMitigated}>
          MITM mitigated
        </button>
        <button type="button" onClick={simulateReplay}>
          Replay attempt
        </button>
      </div>
      <ul className="logs">
        {logs.map((log) => (
          <li key={log.id}>
            <header>
              <strong>{log.type}</strong> ·{' '}
              {new Date(log.timestamp).toLocaleTimeString()}
            </header>
            <p>{log.description}</p>
            <p className={log.mitigated ? 'ok' : 'error'}>
              {log.mitigated ? 'Mitigated' : 'Successful attack'}
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
};

