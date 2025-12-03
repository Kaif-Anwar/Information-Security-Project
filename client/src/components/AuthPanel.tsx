import { useState, type FormEvent } from 'react';
import { useAuth } from '../context/AuthContext';

export const AuthPanel = () => {
  const { userId, setCredentials, logout } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState<'login' | 'register'>('register');
  const [status, setStatus] = useState<string | null>(null);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!username || !password) {
      setStatus('Username and password are required');
      return;
    }
    // TODO: Replace with real API calls once backend is ready.
    const fakeToken = btoa(`${username}:${Date.now()}`);
    setCredentials(username, fakeToken);
    setStatus(`${mode === 'login' ? 'Logged in' : 'Registered'} as ${username}`);
    setUsername('');
    setPassword('');
  };

  if (userId) {
    return (
      <section className="panel">
        <header>
          <h2>Session</h2>
          <p>Authenticated as {userId}</p>
        </header>
        <button type="button" onClick={logout}>
          Sign out
        </button>
        {status && <p className="status">{status}</p>}
      </section>
    );
  }

  return (
    <section className="panel">
      <header>
        <h2>{mode === 'login' ? 'Login' : 'Register'}</h2>
        <p>Credentials stay on-device for now. Backend wiring pending.</p>
      </header>
      <form onSubmit={handleSubmit} className="stack gap-sm">
        <label htmlFor="username">
          Username
          <input
            id="username"
            name="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
          />
        </label>
        <label htmlFor="password">
          Password
          <input
            id="password"
            type="password"
            name="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete={
              mode === 'login' ? 'current-password' : 'new-password'
            }
          />
        </label>
        <div className="row">
          <button type="submit">
            {mode === 'login' ? 'Log in' : 'Create account'}
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
          >
            Switch to {mode === 'login' ? 'register' : 'login'}
          </button>
        </div>
        {status && <p className="status">{status}</p>}
      </form>
    </section>
  );
};

