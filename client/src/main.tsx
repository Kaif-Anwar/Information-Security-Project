import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App.tsx';
import { AuthProvider } from './context/AuthContext';
import { CryptoProvider } from './context/CryptoContext';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <CryptoProvider>
        <App />
      </CryptoProvider>
    </AuthProvider>
  </StrictMode>,
);
