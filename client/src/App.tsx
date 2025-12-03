import './App.css';
import { AuthPanel } from './components/AuthPanel';
import { KeyManagementCard } from './components/KeyManagementCard';
import { SessionConsole } from './components/SessionConsole';
import { MessageComposer } from './components/MessageComposer';
import { FileEncryptor } from './components/FileEncryptor';
import { AttackPlayground } from './components/AttackPlayground';
import { LLMAssistantPanel } from './components/LLMAssistantPanel';

const App = () => (
  <div className="app-shell">
    <header className="hero">
      <div>
        <p className="tag">Information Security · Semester Project</p>
        <h1>Secure E2EE Messaging & File Sharing Workbench</h1>
        <p>
          React + Web Crypto playground for building and validating the required
          hybrid cryptography flows (auth, key management, AES-GCM messaging,
          encrypted file transfer, and attack simulations).
        </p>
      </div>
    </header>
    <main className="grid">
      <AuthPanel />
      <KeyManagementCard />
      <SessionConsole />
      <MessageComposer />
      <FileEncryptor />
      <AttackPlayground />
      <LLMAssistantPanel />
    </main>
  </div>
);

export default App;
