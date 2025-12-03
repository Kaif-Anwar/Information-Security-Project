import { useState } from 'react';
import { llmManager } from '../lib/llm/LLMManager';

export const LLMAssistantPanel = () => {
  const [prompt, setPrompt] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!prompt.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const result = await llmManager.chat(prompt);
      setResponse(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="panel">
      <header>
        <h2>Gemini Assistant</h2>
        <p>Use for conceptual help or debugging notes.</p>
      </header>
      <textarea
        value={prompt}
        onChange={(event) => setPrompt(event.target.value)}
        placeholder="Ask Gemini for crypto design feedback..."
      />
      <button type="button" onClick={handleSubmit} disabled={loading}>
        {loading ? 'Querying…' : 'Send to Gemini'}
      </button>
      {error && <p className="error">{error}</p>}
      {response && (
        <article className="response">
          <h3>LLM Response</h3>
          <p>{response}</p>
        </article>
      )}
    </section>
  );
};

