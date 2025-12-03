type GeminiContent = {
  role: 'user' | 'model';
  parts: { text: string }[];
};

export class LLMManager {
  private readonly geminiApiKey =
    'AIzaSyCNd5-v3pLBnuWEX_0KoxnspaYoIr12OUM';

  private readonly baseUrl =
    'https://generativelanguage.googleapis.com/v1beta';

  async chat(prompt: string): Promise<string> {
    const url = `${this.baseUrl}/models/gemini-1.5-flash:generateContent?key=${this.geminiApiKey}`;
    const body = {
      contents: [
        {
          role: 'user',
          parts: [{ text: prompt }],
        } satisfies GeminiContent,
      ],
    };
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.statusText}`);
    }
    const data = await response.json();
    return (
      data?.candidates?.[0]?.content?.parts?.[0]?.text ??
      'No response generated.'
    );
  }
}

export const llmManager = new LLMManager();

