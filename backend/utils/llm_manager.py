"""Manager for different LLM providers"""

class LLMManager:
    """Manager for different LLM providers"""
    
    def __init__(self):
        self.ollama_base_url = "http://localhost:11434"
        # self.gemini_api_key = "AIzaSyATHDe7KU7rRmoEVGq-fZw2KD7iN8P5Ryk"
        self.gemini_api_key = "AIzaSyCNd5-v3pLBnuWEX_0KoxnspaYoIr12OUM"
        # self.gemini_api_key = "AIzaSyBbCbSS5DDnBDexyugXH-KhW68uWdgdfx0"
        
    def get_gemini_client(self):
        """Initialize and return Gemini API client"""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.gemini_api_key)
            return genai.GenerativeModel('gemini-pro')
        except ImportError:
            raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")
    
    def query_gemini(self, prompt):
        """Query Gemini API with a prompt"""
        try:
            model = self.get_gemini_client()
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error querying Gemini: {str(e)}"

