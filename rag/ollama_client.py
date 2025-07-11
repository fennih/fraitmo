"""
Ollama client optimized for RAG with cogito:14b
Handles model communication and response generation
"""

import ollama
from typing import Dict, List, Optional
import time


class OllamaRAGClient:
    """
    Ollama client specifically designed for RAG operations
    Optimized for cogito:14b and threat modeling
    """
    
    def __init__(self, model: str = "cogito:14b"):
        """
        Initialize the Ollama RAG client
        
        Args:
            model: Ollama model name (default: cogito:14b)
        """
        self.model = model
        self.client = ollama.Client()
        
        # Test connection
        self._test_connection()
        
        print(f"🦙 Ollama RAG Client initialized with {model}")
    
    def _test_connection(self):
        """Test connection to Ollama server"""
        try:
            # Try to list models to verify connection
            models = self.client.list()
            
            # Check if our model is available
            available_models = []
            if 'models' in models:
                available_models = [m.get('name', m.get('model', 'unknown')) for m in models['models']]
            
            if self.model not in available_models:
                print(f"⚠️ Model {self.model} not found. Available: {available_models}")
                print(f"📝 Full response: {models}")
                # Don't raise error, just warn
            
            print(f"✅ Connected to Ollama server")
            
        except Exception as e:
            print(f"⚠️ Connection test failed: {e}")
            print(f"🔄 Attempting to continue anyway...")
    
    def query(self, prompt: str, max_tokens: int = 512, temperature: float = 0.1) -> str:
        """
        Execute a query to the model
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Temperature for generation (0.1 for focused responses)
            
        Returns:
            Model response
        """
        try:
            start_time = time.time()
            
            # Generate response
            response = self.client.generate(
                model=self.model,
                prompt=prompt,
                options={
                    'temperature': temperature,
                    'num_predict': max_tokens,
                    'top_p': 0.9,
                    'stop': ['\n\n', '---']  # Stop tokens for clean responses
                }
            )
            
            elapsed = time.time() - start_time
            
            # Extract response text
            response_text = response['response'].strip()
            
            print(f"🤖 Generated response in {elapsed:.2f}s")
            return response_text
            
        except Exception as e:
            print(f"❌ Error during generation: {e}")
            return f"Error: {str(e)}"
    
    def rag_query(self, question: str, context: str, max_tokens: int = 256) -> str:
        """
        Execute a RAG query with context
        
        Args:
            question: User question
            context: Retrieved context from knowledge base
            max_tokens: Maximum tokens to generate
            
        Returns:
            Contextualized response
        """
        # Create RAG prompt
        rag_prompt = self._build_rag_prompt(question, context)
        
        return self.query(rag_prompt, max_tokens=max_tokens, temperature=0.1)
    
    def _build_rag_prompt(self, question: str, context: str) -> str:
        """
        Build optimized RAG prompt for threat modeling
        
        Args:
            question: User question
            context: Retrieved context
            
        Returns:
            Formatted prompt
        """
        return f"""You are a cybersecurity expert specializing in threat modeling and AI/LLM security.

Context from knowledge base:
{context}

Question: {question}

Instructions:
- Answer based primarily on the provided context
- Be concise and precise
- Focus on actionable security insights
- If context is insufficient, say so clearly

Answer:"""
    
    def get_model_info(self) -> Dict:
        """Get information about the current model"""
        try:
            models = self.client.list()
            
            for model in models['models']:
                if model['name'] == self.model:
                    return {
                        'name': model['name'],
                        'size': model['size'],
                        'modified': model['modified_at']
                    }
            
            return {'error': f'Model {self.model} not found'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def warm_up(self) -> bool:
        """
        Warm up the model with a simple query
        Useful to preload model into memory
        
        Returns:
            True if successful
        """
        try:
            print("🔥 Warming up model...")
            
            warm_up_prompt = "What is cybersecurity?"
            self.query(warm_up_prompt, max_tokens=50)
            
            print("✅ Model warmed up successfully")
            return True
            
        except Exception as e:
            print(f"❌ Model warm-up failed: {e}")
            return False


def test_ollama_client():
    """Test the Ollama RAG client"""
    print("🧪 Testing Ollama RAG Client...")
    
    try:
        # Initialize client
        client = OllamaRAGClient()
        
        # Test model info
        info = client.get_model_info()
        print(f"📊 Model info: {info}")
        
        # Test warm up
        client.warm_up()
        
        # Test basic query
        test_question = "What is SQL injection?"
        response = client.query(test_question, max_tokens=100)
        print(f"🔍 Test query: {test_question}")
        print(f"🤖 Response: {response}")
        
        # Test RAG query
        test_context = "SQL injection is a code injection technique that exploits vulnerabilities in data-driven applications."
        rag_response = client.rag_query(test_question, test_context, max_tokens=100)
        print(f"🔍 RAG query: {test_question}")
        print(f"📚 Context: {test_context}")
        print(f"🤖 RAG Response: {rag_response}")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")


if __name__ == "__main__":
    test_ollama_client() 