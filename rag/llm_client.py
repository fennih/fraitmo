"""
Unified LLM client that automatically switches between Ollama and LM Studio
Detects available services and uses the appropriate one
"""

import requests
import ollama
import time
from typing import Dict, List, Optional, Literal
from dataclasses import dataclass
import json


@dataclass
class ModelInfo:
    """Information about an available model"""
    name: str
    provider: Literal["ollama", "lmstudio"]
    size: Optional[str] = None
    specialized_for: Optional[str] = None


class UnifiedLLMClient:
    """
    Unified LLM client that automatically detects and uses available services
    Supports both Ollama and LM Studio with automatic fallback
    """
    
    def __init__(self, preferred_model: Optional[str] = None):
        """
        Initialize the unified LLM client
        
        Args:
            preferred_model: Preferred model name (will search across providers)
        """
        self.preferred_model = preferred_model or "foundation-sec-8b"
        self.ollama_client = None
        self.lmstudio_base_url = "http://localhost:1234/v1"
        
        # Detect available services and models
        self.available_models = self._detect_available_models()
        self.active_provider, self.active_model = self._select_best_model()
        
        print(f"🤖 Using: {self.active_model} via {self.active_provider} ({len(self.available_models)} models available)")
    
    def _detect_available_models(self) -> List[ModelInfo]:
        """Detect all available models across providers"""
        models = []
        
        # Check Ollama
        try:
            self.ollama_client = ollama.Client()
            ollama_models = self.ollama_client.list()
            
            if 'models' in ollama_models:
                for model in ollama_models['models']:
                    models.append(ModelInfo(
                        name=model.get('name', model.get('model', 'unknown')),
                        provider="ollama",
                        size=model.get('size'),
                        specialized_for="cybersecurity" if "cogito" in model.get('name', '') else None
                    ))
            
            ollama_count = len([m for m in models if m.provider == 'ollama'])
            if ollama_count > 0:
                print(f"✅ Ollama: Found {ollama_count} models")
            
        except Exception as e:
            # Silently handle Ollama not being available
            self.ollama_client = None
        
        # Check LM Studio
        try:
            response = requests.get(f"{self.lmstudio_base_url}/models", timeout=5)
            if response.status_code == 200:
                lms_models = response.json()
                
                for model in lms_models.get('data', []):
                    model_name = model.get('id', 'unknown')
                    specialized = None
                    
                    # Detect specialization from model name
                    if any(term in model_name.lower() for term in ['sec', 'security', 'foundation-sec']):
                        specialized = "cybersecurity"
                    elif any(term in model_name.lower() for term in ['code', 'llama']):
                        specialized = "code"
                    
                    models.append(ModelInfo(
                        name=model_name,
                        provider="lmstudio",
                        specialized_for=specialized
                    ))
            
            lms_count = len([m for m in models if m.provider == 'lmstudio'])
            if lms_count > 0:
                print(f"✅ LM Studio: Found {lms_count} models")
            
        except Exception as e:
            # Silently handle LM Studio not being available
            pass
        
        return models
    
    def _select_best_model(self) -> tuple[str, str]:
        """Select the best available model based on preferences"""
        if not self.available_models:
            raise Exception("No LLM providers available. Please start Ollama or LM Studio.")
        
        # Priority 1: Preferred model if available
        for model in self.available_models:
            if self.preferred_model.lower() in model.name.lower():
                return model.provider, model.name
        
        # Priority 2: Security-specialized models
        security_models = [m for m in self.available_models if m.specialized_for == "cybersecurity"]
        if security_models:
            # Prefer LM Studio for security models (typically newer)
            lms_security = [m for m in security_models if m.provider == "lmstudio"]
            if lms_security:
                return lms_security[0].provider, lms_security[0].name
            return security_models[0].provider, security_models[0].name
        
        # Priority 3: Any available model (prefer LM Studio)
        lms_models = [m for m in self.available_models if m.provider == "lmstudio"]
        if lms_models:
            return lms_models[0].provider, lms_models[0].name
        
        # Fallback to first available
        return self.available_models[0].provider, self.available_models[0].name
    
    def query(self, prompt: str, max_tokens: int = 512, temperature: float = 0.1) -> str:
        """
        Execute a query using the active provider
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Temperature for generation
            
        Returns:
            Model response
        """
        try:
            start_time = time.time()
            
            if self.active_provider == "ollama":
                response = self._query_ollama(prompt, max_tokens, temperature)
            elif self.active_provider == "lmstudio":
                response = self._query_lmstudio(prompt, max_tokens, temperature)
            else:
                raise Exception(f"Unknown provider: {self.active_provider}")
            
            elapsed = time.time() - start_time
            print(f"🤖 Generated response in {elapsed:.2f}s via {self.active_provider}")
            
            return response
            
        except Exception as e:
            print(f"❌ Error with {self.active_provider}: {e}")
            return self._fallback_query(prompt, max_tokens, temperature)
    
    def _query_ollama(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Query using Ollama"""
        response = self.ollama_client.generate(
            model=self.active_model,
            prompt=prompt,
            options={
                'temperature': temperature,
                'num_predict': max_tokens,
                'top_p': 0.9,
                'stop': ['\n\n', '---']
            }
        )
        return response['response'].strip()
    
    def _query_lmstudio(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Query using LM Studio"""
        payload = {
            "model": self.active_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stop": ["\n\n", "---"]
        }
        
        response = requests.post(
            f"{self.lmstudio_base_url}/chat/completions",
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content'].strip()
        else:
            raise Exception(f"LM Studio API error: {response.status_code}")
    
    def _fallback_query(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Try alternative provider if primary fails"""
        print("🔄 Attempting fallback to alternative provider...")
        
        # Try other available models
        for model in self.available_models:
            if model.provider != self.active_provider:
                try:
                    old_provider, old_model = self.active_provider, self.active_model
                    self.active_provider, self.active_model = model.provider, model.name
                    
                    result = self.query(prompt, max_tokens, temperature)
                    print(f"✅ Fallback successful: {model.provider}/{model.name}")
                    return result
                    
                except Exception as e:
                    print(f"⚠️ Fallback failed for {model.provider}: {e}")
                    # Restore original
                    self.active_provider, self.active_model = old_provider, old_model
        
        return f"Error: All LLM providers failed"
    
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
        rag_prompt = self._build_rag_prompt(question, context)
        return self.query(rag_prompt, max_tokens=max_tokens, temperature=0.1)
    
    def _build_rag_prompt(self, question: str, context: str) -> str:
        """Build optimized RAG prompt for threat modeling"""
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
        """Get information about the active model and all available models"""
        return {
            'active_model': {
                'name': self.active_model,
                'provider': self.active_provider
            },
            'available_models': [
                {
                    'name': m.name,
                    'provider': m.provider,
                    'specialized_for': m.specialized_for
                }
                for m in self.available_models
            ],
            'total_models': len(self.available_models)
        }
    
    def switch_model(self, model_name: str) -> bool:
        """
        Switch to a specific model if available
        
        Args:
            model_name: Name of the model to switch to
            
        Returns:
            True if successful
        """
        for model in self.available_models:
            if model_name.lower() in model.name.lower():
                self.active_provider = model.provider
                self.active_model = model.name
                print(f"🔄 Switched to {model.name} via {model.provider}")
                return True
        
        print(f"❌ Model '{model_name}' not found")
        return False
    
    def warm_up(self) -> bool:
        """Warm up the active model"""
        try:
            print(f"🔥 Warming up {self.active_model} via {self.active_provider}...")
            
            warm_up_prompt = "What is cybersecurity?"
            response = self.query(warm_up_prompt, max_tokens=50)
            
            if response and not response.startswith("Error:"):
                print("✅ Model warmed up successfully")
                return True
            else:
                print("❌ Model warm-up failed")
                return False
                
        except Exception as e:
            print(f"❌ Model warm-up failed: {e}")
            return False


def test_unified_client():
    """Test the unified LLM client"""
    print("🧪 Testing Unified LLM Client...")
    
    try:
        # Initialize client with preference for foundation-sec
        client = UnifiedLLMClient(preferred_model="foundation-sec")
        
        # Show model info
        info = client.get_model_info()
        print(f"📊 Model info: {json.dumps(info, indent=2)}")
        
        # Warm up
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
        print(f"🤖 RAG Response: {rag_response}")
        
        # Test model switching
        print("\n🔄 Testing model switching...")
        available_models = [m['name'] for m in info['available_models']]
        if len(available_models) > 1:
            client.switch_model(available_models[1])
            switch_response = client.query("Hello", max_tokens=20)
            print(f"🤖 Switch test: {switch_response}")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")


if __name__ == "__main__":
    test_unified_client() 