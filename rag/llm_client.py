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
import httpx
from typing import List, Dict, Any, Optional, Union
from rich.console import Console
from rich.text import Text

console = Console()


@dataclass
class ModelInfo:
    """Information about an available model"""
    name: str
    provider: Literal["ollama", "lmstudio"]
    size: Optional[str] = None
    specialized_for: Optional[str] = None


class LLMModel:
    """Represents an LLM model with its provider and capabilities"""
    def __init__(self, name: str, provider: str, url: str):
        self.name = name
        self.provider = provider  
        self.url = url
        self.is_cybersec = self._is_cybersecurity_model(name)
    
    def _is_cybersecurity_model(self, name: str) -> bool:
        """Check if model name suggests cybersecurity specialization"""
        cybersec_keywords = ['sec', 'security', 'cyber', 'threat', 'vuln']
        return any(keyword in name.lower() for keyword in cybersec_keywords)
    
    def __repr__(self):
        return f"LLMModel({self.name}, {self.provider}, cybersec={self.is_cybersec})"


class UnifiedLLMClient:
    """Unified client for multiple LLM providers with automatic fallback"""
    
    # Class-level warning flag for singleton warning pattern
    _no_models_warning_shown = False
    
    def __init__(self):
        self.providers = {
            'lm_studio': 'http://localhost:1234/v1/',
            'ollama': 'http://localhost:11434/'
        }
        
        self.available_models: List[LLMModel] = []
        self.active_model: Optional[str] = None
        self.active_provider: Optional[str] = None
        
        self._detect_available_providers()
    
    def _detect_available_providers(self):
        """Detect available LLM providers and models"""
        for provider, base_url in self.providers.items():
            try:
                models = self._get_models_from_provider(provider, base_url)
                if models:
                    self.available_models.extend(models)
                    console.print(Text("[INFO]", style="bold blue"), f"Found {len(models)} models in {provider}")
            except Exception as e:
                # Silent detection - only show warnings for critical issues
                pass
        
        if self.available_models:
            # Priority: Cybersecurity models > LM Studio > Ollama > Any available
            self._select_best_model()
            console.print(Text("[OK]", style="bold green"), f"Using: {self.active_model} via {self.active_provider}")
        else:
            # Singleton warning pattern - only warn once per session
            if not UnifiedLLMClient._no_models_warning_shown:
                console.print(Text("[WARN]", style="bold yellow"), "No LLM models detected. Start Ollama or LM Studio.")
                UnifiedLLMClient._no_models_warning_shown = True
    
    def _get_models_from_provider(self, provider: str, base_url: str) -> List[LLMModel]:
        """Get available models from a specific provider"""
        models = []
        
        try:
            if provider == 'lm_studio':
                response = httpx.get(f"{base_url}models", timeout=3.0)
                if response.status_code == 200:
                    model_data = response.json()
                    for model in model_data.get('data', []):
                        models.append(LLMModel(
                            name=model['id'], 
                            provider=provider,
                            url=base_url
                        ))
                        
            elif provider == 'ollama':
                response = httpx.get(f"{base_url}api/tags", timeout=3.0)
                if response.status_code == 200:
                    model_data = response.json()
                    for model in model_data.get('models', []):
                        models.append(LLMModel(
                            name=model['name'],
                            provider=provider, 
                            url=base_url
                        ))
                        
        except Exception:
            # Silent failure for detection
            pass
            
        return models
    
    def _select_best_model(self):
        """Select the best available model based on priority"""
        if not self.available_models:
            return
            
        # Priority 1: Cybersecurity specialized models
        cybersec_models = [m for m in self.available_models if m.is_cybersec]
        if cybersec_models:
            # Prefer LM Studio cybersec models over Ollama
            lm_cybersec = [m for m in cybersec_models if m.provider == 'lm_studio']
            if lm_cybersec:
                best_model = lm_cybersec[0]
            else:
                best_model = cybersec_models[0]
        else:
            # Priority 2: LM Studio models (generally more recent)
            lm_models = [m for m in self.available_models if m.provider == 'lm_studio']
            if lm_models:
                best_model = lm_models[0]
            else:
                # Priority 3: Any available model
                best_model = self.available_models[0]
        
        self.active_model = best_model.name
        self.active_provider = best_model.provider
    
    def generate_response(self, prompt: str, max_tokens: int = 500, temperature: float = 0.1) -> str:
        """Generate response using the active model"""
        if not self.active_model:
            raise Exception("No active model available")
        
        provider_url = self.providers[self.active_provider]
        
        try:
            start_time = time.time()
            
            if self.active_provider == 'lm_studio':
                response = self._query_lm_studio(provider_url, prompt, max_tokens, temperature)
            elif self.active_provider == 'ollama':
                response = self._query_ollama(provider_url, prompt, max_tokens, temperature)
            else:
                raise Exception(f"Unsupported provider: {self.active_provider}")
            
            elapsed = time.time() - start_time
            console.print(Text("[OK]", style="bold green"), f"Generated response in {elapsed:.2f}s via {self.active_provider}")
            
            return response
            
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Error with {self.active_provider}: {e}")
            
            # Try to fallback to another provider
            return self._attempt_fallback(prompt, max_tokens, temperature)
    
    def _attempt_fallback(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Attempt to use fallback providers if primary fails"""
        console.print(Text("[INFO]", style="bold blue"), "Attempting fallback to alternative provider...")
        
        # Find alternative models
        fallback_models = [m for m in self.available_models 
                          if m.provider != self.active_provider]
        
        for model in fallback_models:
            try:
                # Temporarily switch to fallback
                original_model = self.active_model
                original_provider = self.active_provider
                
                self.active_model = model.name
                self.active_provider = model.provider
                
                console.print(Text("[OK]", style="bold green"), f"Fallback successful: {model.provider}/{model.name}")
                return self.generate_response(prompt, max_tokens, temperature)
                
            except Exception as e:
                console.print(Text("[WARN]", style="bold yellow"), f"Fallback failed for {model.provider}: {e}")
                continue
        
        raise Exception("All providers failed")
    
    def _query_lm_studio(self, provider_url: str, prompt: str, max_tokens: int, temperature: float) -> str:
        """Query LM Studio API"""
        try:
            payload = {
                "model": self.active_model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False
            }
            
            
            response = requests.post(
                f"{provider_url}chat/completions",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=120  # Increased timeout for longer responses
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'choices' in data and len(data['choices']) > 0:
                    return data['choices'][0]['message']['content'].strip()
                else:
                    raise Exception("No valid response from LM Studio")
            else:
                raise Exception(f"LM Studio API error: {response.status_code} - {response.text}")
                
        except Exception as e:
            raise Exception(f"LM Studio query failed: {e}")
    
    def _query_ollama(self, provider_url: str, prompt: str, max_tokens: int, temperature: float) -> str:
        """Query Ollama API"""
        try:
            client = ollama.Client(host=provider_url)
            response = client.chat(
                model=self.active_model,
                messages=[{'role': 'user', 'content': prompt}],
                options={
                    'num_predict': max_tokens,
                    'temperature': temperature
                }
            )
            
            if 'message' in response and 'content' in response['message']:
                return response['message']['content'].strip()
            else:
                raise Exception("No valid response from Ollama")
                
        except Exception as e:
            raise Exception(f"Ollama query failed: {e}")
    
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
        return self.generate_response(rag_prompt, max_tokens=max_tokens, temperature=0.1)
    
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
                    'specialized_for': m.is_cybersec # Changed to is_cybersec
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
        if not self.available_models:
            console.print(Text("[ERROR]", style="bold red"), "No models available to switch to")
            return False
            
        for model in self.available_models:
            if model_name.lower() in model.name.lower():
                self.active_provider = model.provider
                self.active_model = model.name
                console.print(Text("[OK]", style="bold green"), f"Switched to {model.name} via {model.provider}")
                return True
        
        console.print(Text("[ERROR]", style="bold red"), f"Model '{model_name}' not found")
        return False
    
    def warm_up(self) -> bool:
        """Warm up the active model"""
        if not self.active_provider or not self.active_model:
            return False
            
        try:
            console.print(Text("[INFO]", style="bold blue"), f"Warming up {self.active_model} via {self.active_provider}...")
            
            warm_up_prompt = "What is cybersecurity?"
            response = self.generate_response(warm_up_prompt, max_tokens=50)
            
            if response and not response.startswith("Error:"):
                console.print(Text("[OK]", style="bold green"), "Model warmed up successfully")
                return True
            else:
                console.print(Text("[ERROR]", style="bold red"), "Model warm-up failed")
                return False
                
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Model warm-up failed: {e}")
            return False


def test_unified_client():
    """Test the unified LLM client"""
    console.print(Text("[INFO]", style="bold blue"), "Testing Unified LLM Client...")
    
    try:
        # Initialize client
        client = UnifiedLLMClient()
        
        # Show model info
        info = client.get_model_info()
        console.print(Text("[INFO]", style="bold blue"), f"Model info: {json.dumps(info, indent=2)}")
        
        # Warm up
        client.warm_up()
        
        # Test basic query
        test_question = "What is SQL injection?"
        response = client.generate_response(test_question, max_tokens=100)
        console.print(Text("[INFO]", style="bold blue"), f"Test query: {test_question}")
        console.print(Text("[OK]", style="bold green"), f"Response: {response}")
        
        # Test RAG query
        test_context = "SQL injection is a code injection technique that exploits vulnerabilities in data-driven applications."
        rag_response = client.rag_query(test_question, test_context, max_tokens=100)
        console.print(Text("[INFO]", style="bold blue"), f"RAG query: {test_question}")
        console.print(Text("[OK]", style="bold green"), f"RAG Response: {rag_response}")
        
        # Test model switching
        console.print(Text("[INFO]", style="bold blue"), "\nTesting model switching...")
        available_models = [m['name'] for m in info['available_models']]
        if len(available_models) > 1:
            client.switch_model(available_models[1])
            switch_response = client.generate_response("Hello", max_tokens=20)
            console.print(Text("[OK]", style="bold green"), f"Switch test: {switch_response}")
        
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Test failed: {e}")


if __name__ == "__main__":
    test_unified_client() 