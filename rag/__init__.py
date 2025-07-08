"""
RAG (Retrieval Augmented Generation) module for fraitmo
Complete threat analysis using Ollama and knowledge base
"""

from .document_loader import load_knowledge_base
from .ollama_client import OllamaRAGClient
from .threat_analyzer import ThreatAnalyzer, print_threat_analysis

__all__ = [
    "load_knowledge_base",
    "OllamaRAGClient", 
    "ThreatAnalyzer",
    "print_threat_analysis"
] 