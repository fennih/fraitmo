"""
RAG (Retrieval Augmented Generation) module for fraitmo
Complete threat analysis using Ollama, LM Studio and knowledge base
Enhanced with vector search capabilities
"""

from .document_loader import (
    load_threat_knowledge_base,
    search_threats,
    search_threats_vector,
    search_threats_hybrid,
    get_vector_store_stats,
    reset_vector_store
)
from .llm_client import UnifiedLLMClient
from .threat_analyzer import ThreatAnalyzer

# Optional import for vector store (may fail if dependencies not installed)
try:
    from .vector_store import ThreatVectorStore
    VECTOR_SEARCH_AVAILABLE = True
except ImportError:
    ThreatVectorStore = None
    VECTOR_SEARCH_AVAILABLE = False

__all__ = [
    "load_threat_knowledge_base",
    "search_threats",
    "search_threats_vector",
    "search_threats_hybrid",
    "get_vector_store_stats",
    "reset_vector_store",
    "UnifiedLLMClient",
    "ThreatAnalyzer",
    "ThreatVectorStore",
    "VECTOR_SEARCH_AVAILABLE"
]
