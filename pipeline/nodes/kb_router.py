# Knowledge Base Router Node - Routes to appropriate knowledge base (AI vs General)

from typing import Dict, Any
from rich.console import Console
from rich.text import Text

console = Console()

def kb_router_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Knowledge Base Router Node
    Routes to appropriate knowledge bases based on component types
    """
    console.print(Text("[INFO]", style="bold blue"), "Knowledge Base Router Node: Loading appropriate knowledge bases...")
    
    try:
        # Import here to avoid circular dependencies
        from rag.document_loader import load_threat_knowledge_base
        
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        
        # Load AI-specific knowledge base
        ai_knowledge_base = []
        try:
            ai_knowledge_base = load_threat_knowledge_base("knowledge_base/ai_threats")
            if not ai_knowledge_base:
                # Fallback to general knowledge base for AI components
                ai_knowledge_base = load_threat_knowledge_base("knowledge_base")
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Warning: Could not load AI knowledge base: {e}")
            
        # Load general knowledge base
        general_knowledge_base = []
        try:
            general_knowledge_base = load_threat_knowledge_base("knowledge_base")
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Warning: Could not load general knowledge base: {e}")
        
        # Route based on component composition
        if ai_components and not traditional_components:
            console.print(Text("[INFO]", style="bold blue"), "AI-focused routing: Only AI knowledge base needed")
            routing_strategy = 'ai_only'
        elif traditional_components and not ai_components:
            console.print(Text("[INFO]", style="bold blue"), "Traditional-focused routing: Only general knowledge base needed")
            routing_strategy = 'traditional_only'
        else:
            routing_strategy = 'hybrid'
        
        # Fallback: ensure we have at least one knowledge base
        if not ai_knowledge_base and not general_knowledge_base:
            try:
                # Last resort: try to load any available knowledge base
                fallback_kb = load_threat_knowledge_base()
                general_knowledge_base = fallback_kb
            except Exception as e:
                console.print(Text("[ERROR]", style="bold red"), f"Fallback loading failed: {e}")
        
        console.print(Text("[OK]", style="bold green"), "Knowledge Base Routing Complete:")
        console.print(Text("[INFO]", style="bold blue"), f"AI Knowledge Base: {len(ai_knowledge_base)} documents")
        console.print(Text("[INFO]", style="bold blue"), f"General Knowledge Base: {len(general_knowledge_base)} documents")
        console.print(Text("[INFO]", style="bold blue"), f"Routing Strategy: {routing_strategy}")
        
        # Return only the fields we're modifying
        return {
            "ai_knowledge_base": ai_knowledge_base,
            "general_knowledge_base": general_knowledge_base,
            "routing_strategy": [routing_strategy]
        }
        
    except Exception as e:
        error_msg = f"Knowledge Base Router Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}


 