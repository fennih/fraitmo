# Knowledge Base Router Node - Routes to appropriate knowledge base (AI vs General)

from typing import Dict, Any
from utils.console import console
from rich.text import Text

def kb_router_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """
    Knowledge Base Router Node
    Routes to appropriate knowledge bases based on component types
    """
    console.print(Text("[INFO]", style="bold blue"), "Knowledge Base Router Node: Loading appropriate knowledge bases...")

    if progress_callback:
        progress_callback(12, "📚 Loading knowledge bases...")

    try:
        # Import here to avoid circular dependencies
        from rag.document_loader import load_threat_knowledge_base

        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])

        # Load complete knowledge base from JSON files
        all_knowledge_base = []
        try:
            all_knowledge_base = load_threat_knowledge_base("knowledge_base")
            console.print(Text("[OK]", style="bold green"), f"Loaded {len(all_knowledge_base)} total threats from knowledge base")
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Warning: Could not load knowledge base: {e}")

        # Filter AI-specific threats
        ai_knowledge_base = []
        general_knowledge_base = []

        for threat in all_knowledge_base:
            if threat.get('ai_specific', False):
                ai_knowledge_base.append(threat)
            else:
                general_knowledge_base.append(threat)

        console.print(Text("[INFO]", style="bold blue"), f"AI threats: {len(ai_knowledge_base)}, General threats: {len(general_knowledge_base)}")

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
        error_msg = f"Knowledge Base Routing Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {
            "ai_knowledge_base": [],
            "general_knowledge_base": [],
            "routing_strategy": [],
            "errors": [error_msg]
        }


