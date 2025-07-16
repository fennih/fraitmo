# Knowledge Base Router Node - Routes to appropriate knowledge base (AI vs General)

from typing import Dict, List, Any
from pipeline.state import ThreatAnalysisState
from rag.document_loader import load_knowledge_base

def knowledge_base_router_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Knowledge Base Router Node
    
    Routes analysis to appropriate knowledge base based on component classification:
    - AI components -> AI/LLM knowledge base  
    - Traditional components -> General knowledge base
    
    Args:
        state: Current threat analysis state
        
    Returns:
        Updated state with loaded knowledge bases
    """
    print("🧠 Knowledge Base Router Node: Loading appropriate knowledge bases...")
    
    try:
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        
        ai_knowledge_base = []
        general_knowledge_base = []
        
        # Load AI knowledge base if we have AI components
        if ai_components:
            print(f"   📚 Loading AI knowledge base for {len(ai_components)} AI components...")
            try:
                ai_kb_path = "knowledge_base/threats/ai_threats"
                ai_knowledge_base = load_knowledge_base(ai_kb_path)
            except Exception as e:
                print(f"   ⚠️ Warning: Could not load AI knowledge base: {e}")
        
        # Load general knowledge base if we have traditional components
        if traditional_components:
            print(f"   🌐 Loading general knowledge base for {len(traditional_components)} traditional components...")
            try:
                general_kb_path = "knowledge_base/threats/general_threats"
                general_knowledge_base = load_knowledge_base(general_kb_path)
            except Exception as e:
                print(f"   ⚠️ Warning: Could not load general knowledge base: {e}")
        
        # Determine routing strategy
        routing_strategy = []
        
        if ai_components and traditional_components:
            routing_strategy.append("hybrid")
            print("   🔀 Hybrid routing: Both AI and traditional knowledge bases loaded")
        elif ai_components:
            routing_strategy.append("ai_focused")
            print("   🤖 AI-focused routing: Only AI knowledge base needed")
        elif traditional_components:
            routing_strategy.append("traditional_focused") 
            print("   🏗️ Traditional-focused routing: Only general knowledge base needed")
        else:
            routing_strategy.append("fallback")
            print("   ❓ Fallback routing: No components classified, loading both knowledge bases")
            # Load both as fallback
            try:
                ai_knowledge_base = load_knowledge_base("knowledge_base/threats/ai_threats")
                general_knowledge_base = load_knowledge_base("knowledge_base/threats/general_threats")
            except Exception as e:
                print(f"   ❌ Fallback loading failed: {e}")
        
        print(f"✅ Knowledge Base Routing Complete:")
        print(f"   📚 AI KB Documents: {len(ai_knowledge_base)}")
        print(f"   🌐 General KB Documents: {len(general_knowledge_base)}")
        print(f"   🔀 Routing Strategy: {', '.join(routing_strategy)}")
        
        return {
            "ai_knowledge_base": ai_knowledge_base,
            "general_knowledge_base": general_knowledge_base,
            "routing_strategy": routing_strategy,
            "processing_status": "knowledge_base_loaded",
            "current_node": "kb_router"
        }
        
    except Exception as e:
        print(f"❌ Knowledge Base Router Error: {e}")
        return {
            "errors": state.get('errors', []) + [f"Knowledge base routing failed: {str(e)}"],
            "processing_status": "error",
            "current_node": "kb_router"
        }


 