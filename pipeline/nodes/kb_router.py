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


def threat_search_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Threat Search Node
    
    Searches for relevant threats in the loaded knowledge bases
    based on component types and characteristics.
    
    Args:
        state: Current threat analysis state
        
    Returns:
        Updated state with found threats
    """
    print("🔍 Threat Search Node: Searching for relevant threats...")
    
    try:
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        ai_knowledge_base = state.get('ai_knowledge_base', [])
        general_knowledge_base = state.get('general_knowledge_base', [])
        
        ai_threats = []
        traditional_threats = []
        
        # Search AI threats for AI components
        if ai_components and ai_knowledge_base:
            print(f"   🤖 Searching AI threats for {len(ai_components)} AI components...")
            for component in ai_components:
                component_threats = search_threats_for_component(
                    component, ai_knowledge_base, "ai"
                )
                ai_threats.extend(component_threats)
        
        # Search traditional threats for traditional components
        if traditional_components and general_knowledge_base:
            print(f"   🏗️ Searching general threats for {len(traditional_components)} traditional components...")
            for component in traditional_components:
                component_threats = search_threats_for_component(
                    component, general_knowledge_base, "traditional"
                )
                traditional_threats.extend(component_threats)
        
        # Combine all threats
        all_threats = ai_threats + traditional_threats
        
        print(f"✅ Threat Search Complete:")
        print(f"   🤖 AI Threats Found: {len(ai_threats)}")
        print(f"   🏗️ Traditional Threats Found: {len(traditional_threats)}")
        print(f"   📊 Total Threats: {len(all_threats)}")
        
        return {
            "ai_threats": ai_threats,
            "traditional_threats": traditional_threats,
            "threats_found": all_threats,
            "processing_status": "threats_searched",
            "current_node": "threat_search"
        }
        
    except Exception as e:
        print(f"❌ Threat Search Error: {e}")
        return {
            "errors": state.get('errors', []) + [f"Threat search failed: {str(e)}"],
            "processing_status": "error",
            "current_node": "threat_search"
        }


def search_threats_for_component(component: Dict[str, Any], knowledge_base: List[Dict], threat_type: str) -> List[Dict[str, Any]]:
    """
    Search threats relevant to a specific component
    
    Args:
        component: Component to search threats for
        knowledge_base: Knowledge base to search in
        threat_type: "ai" or "traditional"
        
    Returns:
        List of relevant threats
    """
    relevant_threats = []
    
    comp_name = component.get('name', '').lower()
    comp_type = component.get('type', '').lower()
    comp_vendor = component.get('vendor', '').lower()
    
    for threat in knowledge_base:
        # Check if threat is relevant to this component
        is_relevant = False
        
        # Check affected components
        affected_components = threat.get('affected_components', [])
        for affected in affected_components:
            if (affected.lower() in comp_name or 
                affected.lower() in comp_type or
                comp_type in affected.lower()):
                is_relevant = True
                break
        
        # For AI threats, check AI-specific indicators
        if threat_type == "ai" and threat.get('ai_specific', False):
            ai_keywords = ['llm', 'ai', 'model', 'prompt', 'agent']
            if any(keyword in comp_name or keyword in comp_type for keyword in ai_keywords):
                is_relevant = True
        
        # For traditional threats, check if it's not AI-specific
        if threat_type == "traditional" and not threat.get('ai_specific', True):
            is_relevant = True
        
        if is_relevant:
            threat_copy = threat.copy()
            threat_copy['target_component'] = component
            threat_copy['threat_source'] = threat_type
            relevant_threats.append(threat_copy)
    
    return relevant_threats 