# RAG Threat Searcher Node - Searches for relevant threats in loaded knowledge bases using RAG

from typing import Dict, Any, List
from rich.console import Console
from rich.text import Text

console = Console()

def rag_threat_searcher_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    RAG Threat Search Node
    Searches for relevant threats in loaded knowledge bases
    """
    console.print(Text("[INFO]", style="bold blue"), "RAG Threat Search Node: Searching for relevant threats in knowledge base...")
    
    try:
        # Import here to avoid circular dependencies
        from rag.document_loader import search_threats
        
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        ai_knowledge_base = state.get('ai_knowledge_base', [])
        general_knowledge_base = state.get('general_knowledge_base', [])
        
        ai_threats = []
        traditional_threats = []
        
        # Search threats for AI components
        if ai_components and ai_knowledge_base:
            console.print(Text("[INFO]", style="bold blue"), f"Searching AI threats for {len(ai_components)} AI components...")
            for component in ai_components:
                # Build search query from component characteristics
                search_query = f"{component.get('name', '')} {component.get('type', '')} {component.get('ai_type', '')}"
                component_threats = search_threats(ai_knowledge_base, search_query, max_results=5)
                
                # Add component context to threats
                for threat in component_threats:
                    threat['target_component'] = component
                    threat['source_path'] = 'rag_ai'
                    ai_threats.append(threat)
        
        # Search threats for traditional components
        if traditional_components and general_knowledge_base:
            console.print(Text("[INFO]", style="bold blue"), f"Searching general threats for {len(traditional_components)} traditional components...")
            for component in traditional_components:
                search_query = f"{component.get('name', '')} {component.get('type', '')}"
                component_threats = search_threats(general_knowledge_base, search_query, max_results=5)
                
                # Add component context to threats
                for threat in component_threats:
                    threat['target_component'] = component
                    threat['source_path'] = 'rag_traditional'
                    traditional_threats.append(threat)
        
        # Combine all threats found
        all_threats = ai_threats + traditional_threats
        
        # Store results in state
        state['threats_found'] = all_threats
        state['ai_threats'] = ai_threats
        state['traditional_threats'] = traditional_threats
        
        console.print(Text("[OK]", style="bold green"), "RAG Threat Search Complete:")
        console.print(Text("[INFO]", style="bold blue"), f"AI Threats Found: {len(ai_threats)}")
        console.print(Text("[INFO]", style="bold blue"), f"Traditional Threats Found: {len(traditional_threats)}")
        console.print(Text("[INFO]", style="bold blue"), f"Total Threats: {len(all_threats)}")
        
        return state
        
    except Exception as e:
        error_msg = f"RAG Threat Search Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        state['errors'] = state.get('errors', []) + [error_msg]
        return state


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


def search_cross_zone_threats(dfd_model, knowledge_base: List[Dict]) -> List[Dict[str, Any]]:
    """
    Search for threats specific to cross-zone communications
    
    Args:
        dfd_model: DFD model with cross-zone connections
        knowledge_base: Knowledge base to search in
        
    Returns:
        List of cross-zone specific threats
    """
    cross_zone_threats = []
    
    if not dfd_model or not hasattr(dfd_model, 'cross_zone_connections'):
        return cross_zone_threats
    
    for connection in dfd_model.cross_zone_connections:
        # Search for threats related to cross-zone communications
        for threat in knowledge_base:
            threat_categories = threat.get('categories', [])
            threat_tags = threat.get('tags', [])
            
            # Check for cross-zone related threats
            cross_zone_indicators = [
                'cross-zone', 'trust boundary', 'boundary crossing',
                'zone traversal', 'inter-zone', 'boundary violation'
            ]
            
            is_cross_zone_threat = False
            for indicator in cross_zone_indicators:
                if (any(indicator in cat.lower() for cat in threat_categories) or
                    any(indicator in tag.lower() for tag in threat_tags) or
                    indicator in threat.get('description', '').lower()):
                    is_cross_zone_threat = True
                    break
            
            if is_cross_zone_threat:
                threat_copy = threat.copy()
                threat_copy['target_connection'] = {
                    'source': connection.source_component.name,
                    'destination': connection.destination_component.name,
                    'source_zone': connection.source_component.trust_zone_name,
                    'destination_zone': connection.destination_component.trust_zone_name
                }
                threat_copy['threat_source'] = 'cross_zone'
                cross_zone_threats.append(threat_copy)
    
    return cross_zone_threats


def search_ai_specific_threats(ai_components: List[Dict], knowledge_base: List[Dict]) -> List[Dict[str, Any]]:
    """
    Search for AI/LLM specific threats that may not be component-specific
    
    Args:
        ai_components: List of AI components
        knowledge_base: AI knowledge base
        
    Returns:
        List of AI-specific architectural threats
    """
    ai_specific_threats = []
    
    if not ai_components or not knowledge_base:
        return ai_specific_threats
    
    # Search for general AI threats that apply to any AI system
    for threat in knowledge_base:
        if threat.get('ai_specific', False) and threat.get('applies_to_all_ai', False):
            threat_copy = threat.copy()
            threat_copy['applies_to_components'] = [comp['name'] for comp in ai_components]
            threat_copy['threat_source'] = 'ai_architectural'
            ai_specific_threats.append(threat_copy)
    
    return ai_specific_threats 