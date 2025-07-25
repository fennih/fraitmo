# RAG Threat Searcher Node - Searches for relevant threats in loaded knowledge bases using RAG

from typing import Dict, Any, List
from rich.console import Console
from rich.text import Text

console = Console()

def rag_threat_searcher_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    RAG Threat Search Node
    Performs full RAG (Retrieval + Generation): searches knowledge base and generates contextual threat analysis
    """
    console.print(Text("[INFO]", style="bold blue"), "RAG Threat Search Node: Performing full RAG analysis...")

    try:
        # Import here to avoid circular dependencies
        from rag.document_loader import search_threats
        from rag.llm_client import UnifiedLLMClient

        # Initialize LLM client for generation
        llm_client = UnifiedLLMClient()
        if not llm_client.active_model:
            error_msg = "RAG analysis requires LLM for generation - no models available"
            console.print(Text("[ERROR]", style="bold red"), error_msg)
            return {"errors": [error_msg]}

        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        ai_knowledge_base = state.get('ai_knowledge_base', [])
        general_knowledge_base = state.get('general_knowledge_base', [])
        dfd_model = state.get('dfd_model')

        ai_threats = []
        traditional_threats = []

        # Perform RAG analysis for AI components
        if ai_components and ai_knowledge_base:
            console.print(Text("[INFO]", style="bold blue"), f"Performing RAG analysis for {len(ai_components)} AI components...")
            for component in ai_components:
                # Step 1: Retrieval - search relevant documents
                search_query = f"{component.get('name', '')} {component.get('type', '')} {component.get('ai_type', '')}"
                relevant_docs = search_threats(ai_knowledge_base, search_query, max_results=5)

                # Step 2: Generation - use LLM to analyze component with retrieved context
                if relevant_docs:
                    component_threats = _generate_contextual_threats(llm_client, component, relevant_docs, dfd_model, 'ai')
                    ai_threats.extend(component_threats)

        # Perform RAG analysis for traditional components
        if traditional_components and general_knowledge_base:
            console.print(Text("[INFO]", style="bold blue"), f"Performing RAG analysis for {len(traditional_components)} traditional components...")
            for component in traditional_components:
                # Step 1: Retrieval - search relevant documents
                search_query = f"{component.get('name', '')} {component.get('type', '')}"
                relevant_docs = search_threats(general_knowledge_base, search_query, max_results=5)

                # Step 2: Generation - use LLM to analyze component with retrieved context
                if relevant_docs:
                    component_threats = _generate_contextual_threats(llm_client, component, relevant_docs, dfd_model, 'traditional')
                    traditional_threats.extend(component_threats)

        # Combine all threats found
        all_threats = ai_threats + traditional_threats

        # Store results in state
        console.print(Text("[OK]", style="bold green"), "RAG Analysis Complete:")
        console.print(Text("[INFO]", style="bold blue"), f"AI Threats Generated: {len(ai_threats)}")
        console.print(Text("[INFO]", style="bold blue"), f"Traditional Threats Generated: {len(traditional_threats)}")
        console.print(Text("[INFO]", style="bold blue"), f"Total Threats: {len(all_threats)}")

        # Return only the fields we're modifying
        return {
            "threats_found": all_threats,
            "ai_threats": ai_threats,
            "traditional_threats": traditional_threats
        }

    except Exception as e:
        error_msg = f"RAG Threat Search Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}


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


def _generate_contextual_threats(llm_client, component: Dict[str, Any], relevant_docs: List[Dict], dfd_model, component_type: str) -> List[Dict[str, Any]]:
    """
    Use LLM to generate contextual threat analysis based on retrieved knowledge base documents

    Args:
        llm_client: UnifiedLLMClient instance
        component: Component to analyze
        relevant_docs: Retrieved documents from knowledge base
        dfd_model: DFD model for context
        component_type: 'ai' or 'traditional'

    Returns:
        List of generated threats with contextual analysis
    """
    try:
        # Build context from retrieved documents
        doc_context = ""
        for i, doc in enumerate(relevant_docs[:3], 1):  # Limit to top 3 docs
            doc_context += f"\n{i}. {doc.get('name', 'Unknown')}: {doc.get('description', '')}\n"
            if doc.get('attack_vectors'):
                doc_context += f"   Attack vectors: {', '.join(doc.get('attack_vectors', []))}\n"
            if doc.get('severity'):
                doc_context += f"   Severity: {doc.get('severity')}\n"

        # Build component context
        comp_name = component.get('name', 'Unknown Component')
        comp_type = component.get('type', 'Unknown Type')
        comp_description = component.get('description', '')

        # Build DFD context
        dfd_context = ""
        if dfd_model:
            connected_components = []
            if hasattr(dfd_model, 'connections'):
                for conn in dfd_model.connections:
                    if (conn.get('source') == comp_name or conn.get('target') == comp_name):
                        other_comp = conn.get('target') if conn.get('source') == comp_name else conn.get('source')
                        connected_components.append(other_comp)

            if connected_components:
                dfd_context = f"\nConnected to: {', '.join(set(connected_components))}"

        # Create prompt for LLM generation
        prompt = f"""You are a cybersecurity expert analyzing a specific component in a system architecture.

COMPONENT TO ANALYZE:
- Name: {comp_name}
- Type: {comp_type}
- Description: {comp_description}
- Category: {component_type.upper()} component{dfd_context}

RELEVANT THREAT KNOWLEDGE:
{doc_context}

TASK:
Based on the provided threat knowledge and component details, generate 2-3 specific, actionable security threats that could affect this component. Each threat should:

1. Be directly relevant to the component type and context
2. Reference appropriate attack vectors from the knowledge base
3. Include realistic impact assessment
4. Be specific to this component (not generic)

OUTPUT FORMAT (JSON):
```json
[
  {{
    "name": "Specific threat name",
    "severity": "Critical|High|Medium|Low",
    "description": "Detailed description of the threat",
    "attack_vector": "How the attack could be executed",
    "impact": "Potential business/technical impact",
    "likelihood": "High|Medium|Low",
    "target_component": "{comp_name}",
    "source_path": "rag_{component_type}",
    "generated_by": "rag_analysis"
  }}
]
```

Generate the threats now:"""

        # Call LLM for generation
        response = llm_client.generate_response(prompt)

        if response and response.strip():
            # Try to extract JSON from response
            import json
            import re

            # Look for JSON in the response
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON without markdown
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    console.print(Text("[WARN]", style="bold yellow"), f"Could not extract JSON from LLM response for {comp_name}")
                    return []

            try:
                threats = json.loads(json_str)
                if isinstance(threats, list):
                    # Validate and clean up threats
                    validated_threats = []
                    for threat in threats:
                        if isinstance(threat, dict) and threat.get('name') and threat.get('description'):
                            # Ensure required fields
                            threat['target_component'] = component
                            threat['source_path'] = f'rag_{component_type}'
                            threat['generated_by'] = 'rag_analysis'
                            validated_threats.append(threat)

                    console.print(Text("[OK]", style="bold green"), f"Generated {len(validated_threats)} contextual threats for {comp_name}")
                    return validated_threats
                else:
                    console.print(Text("[WARN]", style="bold yellow"), f"LLM response was not a list for {comp_name}")
                    return []

            except json.JSONDecodeError as e:
                console.print(Text("[WARN]", style="bold yellow"), f"Could not parse JSON from LLM response for {comp_name}: {e}")
                return []
        else:
            console.print(Text("[WARN]", style="bold yellow"), f"Empty LLM response for {comp_name}")
            return []

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Error generating contextual threats for {comp_name}: {e}")
        return []
