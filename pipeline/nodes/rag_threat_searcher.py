# RAG Threat Searcher Node - Searches for relevant threats in loaded knowledge bases using RAG

from typing import Dict, Any, List
import json
import re
from utils.console import console
from rich.text import Text

# Import severity inference function
def _infer_severity_from_threat_name(threat_name: str) -> str:
    """
    Infer severity level based on threat name when not explicitly provided
    """
    threat_name_lower = threat_name.lower()

    # Critical severity threats
    critical_keywords = [
        'injection', 'bypass', 'escalation', 'extraction', 'code execution',
        'remote code', 'privilege escalation', 'authentication bypass'
    ]

    # High severity threats
    high_keywords = [
        'adversarial', 'poisoning', 'manipulation', 'hijacking', 'tampering',
        'unauthorized access', 'data breach', 'xss', 'csrf', 'sql injection'
    ]

    # Medium severity threats
    medium_keywords = [
        'disclosure', 'leak', 'exposure', 'bias', 'hallucination',
        'denial of service', 'dos', 'brute force'
    ]

    # Low severity threats
    low_keywords = [
        'information disclosure', 'minor leak', 'configuration weakness',
        'logging issue', 'weak cipher', 'version disclosure', 'banner disclosure',
        'path disclosure', 'enumeration', 'fingerprinting', 'cache poisoning'
    ]

    # Check for critical threats
    if any(keyword in threat_name_lower for keyword in critical_keywords):
        return 'Critical'

    # Check for high severity threats
    if any(keyword in threat_name_lower for keyword in high_keywords):
        return 'High'

    # Check for medium severity threats
    if any(keyword in threat_name_lower for keyword in medium_keywords):
        return 'Medium'

    # Check for low severity threats
    if any(keyword in threat_name_lower for keyword in low_keywords):
        return 'Low'

    # Default to Low for truly unknown threats (most conservative approach)
    return 'Low'


def rag_threat_searcher_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """
    RAG Threat Search Node
    Performs full RAG (Retrieval + Generation): searches knowledge base and generates contextual threat analysis
    """
    console.print(Text("[INFO]", style="bold blue"), "RAG Threat Search Node: Performing full RAG analysis...")

    if progress_callback:
        progress_callback(14, "🔎 Starting RAG threat search...")

    try:
        # Import here to avoid circular dependencies
        from rag.document_loader import search_threats
        from rag.llm_client import UnifiedLLMClient

        # Initialize LLM client for generation
        llm_client = UnifiedLLMClient()
        if not llm_client.active_model:
            error_msg = "RAG analysis requires LLM for generation - no models available"
            console.print(Text("[ERROR]", style="bold red"), error_msg)
            return {
                "threats_found": [],
                "ai_threats": [],
                "traditional_threats": [],
                "errors": [error_msg]
            }

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
        return {
            "threats_found": [],
            "ai_threats": [],
            "traditional_threats": [],
            "errors": [error_msg]
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
                    if (conn.source_name == comp_name or conn.target_name == comp_name):
                        other_comp = conn.target_name if conn.source_name == comp_name else conn.source_name
                        connected_components.append(other_comp)

            if connected_components:
                dfd_context = f"\nConnected to: {', '.join(set(connected_components))}"

        # Create prompt for LLM generation
        prompt = f"""CYBERSECURITY EXPERT - RAG-ENHANCED THREAT ANALYSIS

COMPONENT PROFILE:
- Name: {comp_name}
- Type: {comp_type}
- Description: {comp_description}
- Category: {component_type.upper()} component{dfd_context}

KNOWLEDGE BASE CONTEXT:
{doc_context}

THREAT MODELING FRAMEWORK:
- Apply STRIDE methodology where applicable
- Reference OWASP guidelines for web components
- Use MITRE ATT&CK/ATLAS for AI components
- Consider CWE common weakness patterns

COMPLIANCE INTEGRATION:
- Map threats to regulatory requirements (GDPR, SOC 2, PCI-DSS)
- Consider industry-specific standards
- Include data protection implications

RAG ANALYSIS TASK:
Based on the knowledge base evidence and component analysis, generate comprehensive, specific security threats. Each threat should:

1. Be directly relevant to the component type and context
2. Reference specific knowledge base evidence and attack vectors
3. Include realistic business and technical impact assessment
4. Be component-specific with technical implementation details
5. Map to appropriate security frameworks (STRIDE, OWASP, CWE)
6. Include compliance implications where relevant
7. Provide probability scoring based on component exposure and KB evidence

ENHANCED OUTPUT FORMAT (JSON):
```json
[
  {{
    "id": "RAG-{comp_name}-001",
    "name": "Specific threat name with technical detail",
    "severity": "Critical|High|Medium|Low",
    "description": "Detailed technical description with KB references",
    "attack_vector": "Step-by-step attack method from knowledge base",
    "impact": "Business and technical impact assessment",
    "kb_evidence": "Specific knowledge base source or pattern",
    "framework_mapping": "STRIDE|OWASP|CWE reference",
    "compliance_impact": "Regulatory implications (GDPR, PCI-DSS, etc.)",
    "likelihood": "High|Medium|Low",
    "probability_score": 85,
    "target_component": "{comp_name}",
    "source_path": "rag_{component_type}",
    "generated_by": "rag_analysis"
  }}
]
```

Generate the threats now:"""

        # Call LLM for generation
        response = llm_client.generate_response(prompt, context=f"RAG analysis: {comp_name} ({component_type})")

        if not response or response.strip() == "":
            console.print(Text("[WARN]", style="bold yellow"), f"Empty response for {comp_name}")
            return []

        threats = []

        # First try: direct JSON parsing
        response_clean = response.strip()
        if response_clean.startswith('```json'):
            response_clean = response_clean[7:]  # Remove ```json prefix
        if response_clean.endswith('```'):
            response_clean = response_clean[:-3]
        response_clean = response_clean.strip()

        try:
            # Try to extract JSON array - IMPROVED PARSING
            threats_data = []

            # Method 1: Direct array parsing
            if response_clean.startswith('[') and response_clean.endswith(']'):
                try:
                    threats_data = json.loads(response_clean)
                    console.print(Text("[DEBUG]", style="dim green"), f"✅ Direct array parsing successful for {comp_name}")
                except json.JSONDecodeError:
                    console.print(Text("[DEBUG]", style="dim yellow"), f"⚠️ Direct array parsing failed for {comp_name}")

            # Method 2: Find JSON array with improved regex
            if not threats_data:
                import re
                # Try multiple patterns to find JSON arrays
                patterns = [
                    r'\[\s*\{.*?\}\s*\]',  # Array with objects
                    r'\[.*?\]',            # General array
                    r'```json\s*(\[.*?\])\s*```',  # Markdown wrapped
                    r'```\s*(\[.*?\])\s*```',      # Code block wrapped
                ]

                for pattern in patterns:
                    json_match = re.search(pattern, response_clean, re.DOTALL | re.MULTILINE)
                    if json_match:
                        try:
                            json_str = json_match.group(1) if len(json_match.groups()) > 0 else json_match.group(0)
                            threats_data = json.loads(json_str)
                            console.print(Text("[DEBUG]", style="dim green"), f"✅ Pattern {pattern[:20]}... successful for {comp_name}")
                            break
                        except json.JSONDecodeError:
                            continue

            # Method 3: Try to find single objects and create array
            if not threats_data:
                # Look for individual threat objects
                object_pattern = r'\{[^{}]*"name"[^{}]*"description"[^{}]*\}'
                matches = re.findall(object_pattern, response_clean, re.DOTALL)

                for match in matches:
                    try:
                        # Clean up the JSON object
                        clean_match = re.sub(r',\s*}', '}', match)  # Remove trailing commas
                        threat_obj = json.loads(clean_match)
                        if threat_obj.get('name'):
                            threats_data.append(threat_obj)
                    except json.JSONDecodeError:
                        continue

                if threats_data:
                    console.print(Text("[DEBUG]", style="dim green"), f"✅ Individual object parsing found {len(threats_data)} threats for {comp_name}")

            # Method 4: Try to parse as single object (not array)
            if not threats_data:
                try:
                    # Maybe it's a single object, not an array
                    single_obj = json.loads(response_clean)
                    if isinstance(single_obj, dict) and single_obj.get('name'):
                        threats_data = [single_obj]
                        console.print(Text("[DEBUG]", style="dim green"), f"✅ Single object parsing successful for {comp_name}")
                except json.JSONDecodeError:
                    pass

            # If we still have no data, raise the error for fallback handling
            if not threats_data:
                console.print(Text("[DEBUG]", style="dim red"), f"❌ All parsing methods failed for {comp_name}. Response preview: {response_clean[:200]}...")
                raise ValueError("No JSON array found")

            # Process each threat
            for threat_data in threats_data:
                if isinstance(threat_data, dict) and threat_data.get('name'):
                    # Ensure required fields
                    threat_data['target_component'] = component
                    threat_data['source_path'] = f'rag_{component_type}'
                    threat_data['generated_by'] = 'rag_analysis'

                    # Assign severity if missing
                    if not threat_data.get('severity') or threat_data.get('severity', '').lower() in ['unknown', '']:
                        threat_data['severity'] = _infer_severity_from_threat_name(threat_data['name'])

                    # Ensure probability_score exists
                    if 'probability_score' not in threat_data:
                        threat_data['probability_score'] = 70  # Default for RAG-generated threats

                    threats.append(threat_data)

            console.print(Text("[OK]", style="bold green"), f"Generated {len(threats)} contextual threats for {comp_name}")

        except json.JSONDecodeError as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Full JSON parse failed for {comp_name}, attempting enhanced recovery...")

            # ENHANCED Recovery: Multiple fallback strategies
            threats = []

            # Strategy 1: Extract threats by name/description patterns
            threat_patterns = [
                # Pattern 1: Standard format with quotes
                r'"name"\s*:\s*"([^"]+)"[^}]*?"description"\s*:\s*"([^"]+)"',
                # Pattern 2: Relaxed format
                r'name["\s]*:\s*["\s]*([^",\n]+)[^}]*?description["\s]*:\s*["\s]*([^",\n]+)',
                # Pattern 3: Find lines that look like threats
                r'(\w+(?:\s+\w+)*(?:\s+(?:Attack|Vulnerability|Injection|Bypass|Escalation)))[:\-\s]*([^.\n]+)',
            ]

            for i, pattern in enumerate(threat_patterns, 1):
                matches = re.finditer(pattern, response, re.DOTALL | re.IGNORECASE)
                pattern_threats = []

                for match in matches:
                    try:
                        threat_name = match.group(1).strip().strip('"').strip("'")
                        threat_desc = match.group(2).strip().strip('"').strip("'")

                        # Clean up and validate
                        if len(threat_name) > 5 and len(threat_desc) > 10:
                            threat_obj = {
                                'name': threat_name,
                                'description': threat_desc,
                                'severity': _infer_severity_from_threat_name(threat_name),
                                'target_component': component,
                                'source_path': f'rag_{component_type}',
                                'generated_by': 'rag_analysis',
                                'probability_score': 70,
                                'likelihood': 'Medium',
                                'recovered': True,
                                'recovery_pattern': i
                            }
                            pattern_threats.append(threat_obj)

                    except (AttributeError, IndexError):
                        continue

                if pattern_threats:
                    threats.extend(pattern_threats)
                    console.print(Text("[DEBUG]", style="dim green"), f"✅ Recovery pattern {i} found {len(pattern_threats)} threats for {comp_name}")

            # Strategy 2: Generic threat extraction from content
            if not threats:
                # Look for security-related terms and create generic threats
                security_keywords = [
                    'injection', 'bypass', 'escalation', 'vulnerability', 'attack',
                    'unauthorized', 'exploit', 'breach', 'hijacking', 'tampering'
                ]

                found_keywords = []
                for keyword in security_keywords:
                    if keyword.lower() in response.lower():
                        found_keywords.append(keyword)

                if found_keywords:
                    for keyword in found_keywords[:3]:  # Max 3 generic threats
                        threat_obj = {
                            'name': f"{keyword.title()} Vulnerability in {comp_name}",
                            'description': f"Potential {keyword} vulnerability identified in {comp_name} component based on threat analysis.",
                            'severity': _infer_severity_from_threat_name(keyword),
                            'target_component': component,
                            'source_path': f'rag_{component_type}',
                            'generated_by': 'rag_analysis',
                            'probability_score': 60,
                            'likelihood': 'Medium',
                            'recovered': True,
                            'recovery_pattern': 'generic'
                        }
                        threats.append(threat_obj)

                    console.print(Text("[DEBUG]", style="dim blue"), f"🔧 Generic recovery created {len(threats)} threats for {comp_name}")

            if threats:
                console.print(Text("[OK]", style="bold green"), f"Recovered {len(threats)} threats from malformed response for {comp_name}")
                console.print(Text("[RECOVERY]", style="bold cyan"), f"Enhanced recovery successful for {comp_name}")
            else:
                console.print(Text("[WARN]", style="bold yellow"), f"Could not extract any threats from LLM response for {comp_name}")
                console.print(Text("[DEBUG]", style="dim red"), f"Response sample: {response[:300]}...")

        # Final validation and cleanup
        validated_threats = []
        for threat in threats:
            if threat.get('name') and threat.get('description'):
                validated_threats.append(threat)

        console.print(Text("[OK]", style="bold green"), f"Generated {len(validated_threats)} contextual threats for {comp_name}")
        return validated_threats

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Error generating contextual threats for {comp_name}: {e}")
        return []
