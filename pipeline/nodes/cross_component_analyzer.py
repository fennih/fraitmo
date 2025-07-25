# Cross-Component Threat Analysis Node - Analyzes data flows and trust boundary crossings

from typing import Dict, Any, List
from rich.console import Console
from rich.text import Text

console = Console()

def cross_component_analyzer_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cross-Component Analysis Node
    Analyzes data flows between components to identify trust boundary threats
    """
    # Check if cross-component analysis was already completed
    existing_threats = state.get('cross_component_threats', [])
    if existing_threats:
        console.print(Text("[INFO]", style="bold blue"), f"Cross-Component Analysis: Already completed with {len(existing_threats)} threats")
        return {}  # Return empty dict to avoid duplicating state

    console.print(Text("[INFO]", style="bold blue"), "Cross-Component Analysis: Analyzing data flows and trust boundaries...")

    try:
        # Get DFD model and components
        dfd_model = state.get('dfd_model')
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])

        if not dfd_model:
            console.print(Text("[WARN]", style="bold yellow"), "No DFD model available for cross-component analysis")
            return {"warnings": ["No DFD model available for cross-component analysis"]}

        all_components = ai_components + traditional_components

        # Initialize LLM client for advanced threat analysis
        from rag.llm_client import UnifiedLLMClient

        try:
            client = UnifiedLLMClient()
            if not client.available_models:
                error_msg = "Cross-component analysis requires LLM - no models available"
                console.print(Text("[ERROR]", style="bold red"), error_msg)
                return {"errors": [error_msg]}
        except Exception as e:
            error_msg = f"Failed to initialize LLM for cross-component analysis: {e}"
            console.print(Text("[ERROR]", style="bold red"), error_msg)
            return {"errors": [error_msg]}

        # Analyze data flows between components
        cross_threats = []
        skip_mitigation = state.get('skip_mitigation', False)

        # 1. Analyze trust boundary crossings
        trust_boundary_threats = _analyze_trust_boundaries(client, dfd_model, all_components, skip_mitigation)
        cross_threats.extend(trust_boundary_threats)

        # 2. Analyze AI-to-traditional component flows
        ai_integration_threats = _analyze_ai_integration_flows(client, ai_components, traditional_components, dfd_model, skip_mitigation)
        cross_threats.extend(ai_integration_threats)

        # 3. Analyze external service dependencies
        external_dependency_threats = _analyze_external_dependencies(client, all_components, dfd_model, skip_mitigation)
        cross_threats.extend(external_dependency_threats)

        # 4. Analyze authentication/authorization flows
        auth_flow_threats = _analyze_authentication_flows(client, all_components, dfd_model, skip_mitigation)
        cross_threats.extend(auth_flow_threats)

        console.print(Text("[OK]", style="bold green"), f"Cross-component analysis complete: {len(cross_threats)} flow-based threats identified")

        return {
            "cross_component_threats": cross_threats,
            "trust_boundary_count": len(dfd_model.trust_boundaries) if hasattr(dfd_model, 'trust_boundaries') else 0,
            "data_flow_count": len(dfd_model.connections) if hasattr(dfd_model, 'connections') else 0
        }

    except Exception as e:
        error_msg = f"Cross-component analysis error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}

def _analyze_trust_boundaries(client, dfd_model, components: List[Dict], skip_mitigation: bool = False) -> List[Dict]:
    """Analyze threats at trust boundary crossings"""

    threats = []

    # Group components by trust zone
    components_by_zone = {}
    for component in components:
        trust_zone = component.get('trust_zone', 'unknown')
        if trust_zone not in components_by_zone:
            components_by_zone[trust_zone] = []
        components_by_zone[trust_zone].append(component)

    # Analyze connections that cross trust zones
    if hasattr(dfd_model, 'connections'):
        for connection in dfd_model.connections:
            # Access Connection object attributes directly (not dictionary)
            source_id = connection.source_id
            target_id = connection.target_id

            # Find source and target components
            source_comp = _find_component_by_id(source_id, components)
            target_comp = _find_component_by_id(target_id, components)

            if source_comp and target_comp:
                source_zone = source_comp.get('trust_zone', 'unknown')
                target_zone = target_comp.get('trust_zone', 'unknown')

                # If crossing trust boundaries, analyze threats
                if source_zone != target_zone:
                    flow_threats = _analyze_trust_boundary_crossing(
                        client, source_comp, target_comp, connection, skip_mitigation
                    )
                    threats.extend(flow_threats)

    console.print(Text("[INFO]", style="bold blue"), f"Trust boundary analysis: {len(threats)} boundary-crossing threats")
    return threats

def _analyze_trust_boundary_crossing(client, source_comp: Dict, target_comp: Dict, connection: Dict, skip_mitigation: bool) -> List[Dict]:
    """Analyze specific trust boundary crossing for threats"""

    source_name = source_comp.get('name', 'Unknown')
    target_name = target_comp.get('name', 'Unknown')
    source_zone = source_comp.get('trust_zone', 'unknown')
    target_zone = target_comp.get('trust_zone', 'unknown')

    # Create context-aware prompt for boundary crossing analysis
    prompt = f"""Analyze trust boundary crossing security threats:

SOURCE: {source_name} (Trust Zone: {source_zone})
TARGET: {target_name} (Trust Zone: {target_zone})
DATA FLOW: {source_name} → {target_name}

Generate JSON with specific, descriptive threat names (NOT generic categories):

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_threat_description", "likelihood": "High/Medium/Low", "impact": "specific_impact_description", "boundary_type": "trust_boundary_crossing"}}]}}

EXAMPLES of good names:
- "Unencrypted Redis Cache Data in Transit to ECS"
- "Missing Authentication Between Load Balancer and Backend"
- "Man-in-the-Middle Attack on API Gateway Communications"

Focus on specific technical vulnerabilities: data integrity, authentication gaps, authorization bypasses, encryption weaknesses, man-in-the-middle attacks, privilege escalation across zones. Max 3 threats."""

    try:
        response = client.generate_response(prompt, max_tokens=600, temperature=0.1)

        # Parse the response
        from pipeline.nodes.llm_analyzer import _parse_partial_json_threats
        recovery_result = _parse_partial_json_threats(response, f"{source_name}_to_{target_name}")

        threats = recovery_result.get('threats', [])

        # Add cross-component metadata
        for threat in threats:
            threat_id = f"CROSS-{source_name[:4].upper()}{target_name[:4].upper()}-{len(threats):03d}"
            threat['id'] = threat_id
            threat['source_component'] = source_name
            threat['target_component'] = target_name
            threat['source_zone'] = source_zone
            threat['target_zone'] = target_zone
            threat['threat_type'] = 'cross_component'
            threat['boundary_crossing'] = True
            threat['flow_direction'] = f"{source_name} → {target_name}"
            threat['source'] = 'cross_component_analysis'

        return threats

    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze boundary crossing {source_name}→{target_name}: {e}")
        return []

def _analyze_ai_integration_flows(client, ai_components: List[Dict], traditional_components: List[Dict], dfd_model, skip_mitigation: bool) -> List[Dict]:
    """Analyze threats in AI-to-traditional component integrations"""

    threats = []

    for ai_comp in ai_components:
        for trad_comp in traditional_components:
            # Check if there's a connection between AI and traditional components
            if _components_connected(ai_comp, trad_comp, dfd_model):
                integration_threats = _analyze_ai_traditional_integration(
                    client, ai_comp, trad_comp, skip_mitigation
                )
                threats.extend(integration_threats)

    console.print(Text("[INFO]", style="bold blue"), f"AI integration analysis: {len(threats)} AI-traditional integration threats")
    return threats

def _analyze_ai_traditional_integration(client, ai_comp: Dict, trad_comp: Dict, skip_mitigation: bool) -> List[Dict]:
    """Analyze AI-traditional component integration threats"""

    ai_name = ai_comp.get('name', 'Unknown AI')
    trad_name = trad_comp.get('name', 'Unknown Component')
    ai_type = ai_comp.get('ai_type', 'AI/ML')
    trad_type = trad_comp.get('type', 'Traditional')

    prompt = f"""Analyze AI-traditional integration security threats:

AI COMPONENT: {ai_name} (Type: {ai_type})
TRADITIONAL COMPONENT: {trad_name} (Type: {trad_type})

Generate JSON with specific, descriptive threat names (NOT generic categories):

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_threat_description", "likelihood": "High/Medium/Low", "impact": "specific_impact_description", "integration_type": "ai_traditional"}}]}}

EXAMPLES of good names:
- "Prompt Injection via FastAPI Input Validation Bypass"
- "LLM Model Extraction Through Database Query Manipulation"
- "AI Hallucination Data Poisoning via User Upload"
- "Unauthorized LLM Access Through API Authentication Bypass"

Focus on specific AI-traditional vulnerabilities: AI output validation gaps, prompt injection via traditional inputs, model poisoning through data flows, unauthorized AI access patterns, data leakage between AI and traditional systems. Max 4 threats."""

    try:
        response = client.generate_response(prompt, max_tokens=700, temperature=0.1)

        from pipeline.nodes.llm_analyzer import _parse_partial_json_threats
        recovery_result = _parse_partial_json_threats(response, f"{ai_name}_integration_{trad_name}")

        threats = recovery_result.get('threats', [])

        # Add integration metadata
        for i, threat in enumerate(threats):
            threat_id = f"INTEG-{ai_name[:4].upper()}{trad_name[:4].upper()}-{i+1:03d}"
            threat['id'] = threat_id
            threat['ai_component'] = ai_name
            threat['traditional_component'] = trad_name
            threat['threat_type'] = 'ai_integration'
            threat['integration_direction'] = f"{ai_name} ↔ {trad_name}"
            threat['source'] = 'ai_integration_analysis'

        return threats

    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze AI integration {ai_name}↔{trad_name}: {e}")
        return []

def _analyze_external_dependencies(client, components: List[Dict], dfd_model, skip_mitigation: bool) -> List[Dict]:
    """Analyze threats from external service dependencies"""

    threats = []
    external_services = []

    # Identify external services (components in different trust zones or with external indicators)
    for component in components:
        comp_name = component.get('name', '').lower()
        comp_type = component.get('type', '').lower()

        # Identify external services
        if any(external_indicator in comp_name for external_indicator in ['openai', 'aws', 'external', 'api', 'saas']):
            external_services.append(component)

    if external_services:
        prompt = f"""Analyze external service dependency threats:

EXTERNAL SERVICES: {[service.get('name') for service in external_services]}
INTERNAL COMPONENTS: {len(components) - len(external_services)} components

Generate JSON with specific, descriptive threat names (NOT generic categories):

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_threat_description", "likelihood": "High/Medium/Low", "impact": "specific_impact_description", "dependency_type": "external_service"}}]}}

EXAMPLES of good names:
- "OpenAI API Rate Limiting Service Disruption"
- "AWS Service Account Compromise via Credential Leak"
- "Third-Party SaaS Data Sovereignty Violation"
- "External Provider Supply Chain Attack via Dependency"
- "Vendor Lock-in Risk from Single Cloud Provider"

Focus on specific external risks: service availability disruptions, API rate limiting impacts, data sovereignty violations, vendor lock-in dependencies, service account compromises, supply chain attack vectors. Max 5 threats."""

        try:
            response = client.generate_response(prompt, max_tokens=800, temperature=0.1)

            from pipeline.nodes.llm_analyzer import _parse_partial_json_threats
            recovery_result = _parse_partial_json_threats(response, "external_dependencies")

            threats = recovery_result.get('threats', [])

            # Add external dependency metadata
            for i, threat in enumerate(threats):
                threat_id = f"EXT-DEP-{i+1:03d}"
                threat['id'] = threat_id
                threat['external_services'] = [service.get('name') for service in external_services]
                threat['threat_type'] = 'external_dependency'
                threat['dependency_count'] = len(external_services)
                threat['source'] = 'external_dependency_analysis'

        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze external dependencies: {e}")

    console.print(Text("[INFO]", style="bold blue"), f"External dependency analysis: {len(threats)} dependency threats")
    return threats

def _analyze_authentication_flows(client, components: List[Dict], dfd_model, skip_mitigation: bool) -> List[Dict]:
    """Analyze authentication and authorization flow threats"""

    # Identify auth-related components
    auth_components = []
    for component in components:
        comp_name = component.get('name', '').lower()
        comp_type = component.get('type', '').lower()

        if any(auth_indicator in comp_name or auth_indicator in comp_type
               for auth_indicator in ['auth', 'login', 'oauth', 'jwt', 'token', 'identity']):
            auth_components.append(component)

    if not auth_components:
        return []

    prompt = f"""Analyze authentication flow security threats:

AUTH COMPONENTS: {[comp.get('name') for comp in auth_components]}
TOTAL COMPONENTS: {len(components)}

Generate JSON with authentication flow threats:
{{"threats": [{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "threat_description", "likelihood": "High/Medium/Low", "impact": "impact_description", "flow_type": "authentication"}}]}}

Focus on: token theft, session hijacking, authentication bypass, privilege escalation, credential stuffing, OIDC vulnerabilities. Max 4 threats."""

    threats = []
    try:
        response = client.generate_response(prompt, max_tokens=700, temperature=0.1)

        from pipeline.nodes.llm_analyzer import _parse_partial_json_threats
        recovery_result = _parse_partial_json_threats(response, "auth_flows")

        threats = recovery_result.get('threats', [])

        # Add auth flow metadata
        for i, threat in enumerate(threats):
            threat_id = f"AUTH-FLOW-{i+1:03d}"
            threat['id'] = threat_id
            threat['auth_components'] = [comp.get('name') for comp in auth_components]
            threat['threat_type'] = 'authentication_flow'
            threat['flow_complexity'] = len(auth_components)
            threat['source'] = 'auth_flow_analysis'

    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze authentication flows: {e}")

    console.print(Text("[INFO]", style="bold blue"), f"Authentication flow analysis: {len(threats)} auth flow threats")
    return threats

def _find_component_by_id(component_id: str, components: List[Dict]) -> Dict:
    """Find component by ID in components list"""
    for component in components:
        if component.get('id') == component_id:
            return component
    return None

def _components_connected(comp1: Dict, comp2: Dict, dfd_model) -> bool:
    """Check if two components are connected in the DFD"""
    if not hasattr(dfd_model, 'connections'):
        return False

    comp1_id = comp1.get('id')
    comp2_id = comp2.get('id')

    for connection in dfd_model.connections:
        # Access Connection object attributes directly (not dictionary)
        source_id = connection.source_id
        target_id = connection.target_id

        if ((source_id == comp1_id and target_id == comp2_id) or
            (source_id == comp2_id and target_id == comp1_id)):
            return True

    return False

def _analyze_dataflows_simple(dfd_model, components: List[Dict]) -> Dict[str, Any]:
    """Simple data flow analysis when LLM is not available"""

    console.print(Text("[INFO]", style="bold blue"), "Performing simple data flow analysis...")

    # Count trust boundary crossings
    trust_zones = set()
    for component in components:
        trust_zone = component.get('trust_zone', 'unknown')
        trust_zones.add(trust_zone)

    # Generate basic cross-component threats
    basic_threats = []

    if len(trust_zones) > 1:
        basic_threats.append({
            'id': 'CROSS-TRUST-001',
            'name': 'Trust Boundary Data Leakage',
            'severity': 'High',
            'description': 'Data flowing across trust boundaries may be intercepted or modified',
            'threat_type': 'cross_component',
            'boundary_crossing': True,
            'source': 'simple_analysis'
        })

    # Check for AI-traditional component mix
    ai_count = len([c for c in components if c.get('ai_type')])
    traditional_count = len(components) - ai_count

    if ai_count > 0 and traditional_count > 0:
        basic_threats.append({
            'id': 'INTEG-AI-001',
            'name': 'AI-Traditional Integration Risk',
            'severity': 'Medium',
            'description': 'Integration between AI and traditional components may introduce vulnerabilities',
            'threat_type': 'ai_integration',
            'source': 'simple_analysis'
        })

    console.print(Text("[OK]", style="bold green"), f"Simple analysis complete: {len(basic_threats)} basic cross-component threats")

    return {
        "cross_component_threats": basic_threats,
        "trust_boundary_count": len(trust_zones),
        "analysis_type": "simple"
    }
