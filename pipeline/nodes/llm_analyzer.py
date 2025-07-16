"""
LLM Threat Analysis Node
Analyzes DFD components directly with LLM without requiring knowledge base
"""

from typing import Dict, Any, List
from pipeline.state import ThreatAnalysisState
from rag.llm_client import UnifiedLLMClient


def llm_analyzer_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    LLM Analysis Node - Analyzes threats using only LLM reasoning
    No knowledge base required, pure LLM threat modeling
    """
    print("🧠 LLM Analysis Node: Analyzing threats with pure LLM reasoning...")
    
    try:
        # Get DFD data
        dfd_model = state.get('dfd_model')
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        
        if not dfd_model:
            print("   ⚠️ No DFD model available for direct analysis")
            return {
                "direct_threats": [],
                "direct_mitigations": [],
                "llm_analysis_status": "skipped"
            }
        
        # Initialize LLM client
        try:
            client = UnifiedLLMClient(preferred_model="foundation-sec")
        except Exception as e:
            print(f"   ❌ Failed to initialize LLM client: {e}")
            return {
                "direct_threats": [],
                "direct_mitigations": [],
                "llm_analysis_status": "failed"
            }
        
        # Analyze different aspects
        threats = []
        mitigations = []
        
        # 1. Analyze AI Components
        if ai_components:
            ai_threats, ai_mitigations = _analyze_ai_components(client, ai_components, dfd_model)
            threats.extend(ai_threats)
            mitigations.extend(ai_mitigations)
        
        # 2. Analyze Traditional Components
        if traditional_components:
            trad_threats, trad_mitigations = _analyze_traditional_components(client, traditional_components, dfd_model)
            threats.extend(trad_threats)
            mitigations.extend(trad_mitigations)
        
        # 3. Analyze Cross-Zone Communications
        cross_threats, cross_mitigations = _analyze_cross_zone_communications(client, dfd_model)
        threats.extend(cross_threats)
        mitigations.extend(cross_mitigations)
        
        # 4. Analyze Trust Boundaries
        boundary_threats, boundary_mitigations = _analyze_trust_boundaries(client, dfd_model)
        threats.extend(boundary_threats)
        mitigations.extend(boundary_mitigations)
        
        print(f"   ✅ LLM analysis complete: {len(threats)} threats, {len(mitigations)} mitigations")
        
        return {
            "llm_threats": threats,
            "llm_mitigations": mitigations,
            "llm_analysis_summary": {
                "total_threats": len(threats),
                "total_mitigations": len(mitigations),
                "ai_specific_threats": len([t for t in threats if t.get('category') == 'AI/LLM Security']),
                "traditional_threats": len([t for t in threats if t.get('category') != 'AI/LLM Security'])
            },
            "llm_analysis_status": "complete"
        }
        
    except Exception as e:
        print(f"   ❌ LLM analysis failed: {e}")
        return {
            "direct_threats": [],
            "direct_mitigations": [],
            "errors": state.get('errors', []) + [f"LLM analysis failed: {str(e)}"],
            "llm_analysis_status": "error"
        }


def _analyze_ai_components(client: UnifiedLLMClient, ai_components: List[Dict], dfd_model) -> tuple[List[Dict], List[Dict]]:
    """Analyze AI/LLM components for specific threats"""
    print("   🤖 Analyzing AI/LLM components...")
    
    threats = []
    mitigations = []
    
    for component in ai_components:
        component_name = component.get('name', 'Unknown AI Component')
        component_type = component.get('type', 'AI Service')
        trust_zone = component.get('trust_zone', 'Unknown')
        
        prompt = f"""You are a cybersecurity expert specializing in AI/LLM security threats.

Analyze this AI component for security threats:
- Component: {component_name}
- Type: {component_type}
- Trust Zone: {trust_zone}

Focus on AI/LLM specific threats like:
- Prompt injection attacks
- Model poisoning
- Data leakage through prompts
- Adversarial inputs
- Model inference attacks
- Training data extraction

Provide 3-5 specific threats in JSON format:
[{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "impact": "potential_impact", "likelihood": "High/Medium/Low"}}]

Only JSON, no additional text."""
        
        try:
            response = client.query(prompt, max_tokens=800, temperature=0.1)
            
            # Parse LLM response
            component_threats = _parse_llm_threats_response(response, component_name, "AI/LLM Security")
            threats.extend(component_threats)
            
            # Generate mitigations for each threat
            for threat in component_threats:
                mitigation = _generate_mitigation_for_threat(client, threat, component)
                if mitigation:
                    mitigations.append(mitigation)
            
        except Exception as e:
            print(f"     ⚠️ Failed to analyze AI component {component_name}: {e}")
    
    return threats, mitigations


def _analyze_traditional_components(client: UnifiedLLMClient, traditional_components: List[Dict], dfd_model) -> tuple[List[Dict], List[Dict]]:
    """Analyze traditional infrastructure components"""
    print("   🏗️ Analyzing traditional components...")
    
    threats = []
    mitigations = []
    
    for component in traditional_components:
        component_name = component.get('name', 'Unknown Component')
        component_type = component.get('type', 'Service')
        trust_zone = component.get('trust_zone', 'Unknown')
        
        prompt = f"""You are a cybersecurity expert specializing in infrastructure security.

Analyze this component for security threats:
- Component: {component_name}
- Type: {component_type}
- Trust Zone: {trust_zone}

Focus on traditional threats like:
- SQL injection
- Cross-site scripting (XSS)
- Authentication bypasses
- Authorization flaws
- Network attacks
- Data breaches

Provide 2-4 specific threats in JSON format:
[{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "impact": "potential_impact", "likelihood": "High/Medium/Low"}}]

Only JSON, no additional text."""
        
        try:
            response = client.query(prompt, max_tokens=600, temperature=0.1)
            
            # Parse LLM response
            component_threats = _parse_llm_threats_response(response, component_name, "Infrastructure Security")
            threats.extend(component_threats)
            
            # Generate mitigations for each threat
            for threat in component_threats:
                mitigation = _generate_mitigation_for_threat(client, threat, component)
                if mitigation:
                    mitigations.append(mitigation)
            
        except Exception as e:
            print(f"     ⚠️ Failed to analyze component {component_name}: {e}")
    
    return threats, mitigations


def _analyze_cross_zone_communications(client: UnifiedLLMClient, dfd_model) -> tuple[List[Dict], List[Dict]]:
    """Analyze communications crossing trust boundaries"""
    print("   🔗 Analyzing cross-zone communications...")
    
    threats = []
    mitigations = []
    
    if not hasattr(dfd_model, 'connections') or not dfd_model.connections:
        return threats, mitigations
    
    # Find cross-zone connections
    cross_zone_connections = []
    for connection in dfd_model.connections:
        # Get components by ID
        source_component = dfd_model.components.get(connection.source_id)
        target_component = dfd_model.components.get(connection.target_id)
        
        if source_component and target_component:
            source_zone = getattr(source_component, 'trust_zone_name', 'Unknown')
            target_zone = getattr(target_component, 'trust_zone_name', 'Unknown')
            
            if source_zone != target_zone and source_zone != 'Unknown' and target_zone != 'Unknown':
                cross_zone_connections.append({
                    'connection': connection,
                    'source_component': source_component,
                    'target_component': target_component,
                    'source_zone': source_zone,
                    'target_zone': target_zone
                })
    
    if not cross_zone_connections:
        return threats, mitigations
    
    # Analyze cross-zone threats
    connections_desc = "\n".join([
        f"- {conn['source_component'].name} ({conn['source_zone']}) → {conn['target_component'].name} ({conn['target_zone']})"
        for conn in cross_zone_connections
    ])
    
    prompt = f"""You are a cybersecurity expert specializing in network security and trust boundaries.

Analyze these cross-trust-zone communications for security threats:
{connections_desc}

Focus on threats like:
- Man-in-the-middle attacks
- Network eavesdropping
- Trust boundary violations
- Privilege escalation
- Data interception
- Protocol-level attacks

Provide 3-5 specific threats in JSON format:
[{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "impact": "potential_impact", "likelihood": "High/Medium/Low"}}]

Only JSON, no additional text."""
    
    try:
        response = client.query(prompt, max_tokens=700, temperature=0.1)
        
        # Parse LLM response
        cross_threats = _parse_llm_threats_response(response, "Cross-Zone Communications", "Network Security")
        threats.extend(cross_threats)
        
        # Generate mitigations
        for threat in cross_threats:
            mitigation = _generate_network_mitigation(client, threat, cross_zone_connections)
            if mitigation:
                mitigations.append(mitigation)
        
    except Exception as e:
        print(f"     ⚠️ Failed to analyze cross-zone communications: {e}")
    
    return threats, mitigations


def _analyze_trust_boundaries(client: UnifiedLLMClient, dfd_model) -> tuple[List[Dict], List[Dict]]:
    """Analyze trust boundaries for security weaknesses"""
    print("   🏰 Analyzing trust boundaries...")
    
    threats = []
    mitigations = []
    
    if not hasattr(dfd_model, 'trust_zones') or not dfd_model.trust_zones:
        return threats, mitigations
    
    trust_zones_desc = "\n".join([
        f"- {zone.name}: {getattr(zone, 'trust_level', 'Unknown')}"
        for zone in dfd_model.trust_zones.values()
    ])
    
    prompt = f"""You are a cybersecurity expert specializing in trust boundary analysis.

Analyze these trust zones for security weaknesses:
{trust_zones_desc}

Focus on threats like:
- Trust boundary bypasses
- Privilege escalation between zones
- Insufficient access controls
- Zone-specific vulnerabilities
- Trust level misconfigurations

Provide 2-4 specific threats in JSON format:
[{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "impact": "potential_impact", "likelihood": "High/Medium/Low"}}]

Only JSON, no additional text."""
    
    try:
        response = client.query(prompt, max_tokens=600, temperature=0.1)
        
        # Parse LLM response
        boundary_threats = _parse_llm_threats_response(response, "Trust Boundaries", "Access Control")
        threats.extend(boundary_threats)
        
        # Generate mitigations
        for threat in boundary_threats:
            mitigation = _generate_boundary_mitigation(client, threat, list(dfd_model.trust_zones.values()))
            if mitigation:
                mitigations.append(mitigation)
        
    except Exception as e:
        print(f"     ⚠️ Failed to analyze trust boundaries: {e}")
    
    return threats, mitigations


def _parse_llm_threats_response(response: str, component_name: str, category: str) -> List[Dict]:
    """Parse LLM response into structured threats"""
    import json
    import re
    
    threats = []
    
    try:
        # Extract JSON from response
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            parsed_threats = json.loads(json_str)
            
            for threat in parsed_threats:
                if isinstance(threat, dict) and 'name' in threat:
                    structured_threat = {
                        'id': f"DIRECT_{len(threats)+1}",
                        'name': threat.get('name', 'Unknown Threat'),
                        'description': threat.get('description', ''),
                        'severity': threat.get('severity', 'Medium'),
                        'category': category,
                        'component': component_name,
                        'impact': threat.get('impact', ''),
                        'likelihood': threat.get('likelihood', 'Medium'),
                        'source': 'Direct LLM Analysis'
                    }
                    threats.append(structured_threat)
        
    except Exception as e:
        print(f"     ⚠️ Failed to parse LLM response: {e}")
        # Fallback: create a generic threat
        threats.append({
            'id': 'DIRECT_FALLBACK',
            'name': f'Security Risk in {component_name}',
            'description': f'LLM identified potential security risks but response parsing failed: {response[:200]}...',
            'severity': 'Medium',
            'category': category,
            'component': component_name,
            'source': 'Direct LLM Analysis (Fallback)'
        })
    
    return threats


def _generate_mitigation_for_threat(client: UnifiedLLMClient, threat: Dict, component: Dict) -> Dict:
    """Generate specific mitigation for a threat"""
    try:
        prompt = f"""Generate a specific mitigation for this threat:

Threat: {threat['name']}
Description: {threat['description']}
Component: {component.get('name', 'Unknown')}
Severity: {threat['severity']}

Provide mitigation in JSON format:
{{"control": "mitigation_name", "description": "detailed_implementation", "priority": "Critical/High/Medium/Low", "effort": "Low/Medium/High", "implementation_time": "estimated_time"}}

Only JSON, no additional text."""
        
        response = client.query(prompt, max_tokens=300, temperature=0.1)
        
        import json
        import re
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            mitigation_data = json.loads(json_match.group())
            mitigation_data['threat_id'] = threat['id']
            mitigation_data['component'] = component.get('name', 'Unknown')
            return mitigation_data
        
    except Exception as e:
        print(f"     ⚠️ Failed to generate mitigation: {e}")
    
    return None


def _generate_network_mitigation(client: UnifiedLLMClient, threat: Dict, connections: List[Dict]) -> Dict:
    """Generate network-specific mitigation"""
    try:
        prompt = f"""Generate a network security mitigation for this cross-zone threat:

Threat: {threat['name']}
Description: {threat['description']}

Provide mitigation in JSON format:
{{"control": "mitigation_name", "description": "detailed_implementation", "priority": "Critical/High/Medium/Low", "effort": "Low/Medium/High", "implementation_time": "estimated_time"}}

Only JSON, no additional text."""
        
        response = client.query(prompt, max_tokens=300, temperature=0.1)
        
        import json
        import re
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            mitigation_data = json.loads(json_match.group())
            mitigation_data['threat_id'] = threat['id']
            mitigation_data['component'] = 'Network Communications'
            return mitigation_data
        
    except Exception as e:
        print(f"     ⚠️ Failed to generate network mitigation: {e}")
    
    return None


def _generate_boundary_mitigation(client: UnifiedLLMClient, threat: Dict, trust_zones: List) -> Dict:
    """Generate trust boundary specific mitigation"""
    try:
        prompt = f"""Generate a trust boundary mitigation for this threat:

Threat: {threat['name']}
Description: {threat['description']}

Provide mitigation in JSON format:
{{"control": "mitigation_name", "description": "detailed_implementation", "priority": "Critical/High/Medium/Low", "effort": "Low/Medium/High", "implementation_time": "estimated_time"}}

Only JSON, no additional text."""
        
        response = client.query(prompt, max_tokens=300, temperature=0.1)
        
        import json
        import re
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            mitigation_data = json.loads(json_match.group())
            mitigation_data['threat_id'] = threat['id']
            mitigation_data['component'] = 'Trust Boundaries'
            return mitigation_data
        
    except Exception as e:
        print(f"     ⚠️ Failed to generate boundary mitigation: {e}")
    
    return None 