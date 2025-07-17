"""
LLM Mitigation Proposer Node
Generates mitigation strategies directly using LLM without requiring knowledge base
"""

import json
from typing import Dict, Any, List
from rich.console import Console
from rich.text import Text
from pipeline.state import ThreatAnalysisState
from rag.llm_client import UnifiedLLMClient

console = Console()

def llm_mitigation_proposer_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    LLM Mitigation Proposer Node - Generates mitigations using pure LLM reasoning
    No knowledge base required, pure LLM mitigation strategies
    """
    console.print(Text("[INFO]", style="bold blue"), "LLM Mitigation Node: Generating mitigations with pure LLM reasoning...")
    
    try:
        # Get all available threats from both paths
        threats_found = state.get('threats_found', [])  # RAG path threats
        llm_threats = state.get('llm_threats', [])      # Direct LLM threats
        direct_threats = state.get('direct_threats', [])  # Current LLM analysis threats
        
        # Combine all threats for comprehensive mitigation generation
        all_threats = threats_found + llm_threats + direct_threats
        
        if not all_threats:
            console.print(Text("[INFO]", style="bold blue"), "No threats found for mitigation generation")
            state['llm_mitigations'] = []
            state['llm_implementation_plan'] = {}
            state['llm_mitigation_summary'] = {}
            return state
        
        # Initialize LLM client
        try:
            client = UnifiedLLMClient()
            if not client.available_models:
                raise Exception("No LLM models available")
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to initialize LLM client: {e}")
            state['errors'] = state.get('errors', []) + [f"LLM mitigation generation failed: {e}"]
            return state
        
        # Generate comprehensive mitigations
        console.print(Text("[INFO]", style="bold blue"), f"Generating mitigations for {len(all_threats)} threats...")
        
        mitigations = []
        
        # 1. Generate threat-specific mitigations
        threat_mitigations = _generate_threat_specific_mitigations(client, all_threats)
        mitigations.extend(threat_mitigations)
        
        # 2. Generate architectural mitigations
        arch_mitigations = _generate_architectural_mitigations(client, state)
        mitigations.extend(arch_mitigations)
        
        # 3. Generate defense-in-depth strategy
        defense_mitigations = _generate_defense_in_depth_strategy(client, state)
        mitigations.extend(defense_mitigations)
        
        # 4. Generate implementation plan
        implementation_plan = _generate_implementation_plan(client, mitigations, all_threats)
        
        # Store results
        state['llm_mitigations'] = mitigations
        state['llm_implementation_plan'] = implementation_plan
        state['llm_mitigation_summary'] = _generate_mitigation_summary(mitigations, implementation_plan)
        
        console.print(Text("[OK]", style="bold green"), f"LLM mitigation generation complete: {len(mitigations)} mitigations")
        console.print(Text("[INFO]", style="bold blue"), f"Implementation plan: {implementation_plan.get('total_tasks', 0)} tasks")
        console.print(Text("[INFO]", style="bold blue"), f"Estimated timeline: {implementation_plan.get('estimated_timeline', 'Unknown')}")
        
        return state
        
    except Exception as e:
        error_msg = f"LLM mitigation generation failed: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        state['errors'] = state.get('errors', []) + [error_msg]
        return state


def _generate_comprehensive_mitigations(client: UnifiedLLMClient, threat: Dict, dfd_model) -> List[Dict]:
    """Generate comprehensive mitigations for a specific threat"""
    mitigations = []
    
    threat_name = threat.get('name', 'Unknown Threat')
    threat_description = threat.get('description', '')
    threat_category = threat.get('category', 'General')
    threat_severity = threat.get('severity', 'Medium')
    component = threat.get('component', 'Unknown')
    
    prompt = f"""You are a cybersecurity expert specializing in mitigation strategies.

Generate comprehensive mitigations for this threat:
- Threat: {threat_name}
- Description: {threat_description}
- Category: {threat_category}
- Severity: {threat_severity}
- Component: {component}

Provide 3-5 specific mitigation controls in JSON format:
[{{
    "control": "mitigation_name",
    "description": "detailed_implementation_steps",
    "priority": "Critical/High/Medium/Low",
    "effort": "Low/Medium/High",
    "implementation_time": "time_estimate",
    "type": "preventive/detective/corrective",
    "cost": "Low/Medium/High"
}}]

Focus on:
- Preventive controls (stop the threat)
- Detective controls (detect the threat)
- Corrective controls (respond to the threat)

Only JSON, no additional text."""
    
    try:
        response = client.query(prompt, max_tokens=1000, temperature=0.1)
        
        # Parse response
        parsed_mitigations = _parse_mitigation_response(response, threat.get('id', 'unknown'))
        
        for mitigation in parsed_mitigations:
            mitigation['threat_name'] = threat_name
            mitigation['component'] = component
            mitigation['source'] = 'Direct LLM Analysis'
            mitigations.append(mitigation)
        
    except Exception as e:
        console.print(Text("[WARNING]", style="bold yellow"), f"Failed to generate mitigations for {threat_name}: {e}")
        # Fallback mitigation
        mitigations.append({
            'control': f'Security Review for {threat_name}',
            'description': f'Conduct security review to address {threat_name} in {component}',
            'priority': threat_severity,
            'effort': 'Medium',
            'implementation_time': '1-2 weeks',
            'type': 'preventive',
            'threat_id': threat.get('id', 'unknown'),
            'threat_name': threat_name,
            'component': component,
            'source': 'Direct LLM Analysis (Fallback)'
        })
    
    return mitigations


def _generate_architectural_mitigations(client: UnifiedLLMClient, ai_components: List[Dict], traditional_components: List[Dict], dfd_model) -> List[Dict]:
    """Generate system-wide architectural security mitigations"""
    mitigations = []
    
    ai_names = [comp.get('name', 'AI Component') for comp in ai_components]
    traditional_names = [comp.get('name', 'Component') for comp in traditional_components]
    
    prompt = f"""You are a security architect specializing in system-wide security controls.

Design architectural security mitigations for this system:

AI/LLM Components: {', '.join(ai_names)}
Traditional Components: {', '.join(traditional_names)}

Provide 4-6 architectural security controls in JSON format:
[{{
    "control": "control_name",
    "description": "detailed_implementation",
    "priority": "Critical/High/Medium/Low",
    "effort": "Low/Medium/High",
    "implementation_time": "time_estimate",
    "type": "architectural/network/access_control",
    "scope": "system_wide/component_specific"
}}]

Focus on:
- Zero trust architecture
- Network segmentation
- Access controls
- Monitoring and logging
- Data protection
- AI/LLM specific controls

Only JSON, no additional text."""
    
    try:
        response = client.query(prompt, max_tokens=1000, temperature=0.1)
        
        # Parse response
        parsed_mitigations = _parse_mitigation_response(response, 'ARCH')
        
        for mitigation in parsed_mitigations:
            mitigation['component'] = 'System Architecture'
            mitigation['source'] = 'Direct LLM Analysis'
            mitigations.append(mitigation)
        
    except Exception as e:
        console.print(Text("[WARNING]", style="bold yellow"), f"Failed to generate architectural mitigations: {e}")
    
    return mitigations


def _generate_defense_in_depth_strategy(client: UnifiedLLMClient, threats: List[Dict], dfd_model) -> List[Dict]:
    """Generate defense-in-depth strategy mitigations"""
    mitigations = []
    
    high_severity_threats = [t for t in threats if t.get('severity', 'Medium') in ['Critical', 'High']]
    threat_categories = list(set([t.get('category', 'General') for t in threats]))
    
    prompt = f"""You are a cybersecurity strategist specializing in defense-in-depth.

Design a layered defense strategy for these threats:
- Total threats: {len(threats)}
- High/Critical threats: {len(high_severity_threats)}
- Threat categories: {', '.join(threat_categories)}

Provide 3-5 defense-in-depth controls in JSON format:
[{{
    "control": "control_name",
    "description": "detailed_implementation",
    "priority": "Critical/High/Medium/Low",
    "effort": "Low/Medium/High",
    "implementation_time": "time_estimate",
    "type": "perimeter/network/host/application/data",
    "layer": "which_defense_layer"
}}]

Focus on layered security:
- Perimeter defense
- Network security
- Host-based security
- Application security
- Data security

Only JSON, no additional text."""
    
    try:
        response = client.query(prompt, max_tokens=800, temperature=0.1)
        
        # Parse response
        parsed_mitigations = _parse_mitigation_response(response, 'DEFENSE')
        
        for mitigation in parsed_mitigations:
            mitigation['component'] = 'Defense Strategy'
            mitigation['source'] = 'Direct LLM Analysis'
            mitigations.append(mitigation)
        
    except Exception as e:
        console.print(Text("[WARNING]", style="bold yellow"), f"Failed to generate defense-in-depth strategy: {e}")
    
    return mitigations


def _generate_implementation_plan(client: UnifiedLLMClient, mitigations: List[Dict], threats: List[Dict]) -> Dict:
    """Generate implementation plan for all mitigations"""
    
    critical_mitigations = [m for m in mitigations if m.get('priority') == 'Critical']
    high_mitigations = [m for m in mitigations if m.get('priority') == 'High']
    
    prompt = f"""You are a project manager specializing in cybersecurity implementations.

Create an implementation plan for these mitigations:
- Total mitigations: {len(mitigations)}
- Critical priority: {len(critical_mitigations)}
- High priority: {len(high_mitigations)}

Provide implementation plan in JSON format:
{{
    "timeline": "total_timeline_estimate",
    "phases": [
        {{
            "phase": "phase_name",
            "duration": "duration",
            "mitigations": ["mitigation1", "mitigation2"],
            "resources": "required_resources",
            "dependencies": "dependencies"
        }}
    ],
    "quick_wins": ["quick_win_controls"],
    "long_term": ["long_term_controls"],
    "estimated_cost": "cost_estimate"
}}

Focus on:
- Prioritization by risk reduction
- Resource optimization
- Quick wins vs long-term strategy
- Dependencies between controls

Only JSON, no additional text."""
    
    try:
        response = client.query(prompt, max_tokens=800, temperature=0.1)
        
        import re
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            plan = json.loads(json_match.group())
            plan['total_mitigations'] = len(mitigations)
            plan['generated_by'] = 'LLM Analysis'
            return plan
        
    except Exception as e:
        console.print(Text("[WARNING]", style="bold yellow"), f"Failed to generate implementation plan: {e}")
    
    # Fallback plan
    return {
        "timeline": "3-6 months",
        "phases": [
            {
                "phase": "Critical Controls",
                "duration": "1 month",
                "mitigations": [m['control'] for m in critical_mitigations],
                "resources": "Security team + External consultant",
                "dependencies": "Management approval"
            },
            {
                "phase": "High Priority Controls",
                "duration": "2-3 months",
                "mitigations": [m['control'] for m in high_mitigations],
                "resources": "Security team",
                "dependencies": "Phase 1 completion"
            }
        ],
        "quick_wins": [m['control'] for m in mitigations if m.get('effort') == 'Low'],
        "long_term": [m['control'] for m in mitigations if m.get('effort') == 'High'],
        "estimated_cost": "Medium to High",
        "total_mitigations": len(mitigations),
        "generated_by": "Direct LLM Analysis"
    }


def _parse_mitigation_response(response: str, threat_id: str) -> List[Dict]:
    """Parse LLM mitigation response into structured mitigations"""
    import re
    
    mitigations = []
    
    try:
        # Extract JSON from response
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            parsed_mitigations = json.loads(json_str)
            
            for i, mitigation in enumerate(parsed_mitigations):
                if isinstance(mitigation, dict) and 'control' in mitigation:
                    structured_mitigation = {
                        'id': f"DIRECT_MIT_{threat_id}_{i+1}",
                        'control': mitigation.get('control', 'Unknown Control'),
                        'description': mitigation.get('description', ''),
                        'priority': mitigation.get('priority', 'Medium'),
                        'effort': mitigation.get('effort', 'Medium'),
                        'implementation_time': mitigation.get('implementation_time', 'Unknown'),
                        'type': mitigation.get('type', 'preventive'),
                        'threat_id': threat_id
                    }
                    
                    # Add additional fields if present
                    for field in ['cost', 'scope', 'layer']:
                        if field in mitigation:
                            structured_mitigation[field] = mitigation[field]
                    
                    mitigations.append(structured_mitigation)
        
    except Exception as e:
        console.print(Text("[WARNING]", style="bold yellow"), f"Failed to parse mitigation response: {e}")
    
    return mitigations


def _categorize_by_priority(mitigations: List[Dict]) -> Dict[str, int]:
    """Categorize mitigations by priority"""
    categories = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    
    for mitigation in mitigations:
        priority = mitigation.get('priority', 'Medium')
        if priority in categories:
            categories[priority] += 1
    
    return categories


def _categorize_by_effort(mitigations: List[Dict]) -> Dict[str, int]:
    """Categorize mitigations by effort level"""
    categories = {'Low': 0, 'Medium': 0, 'High': 0}
    
    for mitigation in mitigations:
        effort = mitigation.get('effort', 'Medium')
        if effort in categories:
            categories[effort] += 1
    
    return categories 