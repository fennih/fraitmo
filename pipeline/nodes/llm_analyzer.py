"""
LLM Threat Analysis Node
Analyzes DFD components directly with LLM without requiring knowledge base
"""

import json
from typing import Dict, Any, List
from rich.console import Console
from rich.text import Text

console = Console()

def llm_analyzer_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Direct LLM Analysis Node - Analyzes threats using pure LLM reasoning"""
    console.print(Text("[INFO]", style="bold blue"), "LLM Analysis Node: Analyzing threats with pure LLM reasoning...")
    
    try:
        # Check if we have DFD model
        dfd_model = state.get('dfd_model')
        if not dfd_model:
            console.print(Text("[WARN]", style="bold yellow"), "No DFD model available for direct analysis")
            return state
        
        # Initialize LLM client
        from rag.llm_client import UnifiedLLMClient
        
        try:
            client = UnifiedLLMClient()
            if not client.available_models:
                console.print(Text("[ERROR]", style="bold red"), "Failed to initialize LLM client: {e}")
                state['errors'] = state.get('errors', []) + [f"LLM client initialization failed"]
                return state
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to initialize LLM client: {e}")
            state['errors'] = state.get('errors', []) + [f"LLM client initialization failed: {e}"]
            return state
        
        # Perform comprehensive threat analysis
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        
        # Initialize result collections
        direct_threats = []
        direct_mitigations = []
        direct_analysis_summary = {}
        
        # Analyze AI/LLM components (if any)
        if ai_components:
            ai_analysis = _analyze_ai_components(client, ai_components, dfd_model)
            direct_threats.extend(ai_analysis.get('threats', []))
            direct_mitigations.extend(ai_analysis.get('mitigations', []))
            direct_analysis_summary.update(ai_analysis.get('summary', {}))
        
        # Analyze traditional components
        if traditional_components:
            traditional_analysis = _analyze_traditional_components(client, traditional_components, dfd_model)
            direct_threats.extend(traditional_analysis.get('threats', []))
            direct_mitigations.extend(traditional_analysis.get('mitigations', []))
        
        # Store results in state
        state['direct_threats'] = direct_threats
        state['direct_mitigations_kb'] = direct_mitigations
        state['direct_analysis_summary'] = direct_analysis_summary
        
        console.print(Text("[OK]", style="bold green"), f"LLM analysis complete: {len(direct_threats)} threats, {len(direct_mitigations)} mitigations")
        
        # Provide summary stats
        if direct_analysis_summary:
            ai_threat_count = direct_analysis_summary.get('ai_specific_threats', 0)
            traditional_threat_count = direct_analysis_summary.get('traditional_threats', 0)
            console.print(Text("[INFO]", style="bold blue"), f"AI-specific threats: {ai_threat_count}")
            console.print(Text("[INFO]", style="bold blue"), f"Traditional threats: {traditional_threat_count}")
        
        return state
        
    except Exception as e:
        error_msg = f"LLM analysis failed: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        state['errors'] = state.get('errors', []) + [error_msg]
        return state


def _analyze_ai_components(client, ai_components: List[Dict], dfd_model) -> Dict[str, Any]:
    """Analyze AI/LLM components for specific threats"""
    console.print(Text("[INFO]", style="bold blue"), "Analyzing AI/LLM components...")
    
    threats = []
    mitigations = []
    
    for component in ai_components:
        try:
            component_name = component.get('name', 'Unknown AI Component')
            ai_type = component.get('ai_type', 'General AI/ML')
            risk_factors = component.get('risk_factors', [])
            
            # Create AI-specific threat analysis prompt
            prompt = f"""
You are a cybersecurity expert specializing in AI/LLM security. Analyze this AI component:

COMPONENT: {component_name}
TYPE: {ai_type}
RISK FACTORS: {', '.join(risk_factors) if risk_factors else 'None identified'}

Provide a JSON response with AI-specific threats and mitigations:
{{
    "threats": [
        {{
            "name": "threat name",
            "severity": "Critical/High/Medium/Low",
            "description": "detailed description",
            "likelihood": "High/Medium/Low",
            "impact": "detailed impact analysis",
            "ai_specific": true
        }}
    ],
    "mitigations": [
        {{
            "name": "mitigation name",
            "type": "preventive/detective/corrective",
            "implementation": "how to implement",
            "effectiveness": "High/Medium/Low"
        }}
    ]
}}

Focus on AI-specific threats like prompt injection, model extraction, adversarial attacks, hallucination, bias, data poisoning, etc.
"""
            
            response = client.generate_response(prompt, max_tokens=800, temperature=0.1)
            
            try:
                analysis = json.loads(response)
                
                # Process threats
                component_threats = analysis.get('threats', [])
                for threat in component_threats:
                    threat['target_component'] = component_name
                    threat['source'] = 'llm_direct'
                    threat['component_type'] = 'ai'
                    threats.append(threat)
                
                # Process mitigations
                component_mitigations = analysis.get('mitigations', [])
                for mitigation in component_mitigations:
                    mitigation['target_component'] = component_name
                    mitigation['source'] = 'llm_direct'
                    mitigations.append(mitigation)
                    
            except json.JSONDecodeError:
                console.print(Text("[WARN]", style="bold yellow"), f"Failed to parse LLM response for AI component {component_name}")
                
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze AI component {component_name}: {e}")
    
    return {
        'threats': threats,
        'mitigations': mitigations,
        'summary': {
            'ai_specific_threats': len(threats),
            'ai_components_analyzed': len(ai_components)
        }
    }


def _analyze_traditional_components(client, traditional_components: List[Dict], dfd_model) -> Dict[str, Any]:
    """Analyze traditional components for standard security threats"""
    console.print(Text("[INFO]", style="bold blue"), "Analyzing traditional components...")
    
    threats = []
    mitigations = []
    
    for component in traditional_components:
        try:
            component_name = component.get('name', 'Unknown Component')
            component_type = component.get('type', 'Unknown')
            
            prompt = f"""
You are a cybersecurity expert. Analyze this traditional component:

COMPONENT: {component_name}
TYPE: {component_type}

Provide a JSON response with security threats and mitigations:
{{
    "threats": [
        {{
            "name": "threat name",
            "severity": "Critical/High/Medium/Low", 
            "description": "detailed description",
            "likelihood": "High/Medium/Low",
            "impact": "detailed impact analysis"
        }}
    ],
    "mitigations": [
        {{
            "name": "mitigation name",
            "type": "preventive/detective/corrective",
            "implementation": "how to implement",
            "effectiveness": "High/Medium/Low"
        }}
    ]
}}

Focus on traditional security threats like SQL injection, XSS, authentication bypass, privilege escalation, etc.
"""
            
            response = client.generate_response(prompt, max_tokens=600, temperature=0.1)
            
            try:
                analysis = json.loads(response)
                
                # Process threats
                component_threats = analysis.get('threats', [])
                for threat in component_threats:
                    threat['target_component'] = component_name
                    threat['source'] = 'llm_direct'
                    threat['component_type'] = 'traditional'
                    threats.append(threat)
                
                # Process mitigations
                component_mitigations = analysis.get('mitigations', [])
                for mitigation in component_mitigations:
                    mitigation['target_component'] = component_name
                    mitigation['source'] = 'llm_direct'
                    mitigations.append(mitigation)
                    
            except json.JSONDecodeError:
                console.print(Text("[WARN]", style="bold yellow"), f"Failed to parse LLM response for component {component_name}")
                
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze component {component_name}: {e}")
    
    return {
        'threats': threats,
        'mitigations': mitigations,
        'summary': {
            'traditional_threats': len(threats),
            'traditional_components_analyzed': len(traditional_components)
        }
    } 