"""
LLM Threat Analysis Node
Analyzes DFD components directly with LLM without requiring knowledge base
"""

import json
import re
from typing import Dict, Any, List
from rich.console import Console
from rich.text import Text

console = Console()

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

    # Check for critical threats
    if any(keyword in threat_name_lower for keyword in critical_keywords):
        return 'Critical'

    # Check for high severity threats
    if any(keyword in threat_name_lower for keyword in high_keywords):
        return 'High'

    # Check for medium severity threats
    if any(keyword in threat_name_lower for keyword in medium_keywords):
        return 'Medium'

    # Default to Medium for unknown threats
    return 'Medium'

def _clean_llm_json_response(response: str, component_name: str = "component") -> str:
    """Clean LLM response to extract valid JSON, removing markdown and extra text"""

    # Remove markdown code blocks
    response = re.sub(r'```(?:json)?\s*', '', response)
    response = re.sub(r'```', '', response)

    # Try to find JSON object boundaries
    start_brace = response.find('{')
    if start_brace != -1:
        # Find the last closing brace
        brace_count = 0
        end_pos = start_brace
        for i, char in enumerate(response[start_brace:], start_brace):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break

        if end_pos > start_brace:
            response = response[start_brace:end_pos]

    return response.strip()

def _parse_partial_json_threats(response: str, component_name: str) -> Dict[str, Any]:
    """
    Advanced parser that recovers threats from partial/malformed JSON
    Returns as many valid threats as possible
    """

    threats = []
    mitigations = []

    try:
        # First attempt: standard JSON parsing
        cleaned_response = _clean_llm_json_response(response, component_name)
        data = json.loads(cleaned_response)

        threats.extend(data.get('threats', []))
        mitigations.extend(data.get('mitigations', []))

        return {
            'threats': threats,
            'mitigations': mitigations,
            'recovery_method': 'full_json'
        }

    except json.JSONDecodeError as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Full JSON parse failed for {component_name}, attempting recovery...")

        # Recovery attempt 1: Extract individual threat objects with regex
        threat_pattern = r'\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*[^}]*\}'
        threat_matches = re.finditer(threat_pattern, response, re.DOTALL)

        for match in threat_matches:
            try:
                threat_json = match.group(0)

                # Try to fix common JSON issues
                threat_json = re.sub(r',\s*}', '}', threat_json)  # Remove trailing commas
                threat_json = re.sub(r'"\s*:\s*"([^"]*)"([^",}]*)"', r'": "\1\2"', threat_json)  # Fix broken strings

                threat_obj = json.loads(threat_json)
                threats.append(threat_obj)

            except (json.JSONDecodeError, KeyError, AttributeError) as e:
                # Skip invalid JSON objects but log the issue for debugging
                console.print(Text("[DEBUG]", style="dim"), f"Skipped malformed threat object: {e}")
                continue

        # Recovery attempt 2: Extract by pattern matching
        if not threats:
            # Extract basic threat info using regex patterns - more comprehensive
            name_pattern = r'"name"\s*:\s*"([^"]+)"'
            severity_pattern = r'"severity"\s*:\s*"([^"]+)"'
            description_pattern = r'"description"\s*:\s*"([^"]*)"'  # Allow empty descriptions
            likelihood_pattern = r'"likelihood"\s*:\s*"([^"]+)"'
            impact_pattern = r'"impact"\s*:\s*"([^"]*)"'

            names = re.findall(name_pattern, response)
            severities = re.findall(severity_pattern, response)
            descriptions = re.findall(description_pattern, response)
            likelihoods = re.findall(likelihood_pattern, response)
            impacts = re.findall(impact_pattern, response)

            # Combine extracted info into threat objects
            for i, name in enumerate(names):
                # Use extracted values or infer reasonable defaults
                severity = severities[i] if i < len(severities) else _infer_severity_from_threat_name(name)
                description = descriptions[i] if i < len(descriptions) else 'No description available'
                likelihood = likelihoods[i] if i < len(likelihoods) else 'Medium'
                impact = impacts[i] if i < len(impacts) else 'Potential system compromise'

                threat = {
                    'name': name,
                    'severity': severity,
                    'description': description,
                    'likelihood': likelihood,
                    'impact': impact,
                    'recovered': True
                }
                threats.append(threat)

        if threats:
            console.print(Text("[OK]", style="bold green"), f"Recovered {len(threats)} threats from malformed JSON for {component_name}")
            return {
                'threats': threats,
                'mitigations': mitigations,
                'recovery_method': 'partial_recovery'
            }
        else:
            console.print(Text("[ERROR]", style="bold red"), f"Unable to recover any threats from response for {component_name}")
            return {
                'threats': [],
                'mitigations': [],
                'recovery_method': 'failed'
            }

def llm_analyzer_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Direct LLM Analysis Node - Analyzes threats using pure LLM reasoning"""
    console.print(Text("[INFO]", style="bold blue"), "LLM Analysis Node: Analyzing threats with pure LLM reasoning...")

    try:
        # Check if we have DFD model
        dfd_model = state.get('dfd_model')
        if not dfd_model:
            console.print(Text("[WARN]", style="bold yellow"), "No DFD model available for direct analysis")
            return {"warnings": ["No DFD model available for direct analysis"]}

        # Initialize LLM client
        from rag.llm_client import UnifiedLLMClient

        try:
            client = UnifiedLLMClient()
            if not client.available_models:
                console.print(Text("[ERROR]", style="bold red"), "Failed to initialize LLM client: no models available")
                return {"errors": ["LLM client initialization failed - no models available"]}
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to initialize LLM client: {e}")
            return {"errors": [f"LLM client initialization failed: {e}"]}

        # Perform comprehensive threat analysis
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])

        # Initialize result collections
        direct_threats = []
        direct_mitigations = []
        direct_analysis_summary = {}

        # Get the skip_mitigation flag from state
        skip_mitigation = state.get('skip_mitigation', False)

        # Analyze AI/LLM components (if any)
        if ai_components:
            ai_analysis = _analyze_ai_components(client, ai_components, dfd_model, skip_mitigation)
            direct_threats.extend(ai_analysis.get('threats', []))
            if not skip_mitigation:
                direct_mitigations.extend(ai_analysis.get('mitigations', []))
            direct_analysis_summary.update(ai_analysis.get('summary', {}))

        # Analyze traditional components
        if traditional_components:
            traditional_analysis = _analyze_traditional_components(client, traditional_components, dfd_model, skip_mitigation)
            direct_threats.extend(traditional_analysis.get('threats', []))
            if not skip_mitigation:
                direct_mitigations.extend(traditional_analysis.get('mitigations', []))

        if skip_mitigation:
            console.print(Text("[OK]", style="bold green"), f"LLM analysis complete: {len(direct_threats)} threats (mitigations skipped)")
        else:
            console.print(Text("[OK]", style="bold green"), f"LLM analysis complete: {len(direct_threats)} threats, {len(direct_mitigations)} mitigations")

        # Provide summary stats
        if direct_analysis_summary:
            ai_threat_count = direct_analysis_summary.get('ai_specific_threats', 0)
            traditional_threat_count = direct_analysis_summary.get('traditional_threats', 0)
            console.print(Text("[INFO]", style="bold blue"), f"AI-specific threats: {ai_threat_count}")
            console.print(Text("[INFO]", style="bold blue"), f"Traditional threats: {traditional_threat_count}")

        # Return only the fields we're modifying
        return {
            "llm_threats": direct_threats,
            "llm_mitigations": direct_mitigations,
            "llm_analysis_summary": direct_analysis_summary
        }

    except Exception as e:
        error_msg = f"LLM analysis failed: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}


def _analyze_ai_components(client, ai_components: List[Dict], dfd_model, skip_mitigation: bool = False) -> Dict[str, Any]:
    """Analyze AI/LLM components for specific threats"""
    console.print(Text("[INFO]", style="bold blue"), "Analyzing AI/LLM components...")

    threats = []
    mitigations = []

    for component in ai_components:
        try:
            component_name = component.get('name', 'Unknown AI Component')
            ai_type = component.get('ai_type', 'General AI/ML')
            risk_factors = component.get('risk_factors', [])

            # Limit risk factors to prevent context overflow
            limited_risk_factors = risk_factors[:3] if risk_factors else []

            # Create AI-specific threat analysis prompt - COMPACT VERSION
            if skip_mitigation:
                prompt = f"""AI Security Analysis - Component: {component_name}
Type: {ai_type}
Risks: {', '.join(limited_risk_factors) if limited_risk_factors else 'Standard AI risks'}

Generate AI-specific threats JSON:
{{"threats": [{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "brief_description", "likelihood": "High/Medium/Low", "impact": "brief_impact", "ai_specific": true}}]}}

Focus on: prompt injection, model extraction, adversarial attacks, bias, hallucination. Max 5 threats."""
            else:
                prompt = f"""AI Security Analysis - Component: {component_name}
Type: {ai_type}
Risks: {', '.join(limited_risk_factors) if limited_risk_factors else 'Standard AI risks'}

Generate threats and mitigations JSON:
{{"threats": [{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "brief_description", "likelihood": "High/Medium/Low", "impact": "brief_impact", "ai_specific": true}}], "mitigations": [{{"name": "mitigation_name", "type": "preventive/detective/corrective", "implementation": "brief_steps", "effectiveness": "High/Medium/Low"}}]}}

Focus on: prompt injection, model extraction, adversarial attacks, bias. Max 4 threats, 3 mitigations."""

            # Reduce max_tokens to prevent overflow
            response = client.generate_response(prompt, max_tokens=800, temperature=0.1)

            # Use advanced parsing with recovery
            recovery_result = _parse_partial_json_threats(response, component_name)

            # Process recovered threats
            component_threats = recovery_result.get('threats', [])
            for threat in component_threats:
                threat['target_component'] = component_name
                threat['source'] = 'llm_direct'
                threat['component_type'] = 'ai'
                threats.append(threat)

            # Process recovered mitigations (only if not skipping)
            if not skip_mitigation:
                component_mitigations = recovery_result.get('mitigations', [])
                for mitigation in component_mitigations:
                    mitigation['target_component'] = component_name
                    mitigation['source'] = 'llm_direct'
                    mitigations.append(mitigation)

            # Log recovery method used
            recovery_method = recovery_result.get('recovery_method', 'unknown')
            if recovery_method == 'partial_recovery':
                console.print(Text("[RECOVERY]", style="bold cyan"), f"Partial data recovered for {component_name} using fallback parsing")

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


def _analyze_traditional_components(client, traditional_components: List[Dict], dfd_model, skip_mitigation: bool = False) -> Dict[str, Any]:
    """Analyze traditional components for standard security threats"""
    console.print(Text("[INFO]", style="bold blue"), "Analyzing traditional components...")

    threats = []
    mitigations = []

    for component in traditional_components:
        try:
            component_name = component.get('name', 'Unknown Component')
            component_type = component.get('type', 'Unknown')

            # Create COMPACT traditional threat analysis prompt
            if skip_mitigation:
                prompt = f"""Security Analysis - Component: {component_name}
Type: {component_type}

Generate security threats JSON:
{{"threats": [{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "brief_description", "likelihood": "High/Medium/Low", "impact": "brief_impact"}}]}}

Focus on: SQL injection, XSS, auth bypass, privilege escalation. Max 4 threats."""
            else:
                prompt = f"""Security Analysis - Component: {component_name}
Type: {component_type}

Generate threats and mitigations JSON:
{{"threats": [{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "brief_description", "likelihood": "High/Medium/Low", "impact": "brief_impact"}}], "mitigations": [{{"name": "mitigation_name", "type": "preventive/detective/corrective", "implementation": "brief_steps", "effectiveness": "High/Medium/Low"}}]}}

Focus on: SQL injection, XSS, auth bypass. Max 3 threats, 3 mitigations."""

            # Reduce max_tokens to prevent overflow
            response = client.generate_response(prompt, max_tokens=600, temperature=0.1)

            # Use advanced parsing with recovery
            recovery_result = _parse_partial_json_threats(response, component_name)

            # Process recovered threats
            component_threats = recovery_result.get('threats', [])
            for threat in component_threats:
                threat['target_component'] = component_name
                threat['source'] = 'llm_direct'
                threat['component_type'] = 'traditional'
                threats.append(threat)

            # Process recovered mitigations (only if not skipping)
            if not skip_mitigation:
                component_mitigations = recovery_result.get('mitigations', [])
                for mitigation in component_mitigations:
                    mitigation['target_component'] = component_name
                    mitigation['source'] = 'llm_direct'
                    mitigations.append(mitigation)

            # Log recovery method used
            recovery_method = recovery_result.get('recovery_method', 'unknown')
            if recovery_method == 'partial_recovery':
                console.print(Text("[RECOVERY]", style="bold cyan"), f"Partial data recovered for {component_name} using fallback parsing")

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
