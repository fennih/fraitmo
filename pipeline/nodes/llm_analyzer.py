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


def _validate_threat_component_logic(threat: Dict[str, Any], component: Dict[str, Any]) -> bool:
    """Validate that a threat is logically appropriate for a specific component type"""

    threat_name = threat.get('name', '').lower()
    component_type = component.get('type', '').lower()
    component_name = component.get('name', '').lower()

    # Database components (Aurora, etc.)
    if any(db_type in component_type for db_type in ['database', 'aurora', 'rds', 'mongodb', 'mysql']):
        # Valid database threats
        valid_threats = ['sql injection', 'privilege escalation', 'data breach', 'backup', 'encryption']
        # Invalid database threats
        invalid_threats = ['xss', 'cross-site scripting', 'csrf', 'clickjacking']

        if any(invalid in threat_name for invalid in invalid_threats):
            return False
        return any(valid in threat_name for valid in valid_threats)

    # Load Balancer components
    elif any(lb_type in component_type for lb_type in ['load-balancer', 'alb', 'elb', 'nginx']):
        # Valid load balancer threats
        valid_threats = ['ddos', 'ssl/tls', 'certificate', 'routing', 'network', 'bypass']
        # Invalid load balancer threats
        invalid_threats = ['sql injection', 'xss', 'database']

        if any(invalid in threat_name for invalid in invalid_threats):
            return False
        return any(valid in threat_name for valid in valid_threats)

    # Infrastructure/Container components (ECS, Docker, etc.)
    elif any(infra_type in component_type for infra_type in ['ecs', 'container', 'docker', 'kubernetes']):
        # Valid infrastructure threats
        valid_threats = ['privilege escalation', 'container escape', 'image', 'network', 'configuration']
        # These are infrastructure, NOT AI components!
        return any(valid in threat_name for valid in valid_threats)

    # Web/UI components
    elif any(web_type in component_type for web_type in ['ui', 'web', 'mobile', 'frontend']):
        # Valid web threats
        valid_threats = ['xss', 'csrf', 'injection', 'authentication', 'session']
        return any(valid in threat_name for valid in valid_threats)

    # API components
    elif any(api_type in component_type for api_type in ['api', 'endpoint', 'rest', 'graphql']):
        # Valid API threats
        valid_threats = ['injection', 'authentication', 'authorization', 'rate limiting', 'input validation']
        return any(valid in threat_name for valid in valid_threats)

    # AI/LLM components (actual AI, not infrastructure)
    elif any(ai_type in component_type for ai_type in ['llm', 'ai', 'model', 'openai', 'claude']) or component.get('ai_specific', False):
        # Valid AI threats
        valid_threats = ['prompt injection', 'model extraction', 'adversarial', 'bias', 'hallucination', 'poisoning']
        return any(valid in threat_name for valid in valid_threats)

    # Default: allow most threats but log for review
    return True

def _fix_component_classification(component: Dict[str, Any]) -> Dict[str, Any]:
    """Fix misclassified components (e.g., AWS ECS marked as AI)"""

    component_name = component.get('name', '').lower()
    component_type = component.get('type', '').lower()

    # Fix AWS ECS misclassification
    if 'ecs' in component_name or 'elastic container' in component_name:
        component['ai_type'] = None  # Remove AI classification
        component['component_category'] = 'Infrastructure'
        component['is_ai_component'] = False
        return component

    # Fix Load Balancer misclassification
    if 'load balancer' in component_name or 'alb' in component_type:
        component['ai_type'] = None
        component['component_category'] = 'Network'
        component['is_ai_component'] = False
        return component

    # Fix Database misclassification
    if any(db_word in component_name for db_word in ['aurora', 'database', 'rds', 'mysql']):
        component['ai_type'] = None
        component['component_category'] = 'Database'
        component['is_ai_component'] = False
        return component

    # Correctly identify actual AI components
    if any(ai_word in component_name for ai_word in ['openai', 'claude', 'gpt', 'llm', 'model']) and not any(infra_word in component_name for infra_word in ['ecs', 'container', 'service']):
        component['is_ai_component'] = True
        component['component_category'] = 'AI/ML'
        return component

    return component

def _analyze_ai_components(client, ai_components: List[Dict], dfd_model, skip_mitigation: bool = False) -> Dict[str, Any]:
    """Analyze AI/LLM components for specific threats"""
    console.print(Text("[INFO]", style="bold blue"), "Analyzing AI/LLM components...")

    threats = []
    mitigations = []

    for component in ai_components:
        try:
            # Fix component classification first
            corrected_component = _fix_component_classification(component.copy())

            # Skip if this was misclassified as AI
            if not corrected_component.get('is_ai_component', True):
                console.print(Text("[WARN]", style="bold yellow"), f"Skipping {corrected_component.get('name')} - reclassified as {corrected_component.get('component_category', 'Infrastructure')}")
                continue

            component_name = corrected_component.get('name', 'Unknown AI Component')
            ai_type = corrected_component.get('ai_type', 'General AI/ML')
            risk_factors = corrected_component.get('risk_factors', [])

            # Limit risk factors to prevent context overflow
            limited_risk_factors = risk_factors[:3] if risk_factors else []

            # Create AI-specific threat analysis prompt with specific naming guidance
            if skip_mitigation:
                prompt = f"""AI Security Analysis - Component: {component_name}
Type: {ai_type}
Risks: {', '.join(limited_risk_factors) if limited_risk_factors else 'Standard AI risks'}

Generate specific, descriptive AI threat names (NOT generic categories):

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "likelihood": "High/Medium/Low", "impact": "specific_impact", "ai_specific": true}}]}}

EXAMPLES of good names:
- "Malicious Prompt Injection to Bypass Content Filters"
- "LLM Model Parameter Extraction via Query Analysis"
- "Training Data Poisoning Through Adversarial Inputs"
- "AI Hallucination Manipulation for Misinformation"

Focus on specific AI vulnerabilities: prompt injection attacks, model extraction techniques, adversarial input manipulation, bias exploitation, hallucination triggers. Max 5 threats."""
            else:
                prompt = f"""AI Security Analysis - Component: {component_name}
Type: {ai_type}
Risks: {', '.join(limited_risk_factors) if limited_risk_factors else 'Standard AI risks'}

Generate specific threats and mitigations:

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "likelihood": "High/Medium/Low", "impact": "specific_impact", "ai_specific": true}}], "mitigations": [{{"name": "specific_mitigation_name", "type": "preventive/detective/corrective", "implementation": "implementation_steps", "effectiveness": "High/Medium/Low"}}]}}

Focus on: prompt injection, model extraction, adversarial attacks, bias. Max 4 threats, 3 mitigations."""

            # Reduce max_tokens to prevent overflow
            response = client.generate_response(prompt, max_tokens=800, temperature=0.1)

            # Use advanced parsing with recovery
            recovery_result = _parse_partial_json_threats(response, component_name)

            # Process recovered threats with validation
            component_threats = recovery_result.get('threats', [])
            for threat in component_threats:
                # Validate threat-component logic
                if _validate_threat_component_logic(threat, corrected_component):
                    threat['target_component'] = component_name
                    threat['source'] = 'llm_direct'
                    threat['component_type'] = 'ai'
                    threat['validated'] = True
                    threats.append(threat)
                else:
                    console.print(Text("[DEBUG]", style="dim"), f"Filtered invalid threat '{threat.get('name')}' for {component_name}")

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
            # Fix component classification first
            corrected_component = _fix_component_classification(component.copy())

            component_name = corrected_component.get('name', 'Unknown Component')
            component_type = corrected_component.get('type', 'Unknown')
            component_category = corrected_component.get('component_category', 'Traditional')

            # Create COMPACT traditional threat analysis prompt with component context and specific naming
            component_context = f"Component Category: {component_category}, Type: {component_type}"

            if skip_mitigation:
                prompt = f"""Security Analysis - Component: {component_name}
{component_context}

Generate specific, descriptive threat names (NOT generic categories):

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "likelihood": "High/Medium/Low", "impact": "specific_impact"}}]}}

EXAMPLES of good names based on component type:
- Database: "SQL Injection via Unvalidated User Queries", "Database Privilege Escalation Through Stored Procedures"
- API: "REST API Authentication Bypass via JWT Manipulation", "GraphQL Query Depth Attack"
- Load Balancer: "SSL/TLS Downgrade Attack on Load Balancer", "DDoS Amplification via Load Balancer"
- UI: "Cross-Site Scripting in User Input Forms", "Session Hijacking via Insecure Cookies"

Focus on threats appropriate for this specific component type. Max 4 threats."""
            else:
                prompt = f"""Security Analysis - Component: {component_name}
{component_context}

Generate specific threats and mitigations:

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_description", "likelihood": "High/Medium/Low", "impact": "specific_impact"}}], "mitigations": [{{"name": "specific_mitigation_name", "type": "preventive/detective/corrective", "implementation": "implementation_steps", "effectiveness": "High/Medium/Low"}}]}}

Focus on threats appropriate for this component type. Max 3 threats, 3 mitigations."""

            # Reduce max_tokens to prevent overflow
            response = client.generate_response(prompt, max_tokens=600, temperature=0.1)

            # Use advanced parsing with recovery
            recovery_result = _parse_partial_json_threats(response, component_name)

            # Process recovered threats with validation
            component_threats = recovery_result.get('threats', [])
            for threat in component_threats:
                # Validate threat-component logic
                if _validate_threat_component_logic(threat, corrected_component):
                    threat['target_component'] = component_name
                    threat['source'] = 'llm_direct'
                    threat['component_type'] = 'traditional'
                    threat['validated'] = True
                    threat['component_category'] = component_category
                    threats.append(threat)
                else:
                    console.print(Text("[DEBUG]", style="dim"), f"Filtered invalid threat '{threat.get('name')}' for {component_name} ({component_category})")

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
