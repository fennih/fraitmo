"""
LLM Threat Analysis Node
Analyzes DFD components directly with LLM without requiring knowledge base
"""

import json
import re
from typing import Dict, Any, List
from utils.console import console
from rich.text import Text



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

def _generate_fallback_threats(component_name: str, response: str) -> List[Dict[str, Any]]:
    """Generate fallback threats when all parsing fails"""
    
    component_type = component_name.lower()
    fallback_threats = []
    
    # Comprehensive threat templates ensuring STRIDE/AI coverage
    threat_templates = {
        'database': [
            # STRIDE coverage for databases
            {'name': f'SQL Injection Attack on {component_name}', 'severity': 'High', 'description': 'Tampering: SQL injection vulnerability in database queries'},
            {'name': f'Unauthorized Database Access to {component_name}', 'severity': 'Critical', 'description': 'Information Disclosure: Risk of unauthorized access to sensitive data'},
            {'name': f'Database Authentication Bypass in {component_name}', 'severity': 'High', 'description': 'Spoofing: Risk of bypassing database authentication mechanisms'},
            {'name': f'Database Service Denial of Service on {component_name}', 'severity': 'Medium', 'description': 'Denial of Service: Resource exhaustion attacks on database'},
            {'name': f'Database Privilege Escalation in {component_name}', 'severity': 'High', 'description': 'Elevation of Privilege: Risk of gaining unauthorized administrative privileges'}
        ],
        'api': [
            # STRIDE coverage for APIs
            {'name': f'API Authentication Bypass in {component_name}', 'severity': 'High', 'description': 'Spoofing: Authentication bypass vulnerability in API endpoints'},
            {'name': f'API Input Validation Failure in {component_name}', 'severity': 'Medium', 'description': 'Tampering: Risk of malicious input processing and injection attacks'},
            {'name': f'API Data Exposure in {component_name}', 'severity': 'High', 'description': 'Information Disclosure: Risk of exposing sensitive data through API responses'},
            {'name': f'API Rate Limiting Bypass in {component_name}', 'severity': 'Medium', 'description': 'Denial of Service: Resource exhaustion through API abuse'},
            {'name': f'API Authorization Bypass in {component_name}', 'severity': 'High', 'description': 'Elevation of Privilege: Risk of accessing unauthorized API resources'}
        ],
        'web': [
            # STRIDE coverage for web applications
            {'name': f'Cross-Site Scripting (XSS) in {component_name}', 'severity': 'Medium', 'description': 'Tampering: XSS vulnerability in web interface allowing script injection'},
            {'name': f'Session Hijacking in {component_name}', 'severity': 'High', 'description': 'Spoofing: Risk of session hijacking or fixation attacks'},
            {'name': f'Sensitive Data Exposure in {component_name}', 'severity': 'High', 'description': 'Information Disclosure: Risk of exposing sensitive user data'},
            {'name': f'Web Application DoS in {component_name}', 'severity': 'Medium', 'description': 'Denial of Service: Resource exhaustion attacks on web application'},
            {'name': f'Web Authorization Bypass in {component_name}', 'severity': 'High', 'description': 'Elevation of Privilege: Risk of accessing unauthorized web resources'}
        ],
        'ai': [
            # AI threat taxonomy coverage
            {'name': f'Prompt Injection Attack on {component_name}', 'severity': 'High', 'description': 'Input Manipulation: Risk of malicious prompt injection to manipulate AI behavior'},
            {'name': f'Model Extraction Attack on {component_name}', 'severity': 'Medium', 'description': 'Model Attack: Potential unauthorized extraction of AI model parameters'},
            {'name': f'AI Training Data Poisoning in {component_name}', 'severity': 'High', 'description': 'Training Attack: Risk of corrupting AI model through malicious training data'},
            {'name': f'AI Hallucination Exploitation in {component_name}', 'severity': 'Medium', 'description': 'Output Manipulation: Risk of exploiting AI hallucinations for misinformation'},
            {'name': f'AI Bias Amplification in {component_name}', 'severity': 'Medium', 'description': 'Output Manipulation: Risk of amplifying harmful biases in AI outputs'}
        ]
    }
    
    # Select appropriate templates
    selected_templates = []
    for key, templates in threat_templates.items():
        if key in component_type:
            selected_templates.extend(templates)
            break
    
    # If no specific match, use generic STRIDE-based threats
    if not selected_templates:
        selected_templates = [
            {'name': f'Identity Spoofing Attack on {component_name}', 'severity': 'High', 'description': 'Spoofing: Risk of identity impersonation attacks'},
            {'name': f'Data Tampering Attack on {component_name}', 'severity': 'Medium', 'description': 'Tampering: Risk of unauthorized data modification'},
            {'name': f'Information Disclosure in {component_name}', 'severity': 'High', 'description': 'Information Disclosure: Risk of exposing sensitive information'},
            {'name': f'Service Denial Attack on {component_name}', 'severity': 'Medium', 'description': 'Denial of Service: Risk of service unavailability'},
            {'name': f'Privilege Escalation in {component_name}', 'severity': 'High', 'description': 'Elevation of Privilege: Risk of gaining unauthorized access'}
        ]
    
    # Build fallback threats with full structure
    for template in selected_templates:
        threat = {
            'name': template['name'],
            'severity': template['severity'],
            'description': template['description'],
            'likelihood': 'Medium',
            'impact': 'Potential security compromise',
            'probability_score': 60,
            'fallback_generated': True
        }
        fallback_threats.append(threat)
    
    return fallback_threats


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

        # Recovery attempt 1: Extract individual threat objects with enhanced regex
        # More flexible pattern that handles various JSON structures
        threat_patterns = [
            r'\{[^{}]*"name"[^{}]*"[^"]*"[^{}]*\}',  # Standard threat objects
            r'"name"\s*:\s*"([^"]+)"[^,}]*(?:,\s*"[^"]+"\s*:\s*"[^"]*")*',  # Name-first patterns
            r'\{[\s\S]*?"name"[\s\S]*?\}',  # Multiline threat objects
        ]
        
        threat_matches = []
        for pattern in threat_patterns:
            matches = re.finditer(pattern, response, re.DOTALL | re.IGNORECASE)
            threat_matches.extend(matches)
            if threat_matches:  # Stop at first successful pattern
                break

        for match in threat_matches:
            try:
                threat_json = match.group(0)
                
                # Enhanced JSON cleanup for complex responses
                threat_json = re.sub(r',\s*}', '}', threat_json)  # Remove trailing commas
                threat_json = re.sub(r',\s*]', ']', threat_json)  # Remove trailing commas in arrays
                threat_json = re.sub(r'"\s*:\s*"([^"]*)"([^",}]*)"', r'": "\1\2"', threat_json)  # Fix broken strings
                threat_json = re.sub(r'\n', ' ', threat_json)  # Remove newlines that break JSON
                threat_json = re.sub(r'\s+', ' ', threat_json)  # Normalize whitespace
                
                # Ensure it's a complete JSON object
                if not threat_json.strip().startswith('{'):
                    threat_json = '{' + threat_json
                if not threat_json.strip().endswith('}'):
                    threat_json = threat_json + '}'
                
                threat_obj = json.loads(threat_json)
                
                # Validate required fields and add defaults
                if 'name' not in threat_obj:
                    continue  # Skip if no name
                    
                # Add missing required fields with defaults
                threat_obj.setdefault('severity', 'Medium')
                threat_obj.setdefault('description', 'Security threat identified')
                threat_obj.setdefault('likelihood', 'Medium')
                threat_obj.setdefault('impact', 'Potential security compromise')
                threat_obj.setdefault('probability_score', 60)
                
                threats.append(threat_obj)

            except (json.JSONDecodeError, KeyError, AttributeError) as e:
                # Skip invalid JSON objects but log the issue for debugging
                console.print(Text("[DEBUG]", style="dim"), f"Skipped malformed threat object: {e}")
                continue

        # Recovery attempt 2: Extract by pattern matching with fallback parsing
        if not threats:
            console.print(Text("[WARN]", style="bold yellow"), f"Object parsing failed, attempting field extraction for {component_name}...")
            
            # Enhanced patterns that handle various formats
            patterns = {
                'name': [r'"name"\s*:\s*"([^"]+)"', r'name:\s*"([^"]+)"', r'Name:\s*([^\n]+)', r'\*\*([^*]+)\*\*', r'\d+\.\s*([^\n]+)'],
                'severity': [r'"severity"\s*:\s*"([^"]+)"', r'severity:\s*"([^"]+)"', r'Severity:\s*([^\n]+)', r'(Critical|High|Medium|Low)'],
                'description': [r'"description"\s*:\s*"([^"]*)"', r'description:\s*"([^"]*)"', r'Description:\s*([^\n]+)'],
                'likelihood': [r'"likelihood"\s*:\s*"([^"]+)"', r'likelihood:\s*"([^"]+)"', r'Likelihood:\s*([^\n]+)'],
                'impact': [r'"impact"\s*:\s*"([^"]*)"', r'impact:\s*"([^"]*)"', r'Impact:\s*([^\n]+)']
            }
            
            # Try each pattern type
            extracted_data = {}
            for field, field_patterns in patterns.items():
                for pattern in field_patterns:
                    matches = re.findall(pattern, response, re.IGNORECASE)
                    if matches:
                        extracted_data[field] = matches
                        break
            
            # Extract names and build threats
            names = extracted_data.get('name', [])
            severities = extracted_data.get('severity', [])
            descriptions = extracted_data.get('description', [])
            likelihoods = extracted_data.get('likelihood', [])
            impacts = extracted_data.get('impact', [])

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

        # Recovery attempt 3: Generate fallback threats if all parsing fails
        if not threats:
            console.print(Text("[WARN]", style="bold yellow"), f"All parsing failed, generating fallback threats for {component_name}...")
            threats = _generate_fallback_threats(component_name, response)
        
        if threats:
            console.print(Text("[OK]", style="bold green"), f"Recovered {len(threats)} threats from malformed JSON for {component_name}")
            return {
                'threats': threats,
                'mitigations': mitigations,
                'recovery_method': 'partial_recovery' if len(threats) > 0 else 'fallback_generation'
            }
        else:
            console.print(Text("[ERROR]", style="bold red"), f"Unable to recover any threats from response for {component_name}")
            return {
                'threats': [],
                'mitigations': [],
                'recovery_method': 'failed'
            }

def llm_analyzer_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """Direct LLM Analysis Node - Analyzes threats using pure LLM reasoning with parallel optimization"""
    console.print(Text("[INFO]", style="bold blue"), "LLM Analysis Node: Analyzing threats with parallel LLM reasoning...")

    try:
        # Check if we have DFD model
        dfd_model = state.get('dfd_model')
        if not dfd_model:
            console.print(Text("[WARN]", style="bold yellow"), "No DFD model available for direct analysis")
            return {
                "llm_threats": [],
                "llm_mitigations": [],
                "warnings": ["No DFD model available for direct analysis"]
            }

        # Initialize LLM client
        from rag.llm_client import UnifiedLLMClient

        try:
            client = UnifiedLLMClient()
            if not client.available_models:
                console.print(Text("[ERROR]", style="bold red"), "Failed to initialize LLM client: no models available")
                return {
                    "llm_threats": [],
                    "llm_mitigations": [],
                    "errors": ["LLM client initialization failed - no models available"]
                }
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to initialize LLM client: {e}")
            return {
                "llm_threats": [],
                "llm_mitigations": [],
                "errors": [f"LLM client initialization failed: {e}"]
            }

        # Perform comprehensive threat analysis with parallelization
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])

        # Initialize result collections
        direct_threats = []
        direct_mitigations = []
        direct_analysis_summary = {}

        # Get the skip_mitigation flag from state
        skip_mitigation = state.get('skip_mitigation', False)

        # Calculate REAL progress based on component count
        total_components = len(ai_components) + len(traditional_components)
        
        # **PERFORMANCE OPTIMIZATION: Use parallel analysis**
        from pipeline.performance.parallel_analyzer import (
            ParallelThreatAnalyzer, 
            optimize_token_allocation, 
            should_skip_enhancement
        )
        from pipeline.nodes.llm_analyzer_optimized import (
            _analyze_single_ai_component_optimized,
            _analyze_single_traditional_component_optimized
        )

        # REALISTIC progress allocation - LLM analysis is 60-90% of total time!
        base_progress = 15  # Start LLM analysis at 15% (after fast setup)
        max_progress = 90   # End at 90% (leaving 10% for final steps)

        # Report start of LLM analysis with REAL component count
        if progress_callback:
            progress_callback(base_progress, f"🤖 Analyzing {total_components} components with LLM...")

        # **PARALLEL OPTIMIZATION**: Analyze AI and traditional components concurrently
        with ParallelThreatAnalyzer(max_workers=4) as parallel_analyzer:
            
            # Optimize token allocation for all components
            all_components = ai_components + traditional_components
            token_allocation = optimize_token_allocation(all_components, base_tokens=700, max_tokens=1600)
            
            # Create optimized analysis functions with reduced token usage
            def analyze_ai_component_optimized(component):
                return _analyze_single_ai_component_optimized(
                    client, component, dfd_model, skip_mitigation, token_allocation.get(component.get('name', 'Unknown'), 800)
                )
            
            def analyze_traditional_component_optimized(component):
                return _analyze_single_traditional_component_optimized(
                    client, component, dfd_model, skip_mitigation, token_allocation.get(component.get('name', 'Unknown'), 700)
                )
            
            # Analyze AI components in parallel
            if ai_components:
                console.print(Text("[PERF]", style="bold cyan"), f"Starting parallel analysis of {len(ai_components)} AI components...")
                if progress_callback:
                    progress_callback(base_progress + 10, f"🚀 AI components analysis (parallel)...")
                
                ai_threats = parallel_analyzer.analyze_components_parallel(
                    ai_components, analyze_ai_component_optimized, 'AI'
                )
                direct_threats.extend(ai_threats)
            
            # Analyze traditional components in parallel
            if traditional_components:
                console.print(Text("[PERF]", style="bold cyan"), f"Starting parallel analysis of {len(traditional_components)} traditional components...")
                if progress_callback:
                    progress_callback(base_progress + 35, f"🚀 Traditional components analysis (parallel)...")
                
                traditional_threats = parallel_analyzer.analyze_components_parallel(
                    traditional_components, analyze_traditional_component_optimized, 'Traditional'
                )
                direct_threats.extend(traditional_threats)

        # Report completion with REAL threat count
        if progress_callback:
            progress_callback(max_progress, f"🤖 LLM analysis complete: {len(direct_threats)} threats found")

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
        return {
            "llm_threats": [],
            "llm_mitigations": [],
            "errors": [error_msg]
        }


def _validate_threat_component_logic(threat: Dict[str, Any], component: Dict[str, Any]) -> bool:
    """Enhanced validation that considers component context and cross-component threats"""

    threat_name = threat.get('name', '').lower()
    component_type = component.get('type', '').lower()
    component_name = component.get('name', '').lower()

    # Check if component is AI-related (more comprehensive check)
    is_ai_component = (
        component.get('ai_type') is not None or
        component.get('is_ai_component', False) or
        any(ai_word in component_name for ai_word in ['langgraph', 'openai', 'claude', 'gpt', 'llm', 'ai']) or
        any(ai_type in component_type for ai_type in ['llm', 'ai', 'model', 'openai', 'claude'])
    )

    # Only filter out clearly nonsensical combinations
    clearly_invalid = False

    # Block only extremely obvious mismatches
    if 'xss' in threat_name and any(db_type in component_type for db_type in ['database', 'aurora', 'rds']):
        clearly_invalid = True  # XSS on pure database makes no sense
    elif 'sql injection' in threat_name and any(ui_type in component_type for ui_type in ['mobile', 'ui']) and 'api' not in component_name:
        clearly_invalid = True  # SQL injection on pure UI (not API) makes no sense

    # Allow AI threats for AI components regardless of type classification
    if is_ai_component and any(ai_threat in threat_name for ai_threat in ['prompt injection', 'model extraction', 'adversarial', 'hallucination', 'poisoning']):
        return True

    # Allow infrastructure threats for container/orchestration components
    if any(infra_type in component_type for infra_type in ['ecs', 'container', 'docker', 'kubernetes']):
        return True  # Infrastructure can have various threat types

    # Allow cross-component threats (e.g., API accessing database)
    if any(api_type in component_type for api_type in ['api', 'endpoint', 'rest']) and 'injection' in threat_name:
        return True  # APIs can have injection threats affecting backends

    # Default: be permissive unless clearly invalid
    return not clearly_invalid

def _fix_component_classification(component: Dict[str, Any]) -> Dict[str, Any]:
    """Preserve original component classification - analyze all components regardless of type"""

    # No classification changes - preserve original classification from AI detector
    # All components should be analyzed for threats regardless of their type
    # This ensures comprehensive threat coverage across the entire DFD

    return component

def _analyze_ai_components(client, ai_components: List[Dict], dfd_model, skip_mitigation: bool = False,
                          progress_callback=None, base_progress=40, max_progress=75,
                          processed_count=0, total_count=1) -> Dict[str, Any]:
    """Analyze AI/LLM components for specific threats"""
    console.print(Text("[INFO]", style="bold blue"), "Analyzing AI/LLM components...")

    threats = []
    mitigations = []

    for i, component in enumerate(ai_components):
        try:
            # Fix component classification first
            corrected_component = _fix_component_classification(component.copy())

            # Note: All components should be analyzed - no skipping based on classification
            # The component will be analyzed regardless of its corrected classification

            component_name = corrected_component.get('name', 'Unknown AI Component')
            ai_type = corrected_component.get('ai_type', 'General AI/ML')
            risk_factors = corrected_component.get('risk_factors', [])

            # Limit risk factors to prevent context overflow
            limited_risk_factors = risk_factors[:3] if risk_factors else []

            # Create AI-specific threat analysis prompt with specific naming guidance
            if skip_mitigation:
                # Simplified comprehensive AI threat analysis
                prompt = f"""COMPREHENSIVE AI THREAT ANALYSIS - {ai_type} COMPONENT

COMPONENT: {component_name} ({ai_type})
RISK FACTORS: {', '.join(limited_risk_factors) if limited_risk_factors else 'Standard AI risks'}

AI THREAT CATEGORIES - Generate ALL relevant threats:
1. Input Manipulation (prompt injection, jailbreaking, adversarial inputs)
2. Model Attacks (extraction, inversion, inference attacks)
3. Training Attacks (data poisoning, backdoors)
4. Output Manipulation (hallucination, bias, data leakage)

RETURN ONLY VALID JSON - NO ADDITIONAL TEXT:
{{"threats": [
  {{"name": "Specific AI threat name", "severity": "Critical|High|Medium|Low", "description": "Technical description", "likelihood": "High|Medium|Low", "impact": "AI-specific impact", "probability_score": 85, "ai_specific": true}}
]}}

Generate comprehensive AI threat list covering all 4 categories for {ai_type}:"""
            else:
                # Simplified comprehensive AI analysis with mitigations  
                prompt = f"""COMPREHENSIVE AI THREAT & MITIGATION ANALYSIS - {ai_type}

COMPONENT: {component_name} ({ai_type})
RISK FACTORS: {', '.join(limited_risk_factors) if limited_risk_factors else 'Standard AI risks'}

AI THREAT CATEGORIES - Generate ALL relevant threats with mitigations:
1. Input Manipulation 2. Model Attacks 3. Training Attacks 4. Output Manipulation

RETURN ONLY VALID JSON - NO ADDITIONAL TEXT:
{{"threats": [
  {{"name": "AI threat name", "severity": "Critical|High|Medium|Low", "description": "Technical description", "likelihood": "High|Medium|Low", "impact": "AI impact", "probability_score": 85, "ai_specific": true}}
], "mitigations": [
  {{"name": "AI mitigation", "type": "preventive|detective|corrective", "implementation": "Implementation steps", "effectiveness": "High|Medium|Low"}}
]}}

Generate comprehensive AI analysis covering all 4 categories for {ai_type}:"""

            # Dynamic token allocation based on component complexity
            ai_complexity_factors = [
                len(limited_risk_factors) > 3,  # Many risk factors
                'agent' in ai_type.lower(),      # Complex AI type
                'rag' in ai_type.lower(),        # RAG systems
                'fine' in ai_type.lower()        # Fine-tuned models
            ]
            complexity_score = sum(ai_complexity_factors)
            
            # Adaptive token allocation: 1200-2400 tokens based on complexity
            max_tokens = 1200 + (complexity_score * 300)
            
            console.print_debug(Text("[DEBUG]", style="dim"), f"AI complexity score: {complexity_score}/4, allocated tokens: {max_tokens}")
            
            response = client.generate_response(prompt, max_tokens=max_tokens, temperature=0.1, context=f"AI component analysis: {component_name}")

            # Use advanced parsing with recovery
            recovery_result = _parse_partial_json_threats(response, component_name)
            
            # Validate AI threat coverage completeness
            from pipeline.nodes.threat_coverage_validator import validate_threat_coverage, generate_coverage_enhancement_prompts
            
            initial_threats = recovery_result.get('threats', [])
            coverage_report = validate_threat_coverage(initial_threats, corrected_component, 'ai')
            
            # If coverage is insufficient, generate additional threats (lowered threshold)
            if coverage_report['coverage_score'] < 0.50 and coverage_report['missing_categories']:
                console.print(Text("[WARN]", style="bold yellow"), f"AI threat coverage insufficient: {coverage_report['coverage_score']:.1%}, enhancing analysis...")
                
                enhancement_prompts = generate_coverage_enhancement_prompts(coverage_report, 'ai')
                for enhancement_prompt in enhancement_prompts[:2]:  # Limit to 2 additional analyses
                    enhanced_prompt = f"""ADDITIONAL AI THREAT ANALYSIS - {component_name}

{enhancement_prompt}

Focus on missing threat categories: {', '.join(coverage_report['missing_categories'])}

Provide additional threats in JSON format:
{{"threats": [{{"name": "threat_name", "ai_taxonomy": "category", "severity": "level", "description": "details", "probability_score": 85, "ai_specific": true}}]}}"""
                    
                    additional_response = client.generate_response(enhanced_prompt, max_tokens=600, temperature=0.1)
                    additional_result = _parse_partial_json_threats(additional_response, f"{component_name}_enhanced")
                    
                    # Merge additional threats
                    if additional_result.get('threats'):
                        recovery_result['threats'].extend(additional_result['threats'])
                        console.print(Text("[OK]", style="bold green"), f"Added {len(additional_result['threats'])} additional AI threats")

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

            # Report REAL progress per component processed
            if progress_callback:
                current_component = processed_count + i + 1
                progress_percent = base_progress + int((current_component / total_count) * (max_progress - base_progress))
                progress_callback(progress_percent, f"🤖 Analyzed {current_component}/{total_count} components ({component_name})")

        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze AI component {component_name}: {e}")

            # Report progress even for failed components
            if progress_callback:
                current_component = processed_count + i + 1
                progress_percent = base_progress + int((current_component / total_count) * (max_progress - base_progress))
                progress_callback(progress_percent, f"🤖 Processed {current_component}/{total_count} components (error in {component_name})")

    return {
        'threats': threats,
        'mitigations': mitigations,
        'summary': {
            'ai_specific_threats': len(threats),
            'ai_components_analyzed': len(ai_components)
        }
    }


def _analyze_traditional_components(client, traditional_components: List[Dict], dfd_model, skip_mitigation: bool = False,
                                   progress_callback=None, base_progress=40, max_progress=75,
                                   processed_count=0, total_count=1) -> Dict[str, Any]:
    """Analyze traditional components for standard security threats"""
    console.print(Text("[INFO]", style="bold blue"), "Analyzing traditional components...")

    threats = []
    mitigations = []

    for i, component in enumerate(traditional_components):
        try:
            # Fix component classification first
            corrected_component = _fix_component_classification(component.copy())

            component_name = corrected_component.get('name', 'Unknown Component')
            component_type = corrected_component.get('type', 'Unknown')
            component_category = corrected_component.get('component_category', 'Traditional')

            # Create COMPACT traditional threat analysis prompt with component context and specific naming
            component_context = f"Component Category: {component_category}, Type: {component_type}"

            if skip_mitigation:
                # Simplified but comprehensive STRIDE-based analysis
                prompt = f"""COMPREHENSIVE THREAT ANALYSIS - {component_type.upper()} COMPONENT

COMPONENT: {component_name} ({component_type})
CATEGORY: {component_category}

APPLY STRIDE METHODOLOGY - Generate ALL relevant threats:
- Spoofing (Identity attacks)
- Tampering (Data integrity attacks)
- Repudiation (Audit/logging failures) 
- Information Disclosure (Data exposure)
- Denial of Service (Availability attacks)
- Elevation of Privilege (Authorization bypass)

RETURN ONLY VALID JSON - NO ADDITIONAL TEXT:
{{"threats": [
  {{"name": "Specific threat name", "severity": "Critical|High|Medium|Low", "description": "Technical description", "likelihood": "High|Medium|Low", "impact": "Impact description", "probability_score": 85}}
]}}

Generate comprehensive threat list for {component_type} - include all STRIDE categories with realistic threats:"""
            else:
                # Simplified comprehensive analysis with mitigations
                prompt = f"""COMPREHENSIVE THREAT & MITIGATION ANALYSIS - {component_type.upper()}

COMPONENT: {component_name} ({component_type})
CATEGORY: {component_category}

APPLY STRIDE METHODOLOGY - Generate ALL relevant threats with mitigations:

RETURN ONLY VALID JSON - NO ADDITIONAL TEXT:
{{"threats": [
  {{"name": "Specific threat name", "severity": "Critical|High|Medium|Low", "description": "Technical description", "likelihood": "High|Medium|Low", "impact": "Impact description", "probability_score": 85}}
], "mitigations": [
  {{"name": "Mitigation name", "type": "preventive|detective|corrective", "implementation": "Implementation steps", "effectiveness": "High|Medium|Low"}}
]}}

Generate comprehensive analysis for {component_type} - include all STRIDE categories with realistic threats and mitigations:"""

            # Reduce max_tokens to prevent overflow
            # Dynamic token allocation for traditional components
            traditional_complexity_factors = [
                'database' in component_type.lower(),     # Complex data systems
                'api' in component_type.lower(),          # API endpoints
                'gateway' in component_type.lower(),      # Gateway components
                'balancer' in component_type.lower(),     # Load balancers
                'auth' in component_type.lower(),         # Authentication systems
                len(str(corrected_component.get('connections', []))) > 50  # Many connections
            ]
            complexity_score = sum(traditional_complexity_factors)
            
            # Adaptive token allocation: 800-1600 tokens
            max_tokens = 800 + (complexity_score * 200)
            
            console.print_debug(Text("[DEBUG]", style="dim"), f"Traditional complexity score: {complexity_score}/6, allocated tokens: {max_tokens}")
            
            response = client.generate_response(prompt, max_tokens=max_tokens, temperature=0.1, context=f"Traditional component analysis: {component_name}")

            # Use advanced parsing with recovery
            recovery_result = _parse_partial_json_threats(response, component_name)
            
            # Validate traditional threat coverage completeness
            from pipeline.nodes.threat_coverage_validator import validate_threat_coverage, generate_coverage_enhancement_prompts
            
            initial_threats = recovery_result.get('threats', [])
            coverage_report = validate_threat_coverage(initial_threats, corrected_component, 'traditional')
            
            # If coverage is insufficient, generate additional threats (lowered threshold)
            if coverage_report['coverage_score'] < 0.45 and coverage_report['missing_categories']:
                console.print(Text("[WARN]", style="bold yellow"), f"Traditional threat coverage insufficient: {coverage_report['coverage_score']:.1%}, enhancing analysis...")
                
                enhancement_prompts = generate_coverage_enhancement_prompts(coverage_report, 'traditional')
                for enhancement_prompt in enhancement_prompts[:2]:  # Limit to 2 additional analyses
                    enhanced_prompt = f"""ADDITIONAL STRIDE THREAT ANALYSIS - {component_name}

{enhancement_prompt}

Focus on missing STRIDE categories: {', '.join(coverage_report['missing_categories'])}

Provide additional threats in JSON format:
{{"threats": [{{"name": "threat_name", "stride_category": "category", "severity": "level", "description": "details", "probability_score": 85}}]}}"""
                    
                    additional_response = client.generate_response(enhanced_prompt, max_tokens=600, temperature=0.1)
                    additional_result = _parse_partial_json_threats(additional_response, f"{component_name}_enhanced")
                    
                    # Merge additional threats
                    if additional_result.get('threats'):
                        recovery_result['threats'].extend(additional_result['threats'])
                        console.print(Text("[OK]", style="bold green"), f"Added {len(additional_result['threats'])} additional traditional threats")

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

            # Report REAL progress per traditional component processed
            if progress_callback:
                current_component = processed_count + i + 1
                progress_percent = base_progress + int((current_component / total_count) * (max_progress - base_progress))
                progress_callback(progress_percent, f"🤖 Analyzed {current_component}/{total_count} components ({component_name})")

        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Failed to analyze component {component_name}: {e}")

            # Report progress even for failed traditional components
            if progress_callback:
                current_component = processed_count + i + 1
                progress_percent = base_progress + int((current_component / total_count) * (max_progress - base_progress))
                progress_callback(progress_percent, f"🤖 Processed {current_component}/{total_count} components (error in {component_name})")

    return {
        'threats': threats,
        'mitigations': mitigations,
        'summary': {
            'traditional_threats': len(threats),
            'traditional_components_analyzed': len(traditional_components)
        }
    }
