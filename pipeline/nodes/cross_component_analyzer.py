# Cross-Component Threat Analysis Node - Analyzes data flows and trust boundary crossings

from typing import Dict, Any, List
from utils.console import console
from rich.text import Text

def cross_component_analyzer_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """Cross-Component Analysis Node"""
    console.print(Text("[INFO]", style="bold blue"), "Cross-Component Analysis Node: Analyzing cross-zone threats...")

    # Check if cross-component analysis was already completed
    existing_threats = state.get('cross_component_threats', [])
    if existing_threats:
        console.print(Text("[INFO]", style="bold blue"), f"Cross-Component Analysis: Already completed with {len(existing_threats)} threats")
        return {
            "cross_component_threats": []
        }

    try:
        # Skip if no DFD model
        dfd_model = state.get('dfd_model')
        if not dfd_model:
            console.print(Text("[WARN]", style="bold yellow"), "No DFD model available for cross-component analysis")
            return {
                "cross_component_threats": [],
                "warnings": ["No DFD model available for cross-component analysis"]
            }

        # Get DFD model and components
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])

        all_components = ai_components + traditional_components

        # Initialize LLM client for advanced threat analysis
        from rag.llm_client import UnifiedLLMClient

        try:
            client = UnifiedLLMClient()
            if not client.available_models:
                error_msg = "Cross-component analysis requires LLM - no models available"
                console.print(Text("[ERROR]", style="bold red"), error_msg)
                return {
                    "cross_component_threats": [],
                    "errors": [error_msg]
                }
        except Exception as e:
            error_msg = f"Failed to initialize LLM for cross-component analysis: {e}"
            console.print(Text("[ERROR]", style="bold red"), error_msg)
            return {
                "cross_component_threats": [],
                "errors": [error_msg]
            }

        # **PARALLEL OPTIMIZATION**: Analyze data flows in parallel
        cross_threats = []
        skip_mitigation = state.get('skip_mitigation', False)
        
        # Import parallel analyzer
        from pipeline.performance.parallel_analyzer import ParallelThreatAnalyzer
        
        with ParallelThreatAnalyzer(max_workers=3) as parallel_analyzer:  # Fewer workers for cross-analysis
            
            console.print(Text("[PERF]", style="bold cyan"), "🚀 Starting parallel cross-component analysis...")
            
            # Create analysis tasks that can run in parallel
            analysis_tasks = []
            
            # Task 1: Trust boundary analysis
            if hasattr(dfd_model, 'connections') and dfd_model.connections:
                analysis_tasks.append({
                    'type': 'trust_boundaries',
                    'function': lambda: _analyze_trust_boundaries(client, dfd_model, all_components, skip_mitigation),
                    'name': 'Trust Boundaries'
                })
            
            # Task 2: AI integration analysis  
            if ai_components and traditional_components:
                analysis_tasks.append({
                    'type': 'ai_integration',
                    'function': lambda: _analyze_ai_integration_flows(client, ai_components, traditional_components, dfd_model, skip_mitigation),
                    'name': 'AI Integration'
                })
            
            # Task 3: External dependencies (if any external components detected)
            external_components = [c for c in all_components if any(ext in c.get('name', '').lower() for ext in ['openai', 'aws', 'external', 'api'])]
            if external_components:
                analysis_tasks.append({
                    'type': 'external_deps',
                    'function': lambda: _analyze_external_dependencies(client, all_components, dfd_model, skip_mitigation),
                    'name': 'External Dependencies'
                })
            
            # Task 4: Auth flows (if auth components detected)
            auth_components = [c for c in all_components if any(auth in c.get('name', '').lower() or auth in c.get('type', '').lower() 
                                                               for auth in ['auth', 'login', 'oauth', 'jwt', 'token'])]
            if auth_components:
                analysis_tasks.append({
                    'type': 'auth_flows', 
                    'function': lambda: _analyze_authentication_flows(client, all_components, dfd_model, skip_mitigation),
                    'name': 'Auth Flows'
                })
            
            # Execute analysis tasks in parallel
            if analysis_tasks:
                import concurrent.futures
                
                console.print_debug(Text("[PERF]", style="dim cyan"), f"Executing {len(analysis_tasks)} cross-component analysis tasks in parallel...")
                
                futures = []
                for task in analysis_tasks:
                    future = parallel_analyzer.executor.submit(task['function'])
                    futures.append((future, task['name']))
                
                # Collect results
                for future, task_name in futures:
                    try:
                        threats = future.result(timeout=120)  # 2 minute timeout per cross-analysis
                        cross_threats.extend(threats)
                        console.print_debug(Text("[PERF]", style="dim green"), f"✅ {task_name}: {len(threats)} threats")
                        
                    except concurrent.futures.TimeoutError:
                        console.print(Text("[WARN]", style="bold yellow"), f"⏱️ {task_name} analysis timeout - skipping")
                    except Exception as e:
                        console.print(Text("[WARN]", style="bold yellow"), f"❌ {task_name} analysis failed: {e}")
            else:
                console.print(Text("[INFO]", style="bold blue"), "No cross-component analysis tasks needed")

        console.print(Text("[OK]", style="bold green"), f"Cross-component analysis complete: {len(cross_threats)} flow-based threats identified")

        return {
            "cross_component_threats": cross_threats,
            "trust_boundary_count": len(dfd_model.trust_boundaries) if hasattr(dfd_model, 'trust_boundaries') else 0,
            "data_flow_count": len(dfd_model.connections) if hasattr(dfd_model, 'connections') else 0
        }

    except ImportError as e:
        error_msg = f"Missing dependencies for cross-component analysis: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {
            "cross_component_threats": [],
            "errors": [error_msg]
        }
    except Exception as e:
        error_msg = f"Cross-component analysis failed: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {
            "cross_component_threats": [],
            "errors": [error_msg]
        }

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

    # Enhanced trust boundary analysis with compliance context
    prompt = f"""TRUST BOUNDARY CROSSING SECURITY ANALYSIS

DATA FLOW PROFILE:
- SOURCE: {source_name} (Trust Zone: {source_zone})
- TARGET: {target_name} (Trust Zone: {target_zone})
- FLOW TYPE: Trust Boundary Crossing
- SECURITY CONTEXT: Inter-Zone Communication

TRUST BOUNDARY THREAT FRAMEWORK:
1. **AUTHENTICATION THREATS**
   - Missing mutual authentication
   - Weak credential validation
   - Session hijacking across zones

2. **AUTHORIZATION THREATS**
   - Privilege escalation across boundaries
   - Access control bypass
   - Resource authorization failures

3. **DATA INTEGRITY THREATS**
   - Man-in-the-middle attacks
   - Data tampering in transit
   - Message replay attacks

4. **CONFIDENTIALITY THREATS**
   - Unencrypted data transmission
   - Cryptographic weaknesses
   - Key management failures

COMPLIANCE CONSIDERATIONS:
- Zero Trust Architecture principles
- Network segmentation requirements (PCI-DSS, SOC 2)
- Data protection in transit (GDPR, HIPAA)
- Cryptographic standards (FIPS 140-2, Common Criteria)

OUTPUT FORMAT:
{{"threats": [{{"id": "TB-{source_name}-{target_name}-001", "name": "Specific boundary crossing threat with technical detail", "threat_category": "Authentication|Authorization|Data Integrity|Confidentiality", "severity": "Critical|High|Medium|Low", "description": "Detailed technical description of boundary threat", "attack_vector": "Cross-zone attack method", "impact": "Business and security impact", "likelihood": "High|Medium|Low", "probability_score": 85, "boundary_type": "trust_boundary_crossing", "compliance_impact": "PCI-DSS|SOC2|GDPR|HIPAA", "zone_risk": "high|medium|low", "prerequisites": ["Network access requirements"], "indicators": ["Network-level detection indicators"]}}]}}

EXAMPLES OF EXCELLENT BOUNDARY THREAT NAMES:
- "Unencrypted Redis Cache Data Exposure in Transit to ECS (GDPR Violation)"
- "Missing Mutual TLS Authentication Between Load Balancer and Backend (Zero Trust Failure)"
- "Man-in-the-Middle Attack on API Gateway Communications via Certificate Spoofing"
- "Cross-Zone Privilege Escalation via Weak Service Account Validation"
- "Session Token Interception in DMZ to Internal Network Communication"

COMPREHENSIVE TRUST BOUNDARY ANALYSIS:
Generate ALL relevant trust boundary crossing threats for this data flow. Include complete coverage of:
- All four threat categories (Authentication, Authorization, Data Integrity, Confidentiality)
- Protocol-specific vulnerabilities (HTTP/HTTPS, TLS, API-specific)
- Network-level and application-level boundary threats
- Zone-specific security control failures
- Cross-zone privilege escalation scenarios

Trust boundary crossings typically expose 6-12+ distinct threat vectors. Provide thorough analysis:"""

    try:
        # Dynamic token allocation for trust boundary complexity
        boundary_complexity_factors = [
            source_zone != target_zone,                    # Different trust zones
            'external' in source_zone.lower(),            # External connections
            'dmz' in (source_zone + target_zone).lower(), # DMZ involvement
            'database' in (source_name + target_name).lower(), # Database connections
            'api' in (source_name + target_name).lower(),      # API connections
        ]
        complexity_score = sum(boundary_complexity_factors)
        
        # Adaptive token allocation: 800-1400 tokens
        max_tokens = 800 + (complexity_score * 120)
        
        console.print_debug(Text("[DEBUG]", style="dim"), f"Boundary complexity score: {complexity_score}/5, allocated tokens: {max_tokens}")
        
        response = client.generate_response(prompt, max_tokens=max_tokens, temperature=0.1)

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

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_threat_description", "likelihood": "High/Medium/Low", "impact": "specific_impact_description", "integration_type": "ai_traditional", "probability_score": 85}}]}}

probability_score (0-100): How likely is this AI-traditional integration threat to be ACTUALLY PRESENT in this specific system? Consider: AI-traditional component mix, data flow patterns, integration security controls.

EXAMPLES of good names:
- "Prompt Injection via FastAPI Input Validation Bypass"
- "LLM Model Extraction Through Database Query Manipulation"
- "AI Hallucination Data Poisoning via User Upload"
- "Unauthorized LLM Access Through API Authentication Bypass"

Focus on specific AI-traditional vulnerabilities: AI output validation gaps, prompt injection via traditional inputs, model poisoning through data flows, unauthorized AI access patterns, data leakage between AI and traditional systems."""

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

{{"threats": [{{"name": "specific_descriptive_threat_name", "severity": "Critical/High/Medium/Low", "description": "detailed_threat_description", "likelihood": "High/Medium/Low", "impact": "specific_impact_description", "dependency_type": "external_service", "probability_score": 85}}]}}

probability_score (0-100): How likely is this external dependency threat to be ACTUALLY PRESENT in this specific system? Consider: external service reliability, dependency criticality, security controls.

EXAMPLES of good names:
- "OpenAI API Rate Limiting Service Disruption"
- "AWS Service Account Compromise via Credential Leak"
- "Third-Party SaaS Data Sovereignty Violation"
- "External Provider Supply Chain Attack via Dependency"
- "Vendor Lock-in Risk from Single Cloud Provider"

Focus on specific external risks: service availability disruptions, API rate limiting impacts, data sovereignty violations, vendor lock-in dependencies, service account compromises, supply chain attack vectors."""

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
{{"threats": [{{"name": "threat_name", "severity": "Critical/High/Medium/Low", "description": "threat_description", "likelihood": "High/Medium/Low", "impact": "impact_description", "flow_type": "authentication", "probability_score": 85}}]}}

probability_score (0-100): How likely is this authentication threat to be ACTUALLY PRESENT in this specific system? Consider: auth components found, deployment context, flow complexity.

Focus on: token theft, session hijacking, authentication bypass, privilege escalation, credential stuffing, OIDC vulnerabilities."""

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
            'probability_score': 75,  # High likelihood for trust boundary issues
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
            'probability_score': 60,  # Medium likelihood for integration issues
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
