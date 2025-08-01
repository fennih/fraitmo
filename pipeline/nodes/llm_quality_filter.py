# LLM Quality Filter Node - Deduplicates threats and creates threat-mitigation mappings

from typing import Dict, Any, List
import json
from utils.console import console
from rich.text import Text
import re

def _infer_severity_from_threat_name(threat_name: str) -> str:
    """
    Infer threat severity from threat name using comprehensive keyword matching
    """
    if not threat_name:
        return 'Medium'

    name_lower = threat_name.lower()

    # CRITICAL severity keywords (immediate system compromise)
    critical_keywords = [
        'injection', 'sql injection', 'command injection', 'code injection',
        'rce', 'remote code execution', 'privilege escalation', 'escalation',
        'bypass', 'authentication bypass', 'authorization bypass',
        'extraction', 'model extraction', 'parameter extraction',
        'unauthenticated', 'unauthorized access', 'data leakage',
        'prompt injection', 'malicious prompt', 'poisoning',
        'manipulation', 'hallucination manipulation'
    ]

    # HIGH severity keywords (significant security impact)
    high_keywords = [
        'xss', 'cross-site scripting', 'csrf', 'cross-site request forgery',
        'mitm', 'man-in-the-middle', 'session hijacking', 'hijacking',
        'unencrypted', 'missing encryption', 'missing authentication',
        'missing authorization', 'insecure', 'vulnerability',
        'tampering', 'spoofing', 'interception', 'eavesdropping'
    ]

    # MEDIUM severity keywords (moderate security risk)
    medium_keywords = [
        'ddos', 'denial of service', 'amplification', 'flooding',
        'rate limiting', 'resource exhaustion', 'misconfiguration',
        'weak', 'insufficient', 'improper', 'inadequate'
    ]

    # LOW severity keywords (minor security concerns)
    low_keywords = [
        'information disclosure', 'exposure', 'leakage',
        'timeout', 'availability', 'service disruption',
        'logging', 'monitoring', 'audit',
        'ssl', 'tls', 'certificate', 'downgrade',
        'query depth', 'nested query', 'path traversal', 'directory traversal',
        'idor', 'insecure direct object reference', 'ssrf', 'server-side request forgery'
    ]

    # Check for critical threats first (highest priority)
    for keyword in critical_keywords:
        if keyword in name_lower:
            return 'Critical'

    # Check for high severity threats
    for keyword in high_keywords:
        if keyword in name_lower:
            return 'High'

    # Check for medium severity threats
    for keyword in medium_keywords:
        if keyword in name_lower:
            return 'Medium'

    # Check for low severity threats
    for keyword in low_keywords:
        if keyword in name_lower:
            return 'Low'

    # Default for unknown threats (conservative approach)
    return 'Medium'

def _generate_unique_threat_id(threat: Dict[str, Any], index: int) -> str:
    """Generate unique threat ID based on component and threat characteristics"""

    # Extract component name
    target_comp = threat.get('target_component', {})
    if isinstance(target_comp, dict):
        component_name = target_comp.get('name', 'Unknown')
    elif isinstance(target_comp, str):
        component_name = target_comp
    else:
        component_name = 'Unknown'

    # Clean component name for ID
    clean_component = re.sub(r'[^a-zA-Z0-9]', '', component_name.replace(' ', ''))[:8].upper()

    # Determine threat type prefix
    threat_name = threat.get('name', 'Unknown').lower()
    ai_specific = threat.get('ai_specific', False)

    if ai_specific or any(kw in threat_name for kw in ['prompt', 'model', 'adversarial', 'hallucination', 'bias']):
        prefix = 'AI'
    elif any(kw in threat_name for kw in ['sql', 'injection', 'xss', 'csrf']):
        prefix = 'WEB'
    elif any(kw in threat_name for kw in ['auth', 'bypass', 'escalation']):
        prefix = 'AUTH'
    elif any(kw in threat_name for kw in ['network', 'ddos', 'mitm']):
        prefix = 'NET'
    else:
        prefix = 'GEN'

    # Generate final ID: PREFIX-COMPONENT-###
    threat_id = f"{prefix}-{clean_component}-{index:03d}"

    return threat_id

def _assign_threat_ids_and_sort(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Assign unique IDs to threats and sort by component and severity"""

    # Group threats by component for better organization
    threats_by_component = {}
    for threat in threats:
        target_comp = threat.get('target_component', {})
        if isinstance(target_comp, dict):
            component_name = target_comp.get('name', 'Unknown')
        elif isinstance(target_comp, str):
            component_name = target_comp
        else:
            component_name = 'Unknown'

        if component_name not in threats_by_component:
            threats_by_component[component_name] = []
        threats_by_component[component_name].append(threat)

    # Sort components alphabetically and threats by severity within each component
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4}

    final_threats = []
    global_index = 1

    for component_name in sorted(threats_by_component.keys()):
        component_threats = threats_by_component[component_name]

        # Sort threats within component by severity
        component_threats.sort(key=lambda t: severity_order.get(t.get('severity', 'Unknown'), 5))

        # Assign IDs and add to final list
        for threat in component_threats:
            threat_id = _generate_unique_threat_id(threat, global_index)
            threat['id'] = threat_id
            threat['component_order'] = component_name
            threat['severity_order'] = severity_order.get(threat.get('severity', 'Unknown'), 5)
            final_threats.append(threat)
            global_index += 1

    console.print(Text("[DEBUG]", style="bold blue"), f"Assigned unique IDs to {len(final_threats)} threats across {len(threats_by_component)} components")

    return final_threats

def llm_quality_filter_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """
    LLM Quality Filter Node
    Uses LLM as judge to deduplicate threats and create specific threat-mitigation mappings
    """
    # Check if quality filter was already applied
    if state.get('quality_filter_applied', False):
        console.print(Text("[INFO]", style="bold blue"), "LLM Quality Filter: Already applied, skipping duplicate execution")
        # Return existing results instead of empty lists to preserve data
        return {
            "filtered_threats": state.get('filtered_threats', []),
            "filtered_mitigations": state.get('filtered_mitigations', []),
            "quality_filter_applied": True
        }

    console.print(Text("[INFO]", style="bold blue"), "LLM Quality Filter: Starting deduplication and mapping...")

    try:
        # Import LLM client
        from rag.llm_client import UnifiedLLMClient

        # Get all threats from both paths
        rag_threats = state.get('threats_found', [])
        llm_threats = state.get('llm_threats', [])
        cross_threats = state.get('cross_component_threats', [])
        all_threats = rag_threats + llm_threats + cross_threats

        # DETAILED LOGGING FOR DEBUGGING
        console.print(Text("[INFO]", style="bold magenta"), f"📊 THREAT GENERATION BREAKDOWN:")
        console.print(Text("[INFO]", style="bold magenta"), f"   RAG Threats: {len(rag_threats)}")
        console.print(Text("[INFO]", style="bold magenta"), f"   LLM Threats: {len(llm_threats)}")
        console.print(Text("[INFO]", style="bold magenta"), f"   Cross-Component Threats: {len(cross_threats)}")
        console.print(Text("[INFO]", style="bold magenta"), f"   TOTAL INPUT: {len(all_threats)} threats")

        # Get all mitigations
        rag_mitigations = state.get('rag_mitigations', [])
        llm_mitigations = state.get('llm_mitigations', [])
        all_mitigations = rag_mitigations + llm_mitigations

        console.print(Text("[INFO]", style="bold blue"), f"Processing {len(all_threats)} threats and {len(all_mitigations)} mitigations...")

        llm_client = UnifiedLLMClient()
        if not llm_client.active_model:
            console.print(Text("[WARN]", style="bold yellow"), "No LLM available for quality filtering - using fallback filtering")
            return {
                'filtered_threats': all_threats[:50],  # Fallback: just take first 50
                'filtered_mitigations': all_mitigations[:20],  # Fallback: just take first 20
                'threat_mitigation_mapping': {},
                'quality_filter_applied': False,
                'quality_filter_metadata': {
                    'fallback_reason': 'No LLM available',
                    'original_threat_count': len(all_threats),
                    'original_mitigation_count': len(all_mitigations)
                },
                'final_counts': {
                    'threats': min(50, len(all_threats)),
                    'mitigations': min(20, len(all_mitigations))
                }
            }

        # Get DFD model for architectural context
        dfd_model = state.get('dfd_model', {})

        console.print(Text("[INFO]", style="bold blue"), "🧠 Starting intelligent threat applicability assessment...")

        # DISABLE ALL FILTERING: Let all threats pass through
        console.print(Text("[INFO]", style="bold green"), f"💡 FILTERING DISABLED: Keeping ALL {len(all_threats)} generated threats")
        applicable_threats = all_threats  # Skip applicability assessment completely

        console.print(Text("[INFO]", style="bold magenta"), f"📊 AFTER APPLICABILITY ASSESSMENT: {len(applicable_threats)} threats (filtered 0)")

        # DISABLE probability filter completely
        console.print(Text("[INFO]", style="bold green"), f"💡 SKIP probability filter - keeping all {len(applicable_threats)} threats")

        console.print(Text("[INFO]", style="bold magenta"), f"📊 AFTER PROBABILITY FILTER: {len(applicable_threats)} threats (filtered 0)")

        # DISABLE deduplication completely
        console.print(Text("[INFO]", style="bold green"), f"💡 SKIP deduplication - keeping all {len(applicable_threats)} threats")
        deduplicated_threats = applicable_threats

        console.print(Text("[INFO]", style="bold magenta"), f"📊 AFTER DEDUPLICATION: {len(deduplicated_threats)} threats (removed 0 duplicates)")

        # Assign unique IDs to threats
        threat_id = 1
        for threat in deduplicated_threats:
            threat['id'] = f"T{threat_id:03d}"
            threat_id += 1

        # Group threats by component for display
        threats_by_component = {}
        for threat in deduplicated_threats:
            component_name = threat.get('target_component', {}).get('name', 'Unknown') if isinstance(threat.get('target_component'), dict) else threat.get('target_component', 'Unknown')
            if component_name not in threats_by_component:
                threats_by_component[component_name] = []
            threats_by_component[component_name].append(threat)

        console.print(Text("[DEBUG]", style="bold blue"), f"Assigned unique IDs to {len(deduplicated_threats)} threats across {len(threats_by_component)} components")
        console.print(Text("[INFO]", style="bold magenta"), f"📊 FINAL OUTPUT: {len(deduplicated_threats)} threats")

        # CRITICAL: Clean up and validate all threats - NO UNKNOWN VALUES ALLOWED!
        console.print(Text("[INFO]", style="bold blue"), "🧹 Cleaning up threats to eliminate Unknown values...")
        final_threats = _cleanup_and_validate_threats(deduplicated_threats, dfd_model)
        console.print(Text("[INFO]", style="bold magenta"), f"📊 AFTER CLEANUP: {len(final_threats)} validated threats")

        # Step 4: Create threat-mitigation mappings
        threat_mitigation_mapping = _create_threat_mitigation_mapping(llm_client, final_threats, all_mitigations)

        # Step 5: Filter and rank mitigations
        filtered_mitigations = _filter_and_rank_mitigations(llm_client, threat_mitigation_mapping, all_mitigations)

        console.print(Text("[OK]", style="bold green"), f"Quality filter complete: {len(final_threats)} applicable threats, {len(filtered_mitigations)} relevant mitigations")

        return {
            'filtered_threats': final_threats,
            'filtered_mitigations': filtered_mitigations,
            'threat_mitigation_mapping': threat_mitigation_mapping,
            'quality_filter_applied': True,
            'quality_filter_metadata': {
                'original_threat_count': len(all_threats),
                'original_mitigation_count': len(all_mitigations),
                'applicability_assessment_enabled': False,  # Disabled
                'probability_filtering_enabled': False,     # Disabled
                'deduplication_enabled': False              # Disabled
            },
            'final_counts': {
                'threats': len(final_threats),
                'mitigations': len(filtered_mitigations)
            }
        }

    except ImportError as e:
        error_msg = f"Missing dependencies for quality filtering: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {
            "filtered_threats": [],
            "filtered_mitigations": [],
            "errors": [error_msg]
        }
    except Exception as e:
        error_msg = f"Quality filtering failed: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {
            "filtered_threats": [],
            "filtered_mitigations": [],
            "errors": [error_msg]
        }

def _deduplicate_threats_with_llm(llm_client, threats: List[Dict]) -> List[Dict]:
    """Use LLM to identify and remove duplicate threats"""

    if len(threats) <= 10:
        return threats  # No need to deduplicate small lists

    console.print(Text("[DEBUG]", style="bold blue"), f"LLM deduplicating {len(threats)} threats...")

    # SIMPLIFIED APPROACH: Group threats by component for more efficient processing
    threats_by_component = {}
    for threat in threats:
        # Handle different target_component formats
        target_comp = threat.get('target_component', {})
        if isinstance(target_comp, dict):
            component = target_comp.get('name', 'unknown')
        elif isinstance(target_comp, str):
            component = target_comp
        else:
            component = threat.get('component', 'unknown')  # Fallback to component field

        if component not in threats_by_component:
            threats_by_component[component] = []
        threats_by_component[component].append(threat)

    deduplicated = []

    for component, component_threats in threats_by_component.items():
        if len(component_threats) <= 5:  # INCREASED from 3 to 5
            # Keep all threats if only a few
            deduplicated.extend(component_threats)
            console.print(Text("[DEBUG]", style="dim green"), f"Component {component}: kept all {len(component_threats)} threats")
            continue

        # For many threats, try LLM dedup but with more permissive fallback
        threat_summaries = []
        for i, threat in enumerate(component_threats):
            summary = {
                'index': i,
                'name': threat.get('name', 'Unknown')[:50],
                'severity': threat.get('severity', 'Unknown'),
                'description': threat.get('description', '')[:60] + '...' if len(threat.get('description', '')) > 60 else threat.get('description', '')
            }
            threat_summaries.append(summary)

        # Enhanced semantic deduplication prompt
        dedup_prompt = f"""INTELLIGENT THREAT DEDUPLICATION ANALYSIS

COMPONENT: {component}
TOTAL THREATS: {len(component_threats)}

DEDUPLICATION CRITERIA:
1. **Semantic Similarity**: Same attack vector, different wording
2. **Technical Overlap**: Same CWE/CVE reference, different descriptions  
3. **Impact Equivalence**: Same business impact, different technical paths
4. **Scope Redundancy**: Subset threats covered by broader threats

THREATS TO ANALYZE:
{json.dumps(threat_summaries[:10], indent=2)}

ANALYSIS FRAMEWORK:
- Group by attack vector families (SQL injection, XSS, etc.)
- Identify parent-child relationships
- Preserve unique technical variants
- Maintain severity-based distinctions

DECISION RULES:
- Keep: Different attack vectors OR different business impacts
- Merge: Same vector + same impact + same component
- Elevate: Choose highest severity when merging
- Preserve: All Critical/High severity threats

OUTPUT FORMAT:
{{"analysis": {{"keep_indices": [0, 1, 3, 5, 7], "merge_groups": [[2, 4], [6, 8]], "reasoning": ["Index 0: Unique SQL injection vector", "Indices 2,4: Merged - same XSS attack, kept higher severity"]}}}}

Perform intelligent deduplication analysis:"""

        try:
            response = llm_client.generate_response(dedup_prompt, max_tokens=500, temperature=0.0)

            # Enhanced parsing for new response format
            try:
                import re
                # Look for nested JSON structure
                json_match = re.search(r'\{[\s\S]*?\}', response)
                if json_match:
                    parsed = json.loads(json_match.group(0))
                    
                    # Extract analysis results
                    analysis = parsed.get('analysis', {})
                    keep_indices = analysis.get('keep_indices', [])
                    merge_groups = analysis.get('merge_groups', [])
                    reasoning = analysis.get('reasoning', [])
                    
                    # Log deduplication reasoning
                    console.print(Text("[DEBUG]", style="dim"), f"Deduplication reasoning: {reasoning[:3]}")
                    
                    # Validate indices
                    valid_indices = [i for i in keep_indices if 0 <= i < len(component_threats)]
                    
                    # Process merge groups - keep highest severity from each group
                    for group in merge_groups:
                        if len(group) > 1:
                            # Find highest severity threat in group
                            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
                            best_idx = max(group, key=lambda idx: severity_order.get(
                                component_threats[idx].get('severity', 'unknown').lower(), 0
                            ) if idx < len(component_threats) else 0)
                            if best_idx not in valid_indices:
                                valid_indices.append(best_idx)

                    if valid_indices and len(valid_indices) >= 3:  # Must keep at least 3
                        # Add selected unique threats
                        for idx in valid_indices:
                            deduplicated.append(component_threats[idx])
                        console.print(Text("[DEBUG]", style="bold green"), f"Component {component}: {len(component_threats)} → {len(valid_indices)} threats (LLM)")
                    else:
                        # Permissive fallback: take first 8 threats instead of 3
                        deduplicated.extend(component_threats[:8])
                        console.print(Text("[DEBUG]", style="bold yellow"), f"Component {component}: kept {min(8, len(component_threats))} threats (permissive fallback)")
                else:
                    # No JSON found: permissive fallback
                    deduplicated.extend(component_threats[:8])
                    console.print(Text("[DEBUG]", style="bold yellow"), f"Component {component}: kept {min(8, len(component_threats))} threats (no JSON fallback)")

            except json.JSONDecodeError:
                # JSON parsing failed: permissive fallback
                deduplicated.extend(component_threats[:8])
                console.print(Text("[DEBUG]", style="bold yellow"), f"Component {component}: kept {min(8, len(component_threats))} threats (JSON error fallback)")

        except Exception as e:
            # LLM call failed: permissive fallback
            deduplicated.extend(component_threats[:8])
            console.print(Text("[DEBUG]", style="bold yellow"), f"Component {component}: kept {min(8, len(component_threats))} threats (LLM error fallback)")

    return deduplicated

def _create_threat_mitigation_mapping(llm_client, threats: List[Dict], mitigations: List[Dict]) -> Dict[str, List[str]]:
    """Create explicit threat → mitigation mappings using LLM"""

    console.print(Text("[DEBUG]", style="bold blue"), f"Creating threat-mitigation mappings...")

    mapping = {}

    # Process threats in smaller batches to avoid context overflow
    batch_size = 3  # Reduced from 5 to 3
    for i in range(0, len(threats), batch_size):  # Process all threats
        batch_threats = threats[i:i+batch_size]

        # Create simplified threat list for LLM
        threat_list = []
        for j, threat in enumerate(batch_threats):
            threat_list.append({
                'id': f"T{i+j+1}",
                'name': threat.get('name', 'Unknown'),
                'category': threat.get('category', 'Unknown'),
                'description': threat.get('description', '')[:100] + '...' if len(threat.get('description', '')) > 100 else threat.get('description', '')
            })

        # Create simplified mitigation list
        mitigation_list = []
        for k, mitigation in enumerate(mitigations):
            mitigation_list.append({
                'id': f"M{k+1}",
                'name': mitigation.get('name', mitigation.get('control', 'Unknown')),
                'type': mitigation.get('type', 'Unknown'),
                'description': mitigation.get('description', mitigation.get('implementation', ''))[:100] + '...' if len(mitigation.get('description', mitigation.get('implementation', ''))) > 100 else mitigation.get('description', mitigation.get('implementation', ''))
            })

        # Compact LLM mapping prompt with explicit JSON formatting
        mapping_prompt = f"""Map each threat ID to mitigation IDs. Return only valid JSON in this exact format:

{{"T1":["M1","M2"],"T2":["M3"]}}

THREATS: {json.dumps(threat_list)}
MITIGATIONS: {json.dumps(mitigation_list[:8])}"""

        try:
            response = llm_client.generate_response(mapping_prompt, max_tokens=150, temperature=0.1)  # Reduced tokens

            # Try to clean and parse the JSON response
            cleaned_response = response.strip()
            if not cleaned_response.startswith('{'):
                # Look for JSON-like content in the response
                import re
                json_match = re.search(r'\{[^{}]*\}', cleaned_response)
                if json_match:
                    cleaned_response = json_match.group(0)
                else:
                    # No valid JSON found, skip this batch
                    console.print(Text("[DEBUG]", style="bold yellow"), f"No valid JSON found in mapping response for batch {i//batch_size + 1}")
                    continue

            batch_mapping = json.loads(cleaned_response)

            # Convert back to threat indices and store
            for j, threat in enumerate(batch_threats):
                threat_id = f"T{i+j+1}"
                if threat_id in batch_mapping:
                    threat_key = f"threat_{i+j}"
                    mapping[threat_key] = batch_mapping[threat_id]

        except json.JSONDecodeError as e:
            console.print(Text("[DEBUG]", style="bold yellow"), f"Failed to parse mapping for batch {i//batch_size + 1}: {e}")
            # Create simple fallback mapping
            for j, threat in enumerate(batch_threats):
                threat_key = f"threat_{i+j}"
                mapping[threat_key] = [f"M{k+1}" for k in range(min(3, len(mitigation_list)))]  # Map to first 3 mitigations

        except Exception as e:
            console.print(Text("[DEBUG]", style="bold yellow"), f"Mapping error for batch {i//batch_size + 1}: {e}")

    return mapping

def _filter_and_rank_mitigations(llm_client, threat_mapping: Dict, all_mitigations: List[Dict]) -> List[Dict]:
    """Filter mitigations to only those mapped to threats and rank by importance"""

    # Get all mitigation IDs that are mapped to threats
    mapped_mitigation_ids = set()
    for threat_id, mitigation_ids in threat_mapping.items():
        mapped_mitigation_ids.update(mitigation_ids)

    # Filter mitigations to only mapped ones
    filtered_mitigations = []
    for mitigation in all_mitigations:
        # Check if this mitigation is in our mapping
        mitigation_name = mitigation.get('name', mitigation.get('control', ''))
        for mapped_id in mapped_mitigation_ids:
            if mapped_id.lower() in mitigation_name.lower() or mitigation_name.lower() in mapped_id.lower():
                # Add mapping metadata
                mitigation['mapped_to_threats'] = True
                mitigation['threat_coverage'] = _count_threat_coverage(mitigation, threat_mapping)
                filtered_mitigations.append(mitigation)
                break

    # If we have too few, add some high-priority ones
    if len(filtered_mitigations) < 10:
        high_priority_mitigations = [m for m in all_mitigations
                                   if m.get('priority', '').lower() in ['critical', 'high']
                                   and m not in filtered_mitigations]
        filtered_mitigations.extend(high_priority_mitigations[:10-len(filtered_mitigations)])

    # Sort by threat coverage (descending) and priority
    filtered_mitigations.sort(key=lambda m: (
        m.get('threat_coverage', 0),
        1 if m.get('priority', '').lower() in ['critical', 'high'] else 0
    ), reverse=True)

    return filtered_mitigations[:30]  # Limit to top 30

def _count_threat_coverage(mitigation: Dict, threat_mapping: Dict) -> int:
    """Count how many threats this mitigation addresses"""
    mitigation_name = mitigation.get('name', mitigation.get('control', '')).lower()
    coverage = 0

    for threat_id, mitigation_ids in threat_mapping.items():
        for mapped_id in mitigation_ids:
            if mapped_id.lower() in mitigation_name or mitigation_name in mapped_id.lower():
                coverage += 1
                break

    return coverage

def _apply_simple_fallback_filter(threats: List[Dict], mitigations: List[Dict], error: str = None) -> Dict[str, Any]:
    """Apply simple rule-based filtering when LLM filter fails"""
    console.print(Text("[DEBUG]", style="bold blue"), "Applying simple fallback filter...")

    # Simple threat deduplication by name
    seen_threats = set()
    filtered_threats = []

    for threat in threats:
        threat_name = threat.get('name', 'Unknown').lower()
        if threat_name not in seen_threats:
            seen_threats.add(threat_name)
            filtered_threats.append(threat)

        # Limit to reasonable number
        if len(filtered_threats) >= 25:
            break

    # Simple mitigation filtering - prioritize by severity/priority
    filtered_mitigations = []
    high_priority_mitigations = [m for m in mitigations if m.get('priority', '').lower() in ['critical', 'high']]
    filtered_mitigations.extend(high_priority_mitigations[:20])

    # Fill remaining with other mitigations if needed
    if len(filtered_mitigations) < 15:
        other_mitigations = [m for m in mitigations if m not in filtered_mitigations]
        filtered_mitigations.extend(other_mitigations[:15-len(filtered_mitigations)])

    console.print(Text("[DEBUG]", style="bold green"), f"Fallback filter: {len(threats)} → {len(filtered_threats)} threats, {len(mitigations)} → {len(filtered_mitigations)} mitigations")

    return {
        'filtered_threats': filtered_threats,
        'filtered_mitigations': filtered_mitigations,
        'threat_mitigation_mapping': {},
        'quality_filter_applied': False,
        'fallback_used': True,
        'original_counts': {
            'threats': len(threats),
            'mitigations': len(mitigations)
        },
        'filtered_counts': {
            'threats': len(filtered_threats),
            'mitigations': len(filtered_mitigations)
        },
        'error': error
    }

def _apply_simple_threat_filter(threats: List[Dict]) -> List[Dict]:
    """INTELLIGENT filter based on probability score instead of arbitrary limits"""
    console.print(Text("[DEBUG]", style="bold blue"), "Filtering threats by probability score...")

    # Group by severity for logging
    critical_threats = [t for t in threats if t.get('severity', '').lower() == 'critical']
    high_threats = [t for t in threats if t.get('severity', '').lower() == 'high']
    medium_threats = [t for t in threats if t.get('severity', '').lower() == 'medium']
    other_threats = [t for t in threats if t.get('severity', '').lower() not in ['critical', 'high', 'medium']]

    # Log original distribution
    console.print(Text("[DEBUG]", style="bold blue"), f"Original threat distribution: {len(critical_threats)} Critical, {len(high_threats)} High, {len(medium_threats)} Medium, {len(other_threats)} Other")

        # INTELLIGENT FILTERING: Use probability_score instead of arbitrary counts
    high_probability = []     # 70-100%: Very likely to be present
    medium_probability = []   # 26-69%: Moderately likely to be present
    low_probability = []      # 0-25%: Very speculative/unlikely

    for threat in threats:
        prob_score = threat.get('probability_score', 50)  # Default to 50% if missing

        # Ensure probability_score is valid
        if isinstance(prob_score, str):
            try:
                prob_score = int(prob_score)
            except:
                prob_score = 50

        if prob_score >= 70:
            high_probability.append(threat)
        elif prob_score >= 26:
            medium_probability.append(threat)
        else:
            low_probability.append(threat)

    # SMART FILTERING: Keep threats based on evidence, not arbitrary limits
    filtered = []

    # Keep ALL high-probability threats (we have evidence they're likely)
    filtered.extend(high_probability)

    # Keep ALL medium-probability threats (no arbitrary limits!)
    filtered.extend(medium_probability)
    if len(medium_probability) > 50:
        console.print(Text("[DEBUG]", style="bold blue"), f"Large number of medium-probability threats: {len(medium_probability)}")

    # Keep ALL low-probability threats up to 30 (more permissive)
    if len(low_probability) <= 30:  # INCREASED from 10 to 30
        filtered.extend(low_probability)  # Keep all if reasonable amount
    else:
        # Keep more low-probability threats - not just critical/high
        important_low_prob = [t for t in low_probability if t.get('severity', '').lower() in ['critical', 'high', 'medium']]  # ADDED medium
        filtered.extend(important_low_prob[:20])  # INCREASED from 10 to 20
        console.print(Text("[DEBUG]", style="bold yellow"), f"Filtered {len(low_probability) - len(important_low_prob[:20])} very speculative threats (<26% probability)")

    console.print(Text("[DEBUG]", style="bold blue"), f"Probability-based filtering: {len(high_probability)} high-prob, {len([t for t in filtered if t in medium_probability])} medium-prob, {len([t for t in filtered if t in low_probability])} low-prob")

    # Remove duplicates by name but preserve variety
    seen_names = set()
    final_filtered = []

    # Process by priority order to keep the most important unique threats
    for threat in filtered:
        name = threat.get('name', 'Unknown').lower().strip()
        # Allow slight variations in names (e.g., "SQL Injection" vs "SQL Injection Attack")
        is_duplicate = any(name in seen_name or seen_name in name for seen_name in seen_names if len(name) > 3 and len(seen_name) > 3)

        if not is_duplicate:
            seen_names.add(name)
            final_filtered.append(threat)
        else:
            # Log what we're considering duplicate
            console.print(Text("[DEBUG]", style="dim"), f"Potential duplicate: '{name}' (already have similar)")

    console.print(Text("[DEBUG]", style="bold green"), f"Pre-filter: {len(threats)} → {len(final_filtered)} threats")
    console.print(Text("[DEBUG]", style="bold blue"), f"Kept: {len([t for t in final_filtered if t.get('severity', '').lower() == 'critical'])} Critical, {len([t for t in final_filtered if t.get('severity', '').lower() == 'high'])} High, {len([t for t in final_filtered if t.get('severity', '').lower() == 'medium'])} Medium")

    return final_filtered


def _assess_threat_applicability_relaxed(llm_client, threats: List[Dict], dfd_model) -> List[Dict]:
    """
    🚀 FAST & RELAXED APPLICABILITY ASSESSMENT - Lower threshold, fewer LLM calls
    """
    console.print(Text("[INFO]", style="bold blue"), f"🚀 Fast applicability assessment for {len(threats)} threats...")

    if not dfd_model or not threats:
        return threats

    # Quick architectural summary (simplified)
    try:
        components = list(dfd_model.components.values()) if hasattr(dfd_model, 'components') else []
        component_names = [getattr(comp, 'name', 'Unknown') for comp in components]

        # Simple tech stack detection
        tech_stack = []
        all_names = ' '.join(component_names).lower()
        if 'api' in all_names or 'rest' in all_names:
            tech_stack.append('API Services')
        if 'database' in all_names or 'db' in all_names:
            tech_stack.append('Database')
        if 'auth' in all_names:
            tech_stack.append('Authentication')
        if 'ai' in all_names or 'llm' in all_names:
            tech_stack.append('AI/ML')

    except:
        # Complete fallback - include all threats
        console.print(Text("[WARN]", style="bold yellow"), "Failed to analyze architecture, including all threats")
        return threats

    # Process in larger batches for speed
    assessed_threats = []
    batch_size = 10  # Larger batches = fewer LLM calls

    for i in range(0, len(threats), batch_size):
        batch_threats = threats[i:i+batch_size]

        # Simplified threat list for faster processing
        threat_names = [t.get('name', 'Unknown') for t in batch_threats]

        # Short and fast prompt
        fast_prompt = f"""Quick threat relevance check for system with: {', '.join(tech_stack[:4])}

Threats: {', '.join(threat_names[:10])}

Rate each threat 0-100% relevance to this system. BE VERY PERMISSIVE - only mark as irrelevant (<5%) if COMPLETELY unrelated to system type (e.g. iOS threats for web system).

Response format: {{"T1": 75, "T2": 20, "T3": 85}}

IMPORTANT: Most threats should score 30-90%. Only score <5% if threat is for completely different platform/technology."""

        try:
            # Faster LLM call with reduced tokens
            response = llm_client.generate_response(fast_prompt, max_tokens=300, temperature=0.0)

            try:
                # Simple JSON parsing
                import re
                json_match = re.search(r'\{[^{}]*\}', response)
                if json_match:
                    scores = json.loads(json_match.group(0))

                    # Apply relaxed scoring (15% threshold instead of 30%)
                    for j, threat in enumerate(batch_threats):
                        threat_id = f"T{j+1}"
                        score = scores.get(threat_id, 50)  # Default 50%

                        threat['applicability_score'] = score
                        threat['applicable'] = score >= 15  # RELAXED THRESHOLD
                        threat['applicability_reasoning'] = f'Fast assessment: {score}% relevance'

                        # Include threats >= 5% (VERY permissive - only remove completely irrelevant)
                        if score >= 5:
                            assessed_threats.append(threat)
                            console.print(Text("[DEBUG]", style="dim green"), f"✅ {threat.get('name', 'Unknown')[:40]}: {score}%")
                        else:
                            console.print(Text("[DEBUG]", style="dim yellow"), f"❌ {threat.get('name', 'Unknown')[:40]}: {score}% - completely irrelevant")

                else:
                    # Fallback: include all in batch
                    for threat in batch_threats:
                        threat['applicability_score'] = 50
                        threat['applicable'] = True
                        assessed_threats.append(threat)

            except:
                # Parsing failed: include all threats in batch
                for threat in batch_threats:
                    threat['applicability_score'] = 50
                    threat['applicable'] = True
                    assessed_threats.append(threat)

        except:
            # LLM call failed: include all threats in batch
            for threat in batch_threats:
                threat['applicability_score'] = 50
                threat['applicable'] = True
                assessed_threats.append(threat)

    console.print(Text("[INFO]", style="bold blue"), f"🚀 Fast assessment: {len(threats)} → {len(assessed_threats)} threats (5% threshold - only remove completely irrelevant)")
    return assessed_threats


def _assess_threat_applicability(llm_client, threats: List[Dict], dfd_model) -> List[Dict]:
    """
    🧠 INTELLIGENT APPLICABILITY ASSESSMENT
    Analyzes each threat against the specific DFD architecture to determine if it's actually applicable
    """
    console.print(Text("[DEBUG]", style="bold blue"), f"🧠 Performing intelligent applicability assessment for {len(threats)} threats...")

    if not dfd_model or not threats:
        console.print(Text("[DEBUG]", style="bold yellow"), "No DFD model or threats to assess")
        return threats

    # Extract architectural context from DFD - fix object access
    try:
        # Access DFD attributes properly (it's a Pydantic model, not a dict)
        components_dict = dfd_model.components if hasattr(dfd_model, 'components') else {}
        connections_list = dfd_model.connections if hasattr(dfd_model, 'connections') else []
        trust_zones_dict = dfd_model.trust_zones if hasattr(dfd_model, 'trust_zones') else {}

        # Convert to lists for processing
        components = list(components_dict.values()) if components_dict else []
        data_flows = connections_list  # connections are the data flows
        trust_boundaries = list(trust_zones_dict.values()) if trust_zones_dict else []
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Failed to extract DFD model attributes: {e}")
        return threats

    # Build architectural summary
    component_types = list(set([getattr(comp, 'component_category', 'Unknown') for comp in components]))
    component_names = [getattr(comp, 'name', 'Unknown') for comp in components]

    # Identify technology stack patterns
    tech_indicators = []
    for comp in components:
        comp_name = getattr(comp, 'name', '').lower()
        comp_type = str(getattr(comp, 'component_category', '')).lower()

        if any(tech in comp_name or tech in comp_type for tech in ['api', 'rest', 'graphql']):
            tech_indicators.append('API/REST Services')
        if any(tech in comp_name or tech in comp_type for tech in ['database', 'db', 'sql', 'mongo']):
            tech_indicators.append('Database Systems')
        if any(tech in comp_name or tech in comp_type for tech in ['auth', 'oauth', 'jwt', 'login']):
            tech_indicators.append('Authentication Systems')
        if any(tech in comp_name or tech in comp_type for tech in ['ai', 'ml', 'llm', 'model']):
            tech_indicators.append('AI/ML Components')
        if any(tech in comp_name or tech in comp_type for tech in ['web', 'ui', 'frontend', 'react', 'vue']):
            tech_indicators.append('Web Frontend')
        if any(tech in comp_name or tech in comp_type for tech in ['load', 'balancer', 'proxy', 'gateway']):
            tech_indicators.append('Load Balancers/Proxies')

    tech_stack = list(set(tech_indicators))

    # Build trust zone summary
    trust_zone_summary = []
    if trust_boundaries:
        trust_zone_summary = [f"Zone {i+1}: {getattr(zone, 'name', 'Unnamed')}" for i, zone in enumerate(trust_boundaries)]

    # Process threats in batches for applicability assessment
    assessed_threats = []
    batch_size = 8  # Increased from 5 to 8 for fewer LLM calls

    for i in range(0, len(threats), batch_size):
        batch_threats = threats[i:i+batch_size]

        # Create detailed threat summaries for assessment
        threat_analysis_list = []
        for j, threat in enumerate(batch_threats):
            threat_analysis_list.append({
                'id': f"T{i+j+1}",
                'name': threat.get('name', 'Unknown'),
                'description': threat.get('description', '')[:100],  # Truncate for speed
                'severity': threat.get('severity', 'Unknown'),
                'target_component': threat.get('target_component', {})
            })

        # OPTIMIZED prompt - shorter and more focused
        assessment_prompt = f"""ARCHITECTURE: {len(components)} components ({', '.join(component_types[:5])})
TECH STACK: {', '.join(tech_stack[:4]) if tech_stack else 'Generic'}

THREATS: {json.dumps(threat_analysis_list)}

Rate each threat's relevance (0-100%) to THIS specific architecture. BE VERY PERMISSIVE:
- 70-100%: Directly applies to identified components
- 30-69%: Generally applies to this system type
- 10-29%: Generic threat but could be relevant
- 0-9%: ONLY if completely irrelevant (e.g. iOS threats for web backend)

IMPORTANT: Most threats should score 30-90%. Only score <10% for completely different platforms.

JSON format: {{"T1": {{"score": 75, "reason": "API endpoints present"}}, "T2": {{"score": 85, "reason": "Database systems detected"}}}}"""

        try:
            console.print(Text("[DEBUG]", style="dim"), f"Assessing batch {i//batch_size + 1}/{(len(threats) + batch_size - 1)//batch_size}")

            # Reduced max_tokens for speed
            response = llm_client.generate_response(assessment_prompt, max_tokens=800, temperature=0.1)

            # Parse LLM assessment response
            try:
                # Clean response to extract JSON
                cleaned_response = response.strip()
                if not cleaned_response.startswith('{'):
                    # Look for JSON block in response
                    import re
                    json_match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
                    if json_match:
                        cleaned_response = json_match.group(0)
                    else:
                        raise ValueError("No JSON found in response")

                assessment_results = json.loads(cleaned_response)

                # Apply assessment results to threats
                for j, threat in enumerate(batch_threats):
                    threat_id = f"T{i+j+1}"
                    if threat_id in assessment_results:
                        assessment = assessment_results[threat_id]

                        # Handle both old and new response formats
                        if isinstance(assessment, dict):
                            score = assessment.get('score', assessment.get('applicability_score', 50))
                            reasoning = assessment.get('reason', assessment.get('reasoning', 'No reasoning'))
                        else:
                            score = assessment  # Simple number format
                            reasoning = 'Score-based assessment'

                        # Add applicability metadata to threat
                        threat['applicability_score'] = score
                        threat['applicable'] = score >= 5  # VERY PERMISSIVE: Only remove completely irrelevant
                        threat['applicability_reasoning'] = reasoning
                        threat['architectural_evidence'] = []

                        # Include threats >= 5% (VERY permissive - only remove completely irrelevant)
                        if score >= 5:
                            assessed_threats.append(threat)
                            console.print(Text("[DEBUG]", style="dim green"), f"✅ {threat.get('name', 'Unknown')[:40]}: {score}%")
                        else:
                            console.print(Text("[DEBUG]", style="dim yellow"), f"❌ {threat.get('name', 'Unknown')[:40]}: {score}% - completely irrelevant")
                    else:
                        # Fallback: include threat with default scoring
                        threat['applicability_score'] = 50
                        threat['applicable'] = True
                        threat['applicability_reasoning'] = 'Assessment failed, using default inclusion'
                        assessed_threats.append(threat)

            except (json.JSONDecodeError, ValueError) as e:
                console.print(Text("[DEBUG]", style="bold yellow"), f"Failed to parse applicability assessment for batch {i//batch_size + 1}: {e}")
                # Fallback: include all threats in batch with default scores
                for threat in batch_threats:
                    threat['applicability_score'] = 50
                    threat['applicable'] = True
                    threat['applicability_reasoning'] = 'Assessment parsing failed, using default inclusion'
                    assessed_threats.append(threat)

        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Critical applicability assessment error for batch {i//batch_size + 1}: {e}")
            # Fallback: include all threats in batch
            for threat in batch_threats:
                threat['applicability_score'] = 50
                threat['applicable'] = True
                threat['applicability_reasoning'] = 'Assessment failed, using default inclusion'
                assessed_threats.append(threat)

    original_count = len(threats)
    filtered_count = len(assessed_threats)

    console.print(Text("[DEBUG]", style="bold blue"), f"🧠 Applicability assessment complete: {original_count} → {filtered_count} threats ({original_count - filtered_count} filtered as <5% relevant)")

    return assessed_threats

def _cleanup_and_validate_threats(threats: List[Dict[str, Any]], dfd_model) -> List[Dict[str, Any]]:
    """
    Clean up and validate all threats to ensure no Unknown values
    """
    cleaned_threats = []

    for threat in threats:
        # Create a copy to avoid modifying original
        clean_threat = threat.copy()

        # 1. FIX SEVERITY: Must not be Unknown
        severity = clean_threat.get('severity', '').strip()
        if not severity or severity.lower() in ['unknown', '', 'none']:
            threat_name = clean_threat.get('name', '')
            clean_threat['severity'] = _infer_severity_from_threat_name(threat_name)
            console.print(Text("[DEBUG]", style="dim yellow"), f"Fixed severity for '{threat_name}': {clean_threat['severity']}")

        # Normalize severity capitalization
        clean_threat['severity'] = clean_threat['severity'].capitalize()

        # 2. FIX COMPONENT: Must not be Unknown
        target_comp = clean_threat.get('target_component')
        component_name = 'Unknown'

        if isinstance(target_comp, dict):
            component_name = target_comp.get('name', 'Unknown')
        elif isinstance(target_comp, str) and target_comp.strip():
            component_name = target_comp.strip()

        # If still Unknown, try to infer from other fields
        if component_name == 'Unknown':
            # Try to extract from source_path
            source_path = clean_threat.get('source_path', '')
            if 'rag_ai' in source_path and dfd_model:
                # Find first AI component
                if hasattr(dfd_model, 'components'):
                    for comp in dfd_model.components.values():
                        if getattr(comp, 'ai_type', None):
                            component_name = comp.name
                            break
            elif 'rag_traditional' in source_path and dfd_model:
                # Find first traditional component
                if hasattr(dfd_model, 'components'):
                    for comp in dfd_model.components.values():
                        if not getattr(comp, 'ai_type', None):
                            component_name = comp.name
                            break

            # Try to infer from threat description/name
            threat_name_lower = clean_threat.get('name', '').lower()
            threat_desc_lower = clean_threat.get('description', '').lower()

            # Component keyword mapping - COMPREHENSIVE LIST
            component_keywords = {
                # === EXISTING COMPONENTS ===
                'FastAPI': ['fastapi', 'api', 'rest', 'endpoint'],
                'LangGraph': ['langgraph', 'llm', 'prompt', 'model'],
                'OpenAI Model': ['openai', 'gpt', 'model'],
                'AWS Aurora': ['aurora', 'database', 'sql', 'db'],
                'AWS ECS': ['ecs', 'container', 'docker'],
                'LangSmith': ['langsmith', 'smith'],
                'Mobile UI': ['mobile', 'ui', 'interface'],
                'AWS Application Load Balancer': ['load balancer', 'alb', 'balancer'],

                # === AWS SERVICES ===
                'AWS EC2': ['ec2', 'elastic compute', 'virtual machine', 'instance'],
                'AWS S3': ['s3', 'simple storage', 'object storage', 'bucket'],
                'AWS RDS': ['rds', 'relational database', 'mysql', 'postgres', 'mariadb'],
                'AWS Lambda': ['lambda', 'serverless', 'function as a service', 'faas'],
                'AWS CloudFront': ['cloudfront', 'cdn', 'content delivery'],
                'AWS API Gateway': ['api gateway', 'gateway', 'api management'],
                'AWS ElastiCache': ['elasticache', 'redis', 'memcached', 'cache'],
                'AWS DynamoDB': ['dynamodb', 'nosql', 'document database'],
                'AWS SQS': ['sqs', 'simple queue', 'message queue'],
                'AWS SNS': ['sns', 'simple notification', 'push notification'],
                'AWS VPC': ['vpc', 'virtual private cloud', 'network'],
                'AWS IAM': ['iam', 'identity access management', 'authentication'],
                'AWS CloudWatch': ['cloudwatch', 'monitoring', 'metrics', 'logs'],
                'AWS EKS': ['eks', 'kubernetes', 'k8s', 'container orchestration'],
                'AWS ELB': ['elb', 'elastic load balancer', 'load balancing'],
                'AWS Route53': ['route53', 'dns', 'domain name'],
                'AWS CloudFormation': ['cloudformation', 'infrastructure as code', 'iac'],
                'AWS Redshift': ['redshift', 'data warehouse', 'analytics'],
                'AWS EMR': ['emr', 'elastic mapreduce', 'big data'],
                'AWS Kinesis': ['kinesis', 'streaming', 'real-time data'],
                'AWS ElasticSearch': ['elasticsearch', 'opensearch', 'search engine'],
                'AWS CodePipeline': ['codepipeline', 'ci/cd', 'deployment pipeline'],
                'AWS Secrets Manager': ['secrets manager', 'secret management', 'credentials'],
                'AWS KMS': ['kms', 'key management', 'encryption keys'],
                'AWS WAF': ['waf', 'web application firewall', 'firewall'],
                'AWS Shield': ['shield', 'ddos protection', 'ddos'],
                'AWS CloudTrail': ['cloudtrail', 'audit', 'activity logs'],
                'AWS Config': ['config', 'compliance', 'configuration management'],

                # === AZURE SERVICES ===
                'Azure VM': ['azure vm', 'virtual machine', 'azure compute'],
                'Azure Storage': ['azure storage', 'blob storage', 'azure blob'],
                'Azure SQL': ['azure sql', 'sql database', 'azure database'],
                'Azure Functions': ['azure functions', 'serverless azure'],
                'Azure CDN': ['azure cdn', 'azure content delivery'],
                'Azure API Management': ['azure api', 'api management azure'],
                'Azure Redis': ['azure redis', 'azure cache'],
                'Azure Cosmos DB': ['cosmos db', 'cosmosdb', 'azure nosql'],
                'Azure Service Bus': ['service bus', 'azure messaging'],
                'Azure Event Hub': ['event hub', 'azure events'],
                'Azure Virtual Network': ['azure vnet', 'virtual network azure'],
                'Azure AD': ['azure ad', 'active directory', 'azure identity'],
                'Azure Monitor': ['azure monitor', 'azure metrics'],
                'Azure AKS': ['aks', 'azure kubernetes'],
                'Azure Load Balancer': ['azure load balancer', 'azure lb'],
                'Azure DNS': ['azure dns'],
                'Azure Resource Manager': ['azure resource manager', 'arm template'],
                'Azure Synapse': ['synapse', 'azure analytics'],
                'Azure Stream Analytics': ['stream analytics', 'azure streaming'],
                'Azure Search': ['azure search', 'cognitive search'],
                'Azure DevOps': ['azure devops', 'azure pipelines'],
                'Azure Key Vault': ['key vault', 'azure secrets'],
                'Azure Firewall': ['azure firewall'],
                'Azure Security Center': ['security center', 'azure security'],

                # === GCP SERVICES ===
                'Google Compute Engine': ['compute engine', 'gce', 'google vm'],
                'Google Cloud Storage': ['cloud storage', 'gcs', 'google storage'],
                'Google Cloud SQL': ['cloud sql', 'google sql'],
                'Google Cloud Functions': ['cloud functions', 'google functions'],
                'Google CDN': ['google cdn', 'cloud cdn'],
                'Google API Gateway': ['google api gateway', 'cloud endpoints'],
                'Google Memorystore': ['memorystore', 'google redis'],
                'Google Firestore': ['firestore', 'google nosql'],
                'Google Pub/Sub': ['pub/sub', 'pubsub', 'google messaging'],
                'Google VPC': ['google vpc', 'cloud vpc'],
                'Google IAM': ['google iam', 'cloud iam'],
                'Google Monitoring': ['google monitoring', 'cloud monitoring'],
                'Google GKE': ['gke', 'google kubernetes'],
                'Google Load Balancer': ['google load balancer', 'cloud load balancer'],
                'Google DNS': ['google dns', 'cloud dns'],
                'Google Deployment Manager': ['deployment manager', 'google iac'],
                'Google BigQuery': ['bigquery', 'google analytics'],
                'Google Dataflow': ['dataflow', 'google streaming'],
                'Google Search': ['google search', 'cloud search'],
                'Google Build': ['cloud build', 'google ci/cd'],
                'Google Secret Manager': ['secret manager google', 'cloud secrets'],
                'Google KMS': ['google kms', 'cloud kms'],
                'Google Armor': ['cloud armor', 'google firewall'],
                'Google Security Center': ['google security', 'cloud security'],

                # === SELF-HOSTED / OPEN SOURCE ===
                'PostgreSQL': ['postgresql', 'postgres', 'pg'],
                'MySQL': ['mysql', 'mariadb'],
                'MongoDB': ['mongodb', 'mongo'],
                'Redis': ['redis', 'in-memory cache'],
                'Nginx': ['nginx', 'web server', 'reverse proxy'],
                'Apache': ['apache', 'httpd'],
                'Docker': ['docker', 'containerization'],
                'Kubernetes': ['kubernetes', 'k8s', 'container orchestration'],
                'Jenkins': ['jenkins', 'ci/cd server'],
                'GitLab': ['gitlab', 'git server'],
                'Elasticsearch': ['elasticsearch', 'elastic', 'search'],
                'Kafka': ['kafka', 'apache kafka', 'message streaming'],
                'RabbitMQ': ['rabbitmq', 'amqp', 'message broker'],
                'Prometheus': ['prometheus', 'monitoring'],
                'Grafana': ['grafana', 'dashboard', 'visualization'],
                'InfluxDB': ['influxdb', 'time series'],
                'Cassandra': ['cassandra', 'distributed database'],
                'CouchDB': ['couchdb', 'document database'],
                'Memcached': ['memcached', 'distributed cache'],
                'HAProxy': ['haproxy', 'load balancer'],
                'Traefik': ['traefik', 'reverse proxy'],
                'Vault': ['vault', 'hashicorp vault', 'secret management'],
                'Consul': ['consul', 'service discovery'],
                'Nomad': ['nomad', 'job scheduler'],
                'Zookeeper': ['zookeeper', 'coordination service'],
                'Spark': ['spark', 'apache spark', 'big data'],
                'Hadoop': ['hadoop', 'distributed computing'],
                'Airflow': ['airflow', 'workflow orchestration'],
                'Superset': ['superset', 'data visualization'],
                'Jupyter': ['jupyter', 'notebook'],
                'MinIO': ['minio', 'object storage'],
                'CockroachDB': ['cockroachdb', 'distributed sql'],
                'ClickHouse': ['clickhouse', 'columnar database'],

                # === FRAMEWORKS & PLATFORMS ===
                'React': ['react', 'react.js', 'frontend framework'],
                'Vue': ['vue', 'vue.js'],
                'Angular': ['angular', 'angularjs'],
                'Django': ['django', 'python web'],
                'Flask': ['flask', 'python api'],
                'Spring': ['spring', 'spring boot', 'java framework'],
                'Express': ['express', 'express.js', 'node.js'],
                'Laravel': ['laravel', 'php framework'],
                'Ruby on Rails': ['rails', 'ruby on rails', 'ror'],
                'ASP.NET': ['asp.net', 'dotnet', '.net'],

                # === DATABASES ===
                'Oracle Database': ['oracle', 'oracle db'],
                'SQL Server': ['sql server', 'mssql', 'microsoft sql'],
                'DB2': ['db2', 'ibm db2'],
                'SAP HANA': ['sap hana', 'hana'],
                'Teradata': ['teradata'],
                'Neo4j': ['neo4j', 'graph database'],
                'ArangoDB': ['arangodb', 'multi-model'],
                'ScyllaDB': ['scylladb', 'nosql'],

                # === MESSAGE QUEUES & STREAMING ===
                'ActiveMQ': ['activemq', 'jms'],
                'Amazon SQS': ['amazon sqs', 'aws sqs'],
                'Azure Service Bus': ['azure service bus'],
                'Google Pub/Sub': ['google pubsub'],
                'NATS': ['nats', 'messaging'],
                'Pulsar': ['pulsar', 'apache pulsar'],

                # === MONITORING & OBSERVABILITY ===
                'New Relic': ['new relic', 'newrelic'],
                'Datadog': ['datadog'],
                'Splunk': ['splunk', 'log analysis'],
                'ELK Stack': ['elk', 'elasticsearch logstash kibana'],
                'Jaeger': ['jaeger', 'tracing'],
                'Zipkin': ['zipkin', 'distributed tracing'],

                # === SECURITY TOOLS ===
                'OWASP ZAP': ['owasp zap', 'zap'],
                'Burp Suite': ['burp suite', 'burp'],
                'Snyk': ['snyk', 'vulnerability scanner'],
                'SonarQube': ['sonarqube', 'code analysis'],
                'Checkmarx': ['checkmarx', 'static analysis'],
                'Veracode': ['veracode', 'security testing'],

                # === GENERIC TERMS ===
                'Database': ['database', 'db', 'data store'],
                'Cache': ['cache', 'caching layer'],
                'Load Balancer': ['load balancer', 'lb', 'balancer'],
                'Web Server': ['web server', 'http server'],
                'API Gateway': ['api gateway', 'gateway'],
                'Message Queue': ['message queue', 'queue'],
                'File Storage': ['file storage', 'storage'],
                'Authentication Service': ['auth service', 'authentication'],
                'Monitoring Service': ['monitoring', 'metrics'],
                'Log Service': ['logging', 'log service'],
                'Backup Service': ['backup', 'backup service'],
                'CDN': ['cdn', 'content delivery network'],
                'DNS': ['dns', 'domain name system'],
                'VPN': ['vpn', 'virtual private network'],
                'Firewall': ['firewall', 'security gateway'],
                'Proxy': ['proxy', 'proxy server'],
                'Search Engine': ['search', 'search engine'],
                'Analytics': ['analytics', 'data analytics'],
                'Machine Learning': ['ml', 'machine learning', 'ai model'],
                'Workflow Engine': ['workflow', 'orchestration'],
                'Notification Service': ['notification', 'alerts'],
                'Identity Provider': ['identity', 'idp', 'sso'],
                'Service Mesh': ['service mesh', 'istio', 'linkerd'],
                'Container Registry': ['registry', 'docker registry'],
                'Code Repository': ['repository', 'repo', 'git'],
                'Configuration Management': ['config', 'configuration'],
                'Secret Management': ['secrets', 'secret store'],
                'Encryption Service': ['encryption', 'crypto'],
                'Compliance Service': ['compliance', 'audit'],
                'Backup Storage': ['backup storage', 'archive'],
                'Event Processing': ['event processing', 'events'],
                'Data Pipeline': ['data pipeline', 'etl'],
                'Stream Processing': ['stream processing', 'real-time'],
                'Batch Processing': ['batch processing', 'batch job'],
                'Scheduler': ['scheduler', 'cron', 'job scheduler'],
                'Health Check': ['health check', 'monitoring probe'],
                'Circuit Breaker': ['circuit breaker', 'fault tolerance'],
                'Rate Limiter': ['rate limiter', 'throttling'],
                'Session Store': ['session', 'session storage'],
                'Feature Flag': ['feature flag', 'toggle'],
                'A/B Testing': ['a/b testing', 'split testing'],
                'Recommendation Engine': ['recommendation', 'recommender'],
                'Chat Service': ['chat', 'messaging'],
                'Video Service': ['video', 'streaming'],
                'Payment Gateway': ['payment', 'payment gateway'],
                'Email Service': ['email', 'smtp'],
                'SMS Service': ['sms', 'text messaging'],
                'Push Notification': ['push notification', 'mobile push'],
                'IoT Platform': ['iot', 'internet of things'],
                'Blockchain': ['blockchain', 'distributed ledger'],
                'Game Engine': ['game engine', 'gaming'],
                'GIS Service': ['gis', 'geographic'],
                'Time Series DB': ['time series', 'timeseries'],
                'Graph Database': ['graph db', 'graph database'],
                'Vector Database': ['vector db', 'embedding'],
                'Content Management': ['cms', 'content management'],
                'E-commerce Platform': ['e-commerce', 'ecommerce'],
                'Social Platform': ['social', 'social network'],
                'Forum': ['forum', 'discussion'],
                'Wiki': ['wiki', 'knowledge base'],
                'Documentation': ['docs', 'documentation'],
                'Help Desk': ['help desk', 'support'],
                'CRM': ['crm', 'customer relationship'],
                'ERP': ['erp', 'enterprise resource'],
                'Business Intelligence': ['bi', 'business intelligence'],
                'Data Warehouse': ['data warehouse', 'dwh'],
                'Data Lake': ['data lake'],
                'Lakehouse': ['lakehouse', 'delta lake'],
            }

            for comp_name, keywords in component_keywords.items():
                if any(kw in threat_name_lower or kw in threat_desc_lower for kw in keywords):
                    component_name = comp_name
                    break

        # Update target_component properly
        if isinstance(target_comp, dict):
            clean_threat['target_component']['name'] = component_name
        else:
            clean_threat['target_component'] = component_name

        console.print(Text("[DEBUG]", style="dim green"), f"Component for '{clean_threat.get('name', 'Unknown')}': {component_name}")

        # 3. FIX PROBABILITY SCORE: Must be numeric
        prob_score = clean_threat.get('probability_score')
        if prob_score is None or prob_score == 'N/A' or not isinstance(prob_score, (int, float)):
            # Assign based on severity
            severity_lower = clean_threat['severity'].lower()
            if severity_lower == 'critical':
                prob_score = 90
            elif severity_lower == 'high':
                prob_score = 75
            elif severity_lower == 'medium':
                prob_score = 60
            elif severity_lower == 'low':
                prob_score = 40
            else:
                prob_score = 50
            clean_threat['probability_score'] = prob_score

        # 4. FIX NAME: Must exist
        if not clean_threat.get('name') or clean_threat.get('name').strip() == '':
            clean_threat['name'] = f"Security Threat in {component_name}"

        # 5. FIX DESCRIPTION: Must exist
        if not clean_threat.get('description') or clean_threat.get('description').strip() == '':
            clean_threat['description'] = f"Security vulnerability affecting {component_name} component"

        cleaned_threats.append(clean_threat)

    console.print(Text("[OK]", style="bold green"), f"Cleaned and validated {len(cleaned_threats)} threats - no Unknown values remaining")
    return cleaned_threats
