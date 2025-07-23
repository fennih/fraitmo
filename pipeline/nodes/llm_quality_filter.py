# LLM Quality Filter Node - Deduplicates threats and creates threat-mitigation mappings

from typing import Dict, Any, List
import json
from rich.console import Console
from rich.text import Text
import re

console = Console()

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

    console.print(Text("[INFO]", style="bold blue"), f"Assigned unique IDs to {len(final_threats)} threats across {len(threats_by_component)} components")

    return final_threats

def llm_quality_filter_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    LLM Quality Filter Node
    Uses LLM as judge to deduplicate threats and create specific threat-mitigation mappings
    """
    # Check if quality filter was already applied
    if state.get('quality_filter_applied', False):
        console.print(Text("[INFO]", style="bold blue"), "LLM Quality Filter: Already applied, skipping duplicate execution")
        return {}  # Return empty dict to avoid duplicating state

    console.print(Text("[INFO]", style="bold blue"), "LLM Quality Filter: Starting deduplication and mapping...")

    try:
        # Import LLM client
        from rag.llm_client import UnifiedLLMClient

        # Get all threats from both paths
        rag_threats = state.get('threats_found', [])
        llm_threats = state.get('llm_threats', [])
        cross_threats = state.get('cross_component_threats', [])
        all_threats = rag_threats + llm_threats + cross_threats

        # Get all mitigations
        rag_mitigations = state.get('rag_mitigations', [])
        llm_mitigations = state.get('llm_mitigations', [])
        all_mitigations = rag_mitigations + llm_mitigations

        console.print(Text("[INFO]", style="bold blue"), f"Processing {len(all_threats)} threats and {len(all_mitigations)} mitigations...")

        # Initialize LLM client
        llm_client = UnifiedLLMClient()
        if not llm_client.active_model:
            console.print(Text("[WARN]", style="bold yellow"), "No LLM available for quality filtering")
            return _apply_simple_fallback_filter(all_threats, all_mitigations)

        # If we have too many threats, apply pre-filtering
        if len(all_threats) > 50:
            console.print(Text("[WARN]", style="bold yellow"), f"Too many threats ({len(all_threats)}), applying pre-filter...")
            all_threats = _apply_simple_threat_filter(all_threats)

        # Step 1: Deduplicate threats using LLM
        deduplicated_threats = _deduplicate_threats_with_llm(llm_client, all_threats)

        # Step 2: Assign unique IDs and sort by component/severity
        organized_threats = _assign_threat_ids_and_sort(deduplicated_threats)

        # Step 3: Create threat-mitigation mappings
        threat_mitigation_mapping = _create_threat_mitigation_mapping(llm_client, organized_threats, all_mitigations)

        # Step 4: Filter and rank mitigations
        filtered_mitigations = _filter_and_rank_mitigations(llm_client, threat_mitigation_mapping, all_mitigations)

        console.print(Text("[OK]", style="bold green"), f"Quality filter complete: {len(organized_threats)} unique threats, {len(filtered_mitigations)} relevant mitigations")

        return {
            'filtered_threats': organized_threats,
            'filtered_mitigations': filtered_mitigations,
            'threat_mitigation_mapping': threat_mitigation_mapping,
            'quality_filter_applied': True,
            'original_counts': {
                'threats': len(rag_threats + llm_threats + cross_threats),
                'mitigations': len(all_mitigations)
            },
            'filtered_counts': {
                'threats': len(organized_threats),
                'mitigations': len(filtered_mitigations)
            }
        }

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Quality filter failed: {e}")
        # Use fallback filter
        fallback_threats = state.get('threats_found', []) + state.get('llm_threats', []) + state.get('cross_component_threats', [])
        fallback_mitigations = state.get('rag_mitigations', []) + state.get('llm_mitigations', [])
        return _apply_simple_fallback_filter(fallback_threats, fallback_mitigations, error=str(e))

def _deduplicate_threats_with_llm(llm_client, threats: List[Dict]) -> List[Dict]:
    """Use LLM to identify and remove duplicate threats"""

    if len(threats) <= 10:
        return threats  # No need to deduplicate small lists

    console.print(Text("[INFO]", style="bold blue"), f"LLM deduplicating {len(threats)} threats...")

    # Group threats by component for more efficient processing
    threats_by_component = {}
    for threat in threats:
        # Handle different target_component formats
        target_comp = threat.get('target_component', {})
        if isinstance(target_comp, dict):
            component = target_comp.get('name', 'unknown')
        elif isinstance(target_comp, str):
            component = target_comp
        else:
            component = 'unknown'

        if component not in threats_by_component:
            threats_by_component[component] = []
        threats_by_component[component].append(threat)

    deduplicated = []

    for component, component_threats in threats_by_component.items():
        if len(component_threats) <= 3:
            # Keep all threats if only a few
            deduplicated.extend(component_threats)
            continue

        # Create threat summary for LLM (keep it compact to avoid context overflow)
        threat_summaries = []
        for i, threat in enumerate(component_threats[:15]):  # Limit to 15 threats per component
            summary = {
                'index': i,
                'name': threat.get('name', 'Unknown')[:50],  # Limit name length
                'severity': threat.get('severity', 'Unknown'),
                'category': threat.get('category', 'Unknown'),
                'description': threat.get('description', '')[:80] + '...' if len(threat.get('description', '')) > 80 else threat.get('description', '')  # Shorter description
            }
            threat_summaries.append(summary)

        # Compact LLM deduplication prompt
        dedup_prompt = f"""Remove duplicate threats for "{component}". Return JSON only.

THREATS: {json.dumps(threat_summaries)}

Remove duplicates with same vulnerability type. Return indices of unique threats only.
Format: {{"unique_indices": [0, 2, 4]}}"""

        try:
            response = llm_client.generate_response(dedup_prompt, max_tokens=100, temperature=0.1)  # Reduced tokens

            # Parse LLM response
            try:
                parsed = json.loads(response)
                unique_indices = parsed.get('unique_indices', [])

                # Validate indices
                valid_indices = [i for i in unique_indices if 0 <= i < len(component_threats)]

                if valid_indices:
                    # Add selected unique threats
                    for idx in valid_indices:
                        deduplicated.append(component_threats[idx])
                else:
                    # Fallback: take first 3 threats
                    deduplicated.extend(component_threats[:3])

                console.print(Text("[OK]", style="bold green"), f"Component {component}: {len(component_threats)} → {len(valid_indices)} threats")

            except json.JSONDecodeError:
                # Fallback: take first 3 threats
                deduplicated.extend(component_threats[:3])
                console.print(Text("[WARN]", style="bold yellow"), f"LLM dedup failed for {component}, using fallback")

        except Exception as e:
            # Fallback: take first 3 threats
            deduplicated.extend(component_threats[:3])
            console.print(Text("[WARN]", style="bold yellow"), f"LLM dedup error for {component}: {e}")

    return deduplicated

def _create_threat_mitigation_mapping(llm_client, threats: List[Dict], mitigations: List[Dict]) -> Dict[str, List[str]]:
    """Create explicit threat → mitigation mappings using LLM"""

    console.print(Text("[INFO]", style="bold blue"), f"Creating threat-mitigation mappings...")

    mapping = {}

    # Process threats in smaller batches to avoid context overflow
    batch_size = 3  # Reduced from 5 to 3
    for i in range(0, min(len(threats), 20), batch_size):  # Limit total threats to 20
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
                    console.print(Text("[WARN]", style="bold yellow"), f"No valid JSON found in mapping response for batch {i//batch_size + 1}")
                    continue

            batch_mapping = json.loads(cleaned_response)

            # Convert back to threat indices and store
            for j, threat in enumerate(batch_threats):
                threat_id = f"T{i+j+1}"
                if threat_id in batch_mapping:
                    threat_key = f"threat_{i+j}"
                    mapping[threat_key] = batch_mapping[threat_id]

        except json.JSONDecodeError as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Failed to parse mapping for batch {i//batch_size + 1}: {e}")
            # Create simple fallback mapping
            for j, threat in enumerate(batch_threats):
                threat_key = f"threat_{i+j}"
                mapping[threat_key] = [f"M{k+1}" for k in range(min(3, len(mitigation_list)))]  # Map to first 3 mitigations

        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Mapping error for batch {i//batch_size + 1}: {e}")

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
    console.print(Text("[INFO]", style="bold blue"), "Applying simple fallback filter...")

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

    console.print(Text("[OK]", style="bold green"), f"Fallback filter: {len(threats)} → {len(filtered_threats)} threats, {len(mitigations)} → {len(filtered_mitigations)} mitigations")

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
    """Pre-filter threats to reduce context size while preserving important ones"""
    console.print(Text("[INFO]", style="bold blue"), "Pre-filtering threats...")

    # Group by severity and prioritize
    critical_threats = [t for t in threats if t.get('severity', '').lower() == 'critical']
    high_threats = [t for t in threats if t.get('severity', '').lower() == 'high']
    medium_threats = [t for t in threats if t.get('severity', '').lower() == 'medium']
    other_threats = [t for t in threats if t.get('severity', '').lower() not in ['critical', 'high', 'medium']]

    # Log what we found before filtering
    console.print(Text("[INFO]", style="bold blue"), f"Original threat distribution: {len(critical_threats)} Critical, {len(high_threats)} High, {len(medium_threats)} Medium, {len(other_threats)} Other")

    # More generous pre-filtering - keep more important threats
    filtered = []
    filtered.extend(critical_threats)  # Keep ALL critical threats
    filtered.extend(high_threats[:20])  # Increased from 15 to 20 high threats
    filtered.extend(medium_threats[:15])  # Increased from 10 to 15 medium threats
    filtered.extend(other_threats[:10])  # Increased from 5 to 10 others

    # Log what we're keeping vs removing
    if len(high_threats) > 20:
        console.print(Text("[WARN]", style="bold yellow"), f"Trimmed {len(high_threats) - 20} high severity threats to fit context")
    if len(medium_threats) > 15:
        console.print(Text("[WARN]", style="bold yellow"), f"Trimmed {len(medium_threats) - 15} medium severity threats to fit context")

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

    console.print(Text("[OK]", style="bold green"), f"Pre-filter: {len(threats)} → {len(final_filtered)} threats")
    console.print(Text("[INFO]", style="bold blue"), f"Kept: {len([t for t in final_filtered if t.get('severity', '').lower() == 'critical'])} Critical, {len([t for t in final_filtered if t.get('severity', '').lower() == 'high'])} High, {len([t for t in final_filtered if t.get('severity', '').lower() == 'medium'])} Medium")

    return final_filtered
