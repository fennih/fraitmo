#!/usr/bin/env python3
"""
Export FRAITMO Results - Save threat analysis results to JSON/CSV
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, Any, List

def export_threats_to_json(result: Dict[str, Any], output_dir: str = "results") -> str:
    """Export all threats to JSON file"""

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Use export-ready threats with [LOW PROB] flags if available
    if result.get('all_threats_for_export'):
        all_threats = result.get('all_threats_for_export', [])
    elif result.get('quality_filter_applied', False):
        all_threats = result.get('filtered_threats', [])
    else:
        # Fallback to original combined threats
        all_threats = result.get('threats_found', []) + result.get('llm_threats', [])
        # Add cross-component threats to the export
        cross_component_threats = result.get('cross_component_threats', [])
        all_threats.extend(cross_component_threats)

    # Get mitigations
    all_mitigations = result.get('filtered_mitigations', [])
    if not all_mitigations:
        all_mitigations = result.get('rag_mitigations', []) + result.get('llm_mitigations', [])

    threat_mitigation_mapping = result.get('threat_mitigation_mapping', {})

    # Add progressive numbering to threats
    for i, threat in enumerate(all_threats, 1):
        threat['threat_number'] = i
        # Improve threat names to be more descriptive
        threat['name'] = _improve_threat_name(threat)

    # Categorize threats by type for better organization
    threat_categories = {
        'component_threats': [t for t in all_threats if t.get('threat_type') not in ['cross_component', 'ai_integration', 'external_dependency', 'authentication_flow']],
        'cross_component_threats': [t for t in all_threats if t.get('threat_type') == 'cross_component'],
        'ai_integration_threats': [t for t in all_threats if t.get('threat_type') == 'ai_integration'],
        'external_dependency_threats': [t for t in all_threats if t.get('threat_type') == 'external_dependency'],
        'authentication_flow_threats': [t for t in all_threats if t.get('threat_type') == 'authentication_flow']
    }

    # Create comprehensive export data
    export_data = {
        "analysis_metadata": {
            "timestamp": datetime.now().isoformat(),
            "status": result.get('processing_status', 'unknown'),
            "total_components": len(result.get('ai_components', [])) + len(result.get('traditional_components', [])),
            "ai_components": len(result.get('ai_components', [])),
            "traditional_components": len(result.get('traditional_components', [])),
            "quality_filter_applied": result.get('quality_filter_applied', False),
            "original_counts": result.get('original_counts', {}),
            "filtered_counts": result.get('filtered_counts', {}),
            "errors": len(result.get('errors', [])),
            "warnings": len(result.get('warnings', [])),
            "overall_risk": result.get('overall_risk', 'Unknown'),
            "trust_boundary_count": result.get('trust_boundary_count', 0),
            "data_flow_count": result.get('data_flow_count', 0)
        },
        "threats": {
            "total_count": len(all_threats),
            "by_category": {
                "component_threats": len(threat_categories['component_threats']),
                "cross_component_threats": len(threat_categories['cross_component_threats']),
                "ai_integration_threats": len(threat_categories['ai_integration_threats']),
                "external_dependency_threats": len(threat_categories['external_dependency_threats']),
                "authentication_flow_threats": len(threat_categories['authentication_flow_threats'])
            },
            "rag_threats": len(result.get('threats_found', [])),
            "llm_threats": len(result.get('llm_threats', [])),
            "cross_component_threats": len(cross_component_threats),
            "ai_specific": len(result.get('ai_threats', [])),
            "traditional": len(result.get('traditional_threats', [])),
            "details": all_threats
        },
        "threat_categories": threat_categories,
        "mitigations": {
            "total_count": len(all_mitigations),
            "filtered_mitigations": all_mitigations,
            "rag_mitigations": result.get('rag_mitigations', []),
            "llm_mitigations": result.get('llm_mitigations', [])
        },
        "threat_mitigation_mapping": threat_mitigation_mapping,
        "components": {
            "ai_components": result.get('ai_components', []),
            "traditional_components": result.get('traditional_components', [])
        },
        "risk_assessment": result.get('risk_assessment', {}),
        "implementation_plans": {
            "rag_plan": result.get('rag_implementation_plan', {}),
            "llm_plan": result.get('llm_implementation_plan', {})
        }
    }

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/fraitmo_analysis_{timestamp}.json"

    # Save to JSON
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    return filename

def _improve_threat_name(threat: Dict[str, Any]) -> str:
    """Generate a descriptive, specific threat name from the threat data"""

    original_name = threat.get('name', 'Unknown Threat')
    description = threat.get('description', '')
    threat_type = threat.get('threat_type', 'component')
    target_component = threat.get('target_component', 'Unknown')

    # If the name is already specific and descriptive, keep it
    generic_names = [
        'authentication threat', 'authorization threat', 'data integrity threat',
        'encryption threat', 'network threat', 'access control threat',
        'privilege escalation', 'sql injection', 'xss', 'csrf', 'prompt injection'
    ]

    if original_name.lower() not in [name.lower() for name in generic_names]:
        # Name is already specific, just clean it up
        return _clean_threat_name(original_name)

    # Generate more specific name based on context
    if threat_type == 'cross_component':
        source_comp = threat.get('source_component', '').split('(')[0].strip()
        target_comp = threat.get('target_component', '').split('(')[0].strip()

        if 'authentication' in original_name.lower():
            return f"Weak Authentication Between {source_comp} and {target_comp}"
        elif 'authorization' in original_name.lower():
            return f"Insufficient Authorization Controls {source_comp}→{target_comp}"
        elif 'data integrity' in original_name.lower():
            return f"Data Corruption Risk in {source_comp}→{target_comp} Transit"
        elif 'encryption' in original_name.lower():
            return f"Unencrypted Data Flow {source_comp}→{target_comp}"
        else:
            return f"Trust Boundary Violation {source_comp}→{target_comp}"

    elif threat_type == 'ai_integration':
        ai_comp = threat.get('ai_component', '').split('(')[0].strip()
        trad_comp = threat.get('traditional_component', '').split('(')[0].strip()

        if 'prompt injection' in original_name.lower():
            return f"Prompt Injection via {trad_comp} to {ai_comp}"
        elif 'model extraction' in original_name.lower():
            return f"AI Model Extraction Through {trad_comp} Interface"
        elif 'data leakage' in original_name.lower():
            return f"AI Data Leakage Between {ai_comp} and {trad_comp}"
        else:
            return f"AI-Traditional Integration Risk ({ai_comp}↔{trad_comp})"

    elif threat_type == 'external_dependency':
        external_services = threat.get('external_services', [])
        if external_services:
            service_name = external_services[0].split('(')[0].strip()
            if 'service unavailability' in original_name.lower():
                return f"{service_name} Service Outage Risk"
            elif 'vendor lock' in original_name.lower():
                return f"{service_name} Vendor Lock-in Dependency"
            else:
                return f"External {service_name} Dependency Risk"

    # For component-specific threats, make them more specific
    if isinstance(target_component, str) and target_component != 'Unknown':
        comp_short = target_component.split('(')[0].strip()

        if 'sql injection' in original_name.lower():
            return f"SQL Injection Attack on {comp_short}"
        elif 'xss' in original_name.lower() or 'cross-site scripting' in original_name.lower():
            return f"Cross-Site Scripting in {comp_short}"
        elif 'prompt injection' in original_name.lower():
            return f"Prompt Injection Attack Against {comp_short}"
        elif 'privilege escalation' in original_name.lower():
            return f"Privilege Escalation via {comp_short}"
        elif 'model extraction' in original_name.lower():
            return f"AI Model Extraction from {comp_short}"

    # Fallback: extract key words from description if available
    if description and len(description) > 20:
        # Extract first meaningful phrase from description
        desc_words = description.split()[:8]  # First 8 words
        if len(desc_words) >= 3:
            return ' '.join(desc_words).rstrip('.,;:')

    # Last fallback: clean up original name
    return _clean_threat_name(original_name)

def _clean_threat_name(name: str) -> str:
    """Clean and standardize threat name"""
    if not name or name == 'Unknown Threat':
        return 'Unspecified Security Threat'

    # Capitalize first letter of each word, handle common abbreviations
    words = name.split()
    cleaned_words = []

    for word in words:
        word_lower = word.lower()
        if word_lower in ['ai', 'llm', 'api', 'ui', 'sql', 'xss', 'csrf', 'aws', 'dos', 'ddos']:
            cleaned_words.append(word.upper())
        elif word_lower in ['oauth', 'saml', 'jwt']:
            cleaned_words.append(word_lower.upper())
        else:
            cleaned_words.append(word.capitalize())

    return ' '.join(cleaned_words)

def export_threats_to_csv(result: Dict[str, Any], output_dir: str = "results") -> str:
    """Export threats to CSV file for easy analysis"""

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Use export-ready threats with [LOW PROB] flags if available
    if result.get('all_threats_for_export'):
        all_threats = result.get('all_threats_for_export', [])
    elif result.get('quality_filter_applied', False):
        all_threats = result.get('filtered_threats', [])
    else:
        # Fallback to original combined threats
        all_threats = result.get('threats_found', []) + result.get('llm_threats', [])

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/fraitmo_threats_{timestamp}.csv"

    # Define CSV headers
    headers = [
        'threat_id', 'name', 'severity', 'likelihood', 'impact',
        'description', 'target_component', 'component_type',
        'ai_specific', 'source', 'category', 'mitigation_available', 'low_probability'
    ]

    # Write CSV file
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)

        for i, threat in enumerate(all_threats):
            # Handle nested target_component
            target_component = threat.get('target_component', {})
            if isinstance(target_component, dict):
                target_name = target_component.get('name', 'Unknown')
                component_type = target_component.get('type', 'Unknown')
            else:
                target_name = str(target_component)
                component_type = 'Unknown'

            row = [
                threat.get('id', f'THREAT_{i+1}'),
                threat.get('name', 'Unknown Threat'),
                threat.get('severity', 'Unknown'),
                threat.get('likelihood', 'Unknown'),
                threat.get('impact', 'Unknown'),
                threat.get('description', '')[:200] + '...' if len(threat.get('description', '')) > 200 else threat.get('description', ''),
                target_name,
                component_type,
                threat.get('ai_specific', False),
                threat.get('source', 'Unknown'),
                threat.get('category', 'Unknown'),
                len(threat.get('mitigations', [])) > 0,
                threat.get('low_probability_threat', False)
            ]
            writer.writerow(row)

    return filename

def export_full_report(result: Dict[str, Any], output_dir: str = "results") -> Dict[str, str]:
    """Export complete analysis report in multiple formats"""

    files_created = {}

    # Export JSON
    json_file = export_threats_to_json(result, output_dir)
    files_created['json'] = json_file

    # Export CSV
    csv_file = export_threats_to_csv(result, output_dir)
    files_created['csv'] = csv_file

    # Create summary report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_file = f"{output_dir}/fraitmo_summary_{timestamp}.txt"

    all_threats = result.get('threats_found', []) + result.get('llm_threats', [])
    all_mitigations = result.get('rag_mitigations', []) + result.get('llm_mitigations', [])

    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("FRAITMO THREAT ANALYSIS SUMMARY\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Status: {result.get('processing_status', 'Unknown')}\n\n")

        f.write("COMPONENT SUMMARY:\n")
        f.write(f"AI Components: {len(result.get('ai_components', []))}\n")
        f.write(f"Traditional Components: {len(result.get('traditional_components', []))}\n")
        f.write(f"Total Components: {len(result.get('ai_components', [])) + len(result.get('traditional_components', []))}\n\n")

        f.write("THREAT SUMMARY:\n")
        f.write(f"Total Threats: {len(all_threats)}\n")
        if result.get('displayed_threats_count') is not None:
            f.write(f"Displayed Threats: {result.get('displayed_threats_count', 0)}\n")
            f.write(f"Hidden Low-Probability Threats: {result.get('hidden_threats_count', 0)}\n")
        f.write(f"RAG Path Threats: {len(result.get('threats_found', []))}\n")
        f.write(f"LLM Path Threats: {len(result.get('llm_threats', []))}\n")
        f.write(f"AI-Specific Threats: {len(result.get('ai_threats', []))}\n")
        f.write(f"Traditional Threats: {len(result.get('traditional_threats', []))}\n\n")

        f.write("MITIGATION SUMMARY:\n")
        f.write(f"Total Mitigations: {len(all_mitigations)}\n")
        f.write(f"RAG Mitigations: {len(result.get('rag_mitigations', []))}\n")
        f.write(f"LLM Mitigations: {len(result.get('llm_mitigations', []))}\n\n")

        # Error/Warning summary
        errors = result.get('errors', [])
        warnings = result.get('warnings', [])
        if errors or warnings:
            f.write("ISSUES:\n")
            f.write(f"Errors: {len(errors)}\n")
            f.write(f"Warnings: {len(warnings)}\n\n")

    files_created['summary'] = summary_file

    return files_created

if __name__ == "__main__":
    print("FRAITMO Results Exporter")
    print("This module provides functions to export threat analysis results to JSON/CSV")
    print("Use: export_full_report(analysis_result)")
