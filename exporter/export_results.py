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

    # Combine all threats from both paths
    all_threats = result.get('threats_found', []) + result.get('llm_threats', [])

    # Create comprehensive export data
    export_data = {
        "analysis_metadata": {
            "timestamp": datetime.now().isoformat(),
            "status": result.get('processing_status', 'unknown'),
            "total_components": len(result.get('ai_components', [])) + len(result.get('traditional_components', [])),
            "ai_components": len(result.get('ai_components', [])),
            "traditional_components": len(result.get('traditional_components', [])),
            "errors": len(result.get('errors', [])),
            "warnings": len(result.get('warnings', []))
        },
        "threats": {
            "total_count": len(all_threats),
            "rag_threats": len(result.get('threats_found', [])),
            "llm_threats": len(result.get('llm_threats', [])),
            "ai_specific": len(result.get('ai_threats', [])),
            "traditional": len(result.get('traditional_threats', [])),
            "details": all_threats
        },
        "mitigations": {
            "total_count": len(result.get('rag_mitigations', [])) + len(result.get('llm_mitigations', [])),
            "rag_mitigations": result.get('rag_mitigations', []),
            "llm_mitigations": result.get('llm_mitigations', [])
        },
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

def export_threats_to_csv(result: Dict[str, Any], output_dir: str = "results") -> str:
    """Export threats to CSV file for easy analysis"""

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Combine all threats from both paths
    all_threats = result.get('threats_found', []) + result.get('llm_threats', [])

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/fraitmo_threats_{timestamp}.csv"

    # Define CSV headers
    headers = [
        'threat_id', 'name', 'severity', 'likelihood', 'impact',
        'description', 'target_component', 'component_type',
        'ai_specific', 'source', 'category', 'mitigation_available'
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
                len(threat.get('mitigations', [])) > 0
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
