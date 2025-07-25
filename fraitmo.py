#!/usr/bin/env python3
"""
FRAITMO - Framework for Robust AI Threat Modeling Operations
Main entry point for threat analysis pipeline
"""

import os
import sys
import argparse
import json
import csv
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv
from rich.console import Console
from rich.text import Text

# Add the project root to Python path for imports
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import the complete pipeline
from pipeline.graph import run_fraitmo_analysis
from exporter.export_results import export_threats_to_json, export_threats_to_csv  # Export functions


def format_components_summary(console: Console, ai_components, traditional_components):
    """Format component classification summary"""
    console.print(Text("[INFO]", style="bold blue"), "COMPONENT CLASSIFICATION:")
    console.print(Text("[INFO]", style="bold blue"), f"AI Components: {len(ai_components)}")
    for comp in ai_components:
        name = comp.get('name', 'Unknown')
        # Remove everything in parentheses
        clean_name = name.split('(')[0].strip()
        console.print(f"  - {clean_name}")

    console.print(Text("[INFO]", style="bold blue"), f"Traditional Components: {len(traditional_components)}")
    for comp in traditional_components:
        name = comp.get('name', 'Unknown')
        # Remove everything in parentheses
        clean_name = name.split('(')[0].strip()
        console.print(f"  - {clean_name}")


def format_threat_summary(console: Console, threats_found, ai_threats, traditional_threats):
    """Format threat identification summary"""
    console.print(Text("[INFO]", style="bold blue"), "THREAT IDENTIFICATION:")
    console.print(Text("[INFO]", style="bold blue"), f"Total Threats Found: {len(threats_found)}")
    console.print(Text("[INFO]", style="bold blue"), f"AI-Specific Threats: {len(ai_threats)}")
    console.print(Text("[INFO]", style="bold blue"), f"Traditional Threats: {len(traditional_threats)}")

    if threats_found:
        console.print("All Threats Found:")
        for i, threat in enumerate(threats_found, 1):
            console.print(f"  {i}. {threat.get('name', 'Unknown Threat')}")
            console.print(f"     Severity: {threat.get('severity', 'Unknown')}")

            # Handle target_component - can be string or dict
            target_component = threat.get('target_component', 'Unknown')
            if isinstance(target_component, dict):
                target_name = target_component.get('name', 'Unknown')
            else:
                target_name = str(target_component)
            console.print(f"     Target: {target_name}")

            # Add description for more context
            description = threat.get('description', '')
            if description:
                # Truncate long descriptions
                short_desc = description[:100] + '...' if len(description) > 100 else description
                console.print(f"     Description: {short_desc}")
            console.print()  # Empty line between threats


def format_mitigation_summary(console: Console, mitigations, implementation_plan):
    """Format mitigation proposal summary"""
    console.print(Text("[INFO]", style="bold blue"), "MITIGATION PROPOSAL:")
    console.print(Text("[INFO]", style="bold blue"), f"Total Mitigations: {len(mitigations)}")

    if mitigations:
        console.print("Priority Mitigations:")
        for i, mitigation in enumerate(mitigations[:5], 1):
            console.print(f"  {i}. {mitigation.get('name', 'Unknown Mitigation')}")
            console.print(f"     Effectiveness: {mitigation.get('effectiveness', 'Unknown')}")
            console.print(f"     Implementation: {mitigation.get('implementation_time', 'Unknown')}")
            console.print(f"     Cost: {mitigation.get('cost', 'Unknown')}")

    if implementation_plan:
        console.print("Implementation Plan:")
        console.print(f"  Total Tasks: {implementation_plan.get('total_tasks', 0)}")
        console.print(f"  Critical Tasks: {implementation_plan.get('critical_tasks', 0)}")
        console.print(f"  Estimated Completion: {implementation_plan.get('estimated_completion', 'Unknown')}")


def format_llm_analysis(console: Console, threat_analysis, risk_assessment):
    """Format LLM analysis results"""
    console.print(Text("[INFO]", style="bold blue"), "LLM ANALYSIS:")
    console.print(Text("[INFO]", style="bold blue"), f"Overall Risk: {risk_assessment.get('overall_risk', 'Unknown')}")
    console.print(Text("[INFO]", style="bold blue"), f"Model Used: {threat_analysis.get('model_used', 'Unknown')}")

    breakdown = risk_assessment.get('threat_breakdown', {})
    if breakdown:
        console.print("Threat Breakdown:")
        for level, count in breakdown.items():
            if count > 0:
                console.print(f"  {level.title()}: {count}")

    llm_response = threat_analysis.get('llm_response', '')
    if llm_response:
        console.print("LLM Analysis Summary:")
        # Display first 500 characters of LLM response
        summary = llm_response[:500]
        if len(llm_response) > 500:
            summary += "..."
        console.print(f"  {summary}")


def format_direct_analysis_summary(console: Console, result: Dict[str, Any]):
    """Format direct LLM analysis summary"""
    console.print(Text("[INFO]", style="bold blue"), "DIRECT LLM ANALYSIS SUMMARY:")

    direct_summary = result.get('direct_analysis_summary', {})
    direct_threats = result.get('direct_threats', [])
    direct_mitigations = result.get('direct_mitigations_kb', [])

    console.print(Text("[INFO]", style="bold blue"), f"Direct Threats Found: {len(direct_threats)}")
    console.print(Text("[INFO]", style="bold blue"), f"Direct Mitigations Generated: {len(direct_mitigations)}")

    if direct_summary:
        ai_threats = direct_summary.get('ai_specific_threats', 0)
        traditional_threats = direct_summary.get('traditional_threats', 0)
        console.print(Text("[INFO]", style="bold blue"), f"AI-Specific Threats: {ai_threats}")
        console.print(Text("[INFO]", style="bold blue"), f"Traditional Threats: {traditional_threats}")

    # Show mitigation summary
    mitigation_summary = result.get('direct_mitigation_summary', {})
    if mitigation_summary:
        console.print(Text("[INFO]", style="bold blue"), f"Estimated Timeline: {mitigation_summary.get('estimated_timeline', 'Unknown')}")

        priority_breakdown = mitigation_summary.get('by_priority', {})
        if priority_breakdown:
            console.print("Mitigations by Priority:")
            for priority, count in priority_breakdown.items():
                if count > 0:
                    console.print(f"  - {priority}: {count}")


def display_results(result: Dict[str, Any]):
    """Display comprehensive analysis results"""
    console = Console()

    console.print("=" * 80)
    console.print(Text("[OK]", style="bold green"), "FRAITMO THREAT ANALYSIS RESULTS")
    console.print("=" * 80)

    # Component classification
    format_components_summary(
        console,
        result.get('ai_components', []),
        result.get('traditional_components', [])
    )

    # Threat identification (combined from both paths)
    all_threats = result.get('threats_found', []) + result.get('llm_threats', [])
    format_threat_summary(
        console,
        all_threats,
        result.get('ai_threats', []),
        result.get('traditional_threats', [])
    )

    # LLM analysis
    format_llm_analysis(
        console,
        result.get('threat_analysis', {}),
        result.get('risk_assessment', {})
    )

    # Mitigation proposal (combined from both paths) - only if mitigations were generated
    all_mitigations = result.get('rag_mitigations', []) + result.get('llm_mitigations', [])
    if all_mitigations:
        format_mitigation_summary(
            console,
            all_mitigations,
            result.get('rag_implementation_plan', {}) or result.get('llm_implementation_plan', {})
        )
    else:
        console.print(Text("[INFO]", style="bold blue"), "MITIGATION PROPOSAL:")
        console.print(Text("[INFO]", style="dim"), "Mitigation generation skipped (use --mitigation flag to enable)")

    # Direct LLM Analysis Summary
    if result.get('direct_threats') or result.get('direct_mitigations_kb'):
        format_direct_analysis_summary(console, result)

    # Processing status
    console.print(Text("[INFO]", style="bold blue"), "PROCESSING STATUS:")
    console.print(f"Status: {result.get('processing_status', 'Unknown')}")

    if result.get('errors'):
        console.print(Text("[ERROR]", style="bold red"), f"Errors: {len(result.get('errors', []))}")
        for error in result.get('errors', []):
            console.print(f"  - {error}")

    if result.get('warnings'):
        console.print(Text("[WARN]", style="bold yellow"), f"Warnings: {len(result.get('warnings', []))}")
        for warning in result.get('warnings', []):
            console.print(f"  - {warning}")


def main():
    """Main entry point for FRAITMO analysis"""
    # Load environment variables
    load_dotenv()

    # Initialize rich console for styled output
    console = Console()

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='FRAITMO - Framework for Robust AI Threat Modeling Operations',
        epilog="""
Examples:
  # Full threat modeling (threats + mitigations)
  python fraitmo.py dfd.xml --full-threat-modeling

  # Threats only (faster)
  python fraitmo.py dfd.xml --threats

  # Generate mitigations from existing threats
  python fraitmo.py --mitigation threats.json
  python fraitmo.py --mitigation threats.csv

  # Export to different formats
  python fraitmo.py dfd.xml --threats --format json --output-dir ./results
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Main input: DFD file or mitigation mode
    parser.add_argument('input_file', nargs='?',
                       help='Path to DFD XML file or threats JSON/CSV file (for --mitigation mode)')

    # Analysis mode (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--full-threat-modeling', action='store_true',
                           help='Complete analysis: threats + mitigations (default behavior)')
    mode_group.add_argument('--threats', action='store_true',
                           help='Threats only (faster, skip mitigation generation)')
    mode_group.add_argument('--mitigation', action='store_true',
                           help='Generate mitigations from existing threats file (JSON/CSV)')

    # Output options
    parser.add_argument('--format', choices=['screen', 'json', 'csv', 'html'],
                       default='screen', help='Output format (default: screen)')
    parser.add_argument('--output-dir', default='results',
                       help='Output directory for files (default: results)')

    # Filtering options
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                       help='Filter threats by minimum severity level')
    parser.add_argument('--component-type', choices=['ai', 'traditional', 'all'],
                       default='all', help='Filter by component type (default: all)')

    # Advanced options
    parser.add_argument('--config',
                       help='Path to configuration file (JSON)')
    parser.add_argument('--validate', action='store_true',
                       help='Validate DFD structure only, no analysis')
    parser.add_argument('--dry-run', action='store_true',
                       help='Simulate execution without running analysis')

    # Verbosity
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument('--verbose', '-v', action='store_true',
                                help='Verbose output with detailed information')
    verbosity_group.add_argument('--quiet', '-q', action='store_true',
                                help='Minimal output, errors only')

    parser.add_argument('--version', action='version', version='FRAITMO')

    args = parser.parse_args()

    # Configure logging based on verbosity
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Validation: ensure input file is provided unless using --version
    if not args.input_file:
        console.print(Text("[ERROR]", style="bold red"), "Input file is required")
        parser.print_help()
        sys.exit(1)

    # Determine execution mode
    if args.mitigation:
        # Mitigation-only mode
        return _run_mitigation_mode(args, console)
    else:
        # Standard DFD analysis mode
        return _run_analysis_mode(args, console)


# Support functions for the new CLI workflow

def _run_mitigation_mode(args, console):
    """Run mitigation generation from existing threats file"""
    threats_file = args.input_file

    if not os.path.exists(threats_file):
        console.print(Text("[ERROR]", style="bold red"), f"Threats file not found: {threats_file}")
        return 1

    # Determine file format
    file_ext = Path(threats_file).suffix.lower()
    if file_ext not in ['.json', '.csv']:
        console.print(Text("[ERROR]", style="bold red"), "Threats file must be JSON or CSV format")
        return 1

    if args.dry_run:
        console.print(Text("[INFO]", style="bold blue"), f"DRY RUN: Would generate mitigations from {threats_file}")
        return 0

    console.print(Text("[INFO]", style="bold blue"), "FRAITMO - Mitigation Generation Mode")
    console.print("=" * 80)
    console.print(Text("[INFO]", style="bold blue"), f"Loading threats from: {threats_file}")

    try:
        # Load threats from file
        threats = _load_threats_from_file(threats_file, file_ext)

        # Apply severity filter if specified
        if args.severity:
            threats = _filter_threats_by_severity(threats, args.severity)
            console.print(Text("[INFO]", style="bold blue"), f"Filtered to {len(threats)} threats (severity >= {args.severity})")

        # Apply component type filter if specified
        if args.component_type != 'all':
            threats = _filter_threats_by_component_type(threats, args.component_type)
            console.print(Text("[INFO]", style="bold blue"), f"Filtered to {len(threats)} threats (type: {args.component_type})")

        if not threats:
            console.print(Text("[WARN]", style="bold yellow"), "No threats found after filtering")
            return 0

        # Generate mitigations
        mitigations = _generate_mitigations_from_threats(threats, console)

        # Create result structure
        result = {
            'threats_found': threats,
            'llm_mitigations': mitigations,
            'processing_status': 'completed',
            'source_file': threats_file,
            'filters_applied': {
                'severity': args.severity,
                'component_type': args.component_type
            }
        }

        # Output results
        _output_results(result, args, console, mode='mitigation')

        console.print(Text("[OK]", style="bold green"), f"Mitigation generation complete: {len(mitigations)} mitigations generated")
        return 0

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Mitigation generation failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def _run_analysis_mode(args, console):
    """Run standard DFD threat analysis"""
    dfd_file = args.input_file

    if not os.path.exists(dfd_file):
        console.print(Text("[ERROR]", style="bold red"), f"DFD file not found: {dfd_file}")
        return 1

    # Validate DFD file extension
    if not dfd_file.lower().endswith('.xml'):
        console.print(Text("[WARN]", style="bold yellow"), f"Expected XML file, got: {Path(dfd_file).suffix}")

    # Determine analysis mode
    if args.threats:
        skip_mitigation = True
        mode_desc = "Threats Analysis Only"
    elif args.full_threat_modeling:
        skip_mitigation = False
        mode_desc = "Full Threat Modeling (Threats + Mitigations)"
    else:
        # Default behavior: full analysis
        skip_mitigation = False
        mode_desc = "Full Threat Modeling (Default)"

    if args.dry_run:
        console.print(Text("[INFO]", style="bold blue"), f"DRY RUN: Would run {mode_desc} on {dfd_file}")
        return 0

    if args.validate:
        console.print(Text("[INFO]", style="bold blue"), "DFD Validation Mode")
        return _validate_dfd_only(dfd_file, console)

    console.print(Text("[INFO]", style="bold blue"), "FRAITMO - Framework for Robust AI Threat Modeling Operations")
    console.print("=" * 80)
    console.print(Text("[INFO]", style="bold blue"), f"Mode: {mode_desc}")
    console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")

    # Initialize LLM client detection
    _detect_llm_providers(console)

    # Run the analysis
    try:
        # Load custom config if provided
        config = None
        if args.config:
            config = _load_config_file(args.config, console)

        # Run the analysis
        result = run_fraitmo_analysis(dfd_file, config=config, skip_mitigation=skip_mitigation)

        if result:
            # Apply filters if specified
            if args.severity or args.component_type != 'all':
                result = _apply_filters(result, args, console)

            # Output results
            _output_results(result, args, console, mode='analysis')

            # Summary
            total_threats = len(result.get('threats_found', [])) + len(result.get('llm_threats', []))
            total_mitigations = len(result.get('rag_mitigations', [])) + len(result.get('llm_mitigations', []))

            console.print(Text("[OK]", style="bold green"), f"Analysis complete: {total_threats} threats")
            if not skip_mitigation:
                console.print(Text("[OK]", style="bold green"), f"Mitigations generated: {total_mitigations}")

            return 0
        else:
            console.print(Text("[ERROR]", style="bold red"), "Analysis failed to produce results")
            return 1

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Analysis failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def _detect_llm_providers(console):
    """Detect available LLM providers"""
    console.print(Text("[INFO]", style="bold blue"), "Detecting available LLM providers...")
    from rag.llm_client import UnifiedLLMClient

    try:
        test_client = UnifiedLLMClient()

        # Check if any models are available
        if not test_client.available_models:
            console.print(Text("[ERROR]", style="bold red"), "No LLM models detected!")
            console.print(Text("[ERROR]", style="bold red"), "FRAITMO requires an active LLM model to function.")
            console.print(Text("[INFO]", style="bold blue"), "Please start one of the following:")
            console.print(Text("[INFO]", style="bold blue"), "  • Ollama: ollama serve")
            console.print(Text("[INFO]", style="bold blue"), "  • LM Studio: Start LM Studio and load a model")
            sys.exit(1)
        else:
            console.print(Text("[OK]", style="bold green"), f"LLM models detected: {len(test_client.available_models)} available")
            console.print(Text("[INFO]", style="bold blue"), f"Active model: {test_client.active_model} ({test_client.active_provider})")

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"LLM detection failed: {e}")
        console.print(Text("[ERROR]", style="bold red"), "FRAITMO requires an active LLM model to function.")
        console.print(Text("[INFO]", style="bold blue"), "Please start Ollama or LM Studio and try again.")
        sys.exit(1)


def _load_config_file(config_path, console):
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        console.print(Text("[INFO]", style="bold blue"), f"Configuration loaded from: {config_path}")
        return config
    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Failed to load config file: {e}")
        return None


def _validate_dfd_only(dfd_file, console):
    """Validate DFD structure without running analysis"""
    try:
        from dfd_parser.xml_parser import extract_from_xml

        console.print(Text("[INFO]", style="bold blue"), f"Validating DFD structure: {dfd_file}")

        # Parse the XML
        result = extract_from_xml(dfd_file)

        if result:
            console.print(Text("[OK]", style="bold green"), "DFD validation successful!")
            console.print(Text("[INFO]", style="bold blue"), f"Elements found: {len(result.get('elements', []))}")
            console.print(Text("[INFO]", style="bold blue"), f"Data flows found: {len(result.get('data_flows', []))}")
            console.print(Text("[INFO]", style="bold blue"), f"Trust boundaries found: {len(result.get('trust_boundaries', []))}")
            return 0
        else:
            console.print(Text("[ERROR]", style="bold red"), "DFD validation failed - no elements found")
            return 1

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"DFD validation failed: {e}")
        return 1


def _load_threats_from_file(file_path, file_ext):
    """Load threats from JSON or CSV file"""
    threats = []

    if file_ext == '.json':
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Handle different JSON structures
        if isinstance(data, list):
            threats = data
        elif isinstance(data, dict):
            # Try common keys for threats
            for key in ['threats', 'details', 'threats_found', 'llm_threats']:
                if key in data:
                    if isinstance(data[key], list):
                        threats.extend(data[key])
                    elif isinstance(data[key], dict) and 'details' in data[key]:
                        threats.extend(data[key]['details'])

    elif file_ext == '.csv':
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert CSV row to threat dict
                threat = {
                    'id': row.get('threat_id', ''),
                    'name': row.get('name', ''),
                    'severity': row.get('severity', ''),
                    'description': row.get('description', ''),
                    'target_component': row.get('target_component', ''),
                    'component_type': row.get('component_type', ''),
                    'ai_specific': row.get('ai_specific', '').lower() == 'true'
                }
                threats.append(threat)

    return threats


def _filter_threats_by_severity(threats, min_severity):
    """Filter threats by minimum severity level"""
    severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    min_level = severity_order.get(min_severity.lower(), 0)

    filtered = []
    for threat in threats:
        threat_severity = threat.get('severity', 'low').lower()
        threat_level = severity_order.get(threat_severity, 0)
        if threat_level >= min_level:
            filtered.append(threat)

    return filtered


def _filter_threats_by_component_type(threats, component_type):
    """Filter threats by component type"""
    if component_type == 'all':
        return threats

    filtered = []
    for threat in threats:
        if component_type == 'ai':
            if threat.get('ai_specific', False) or threat.get('component_type', '').lower() in ['ai', 'llm', 'ml']:
                filtered.append(threat)
        elif component_type == 'traditional':
            if not threat.get('ai_specific', False) and threat.get('component_type', '').lower() not in ['ai', 'llm', 'ml']:
                filtered.append(threat)

    return filtered


def _generate_mitigations_from_threats(threats, console):
    """Generate mitigations from existing threats using LLM"""
    mitigations = []

    try:
        from rag.llm_client import UnifiedLLMClient
        client = UnifiedLLMClient()

        if not client.available_models:
            console.print(Text("[WARN]", style="bold yellow"), "No LLM models available - cannot generate mitigations")
            return []

        console.print(Text("[INFO]", style="bold blue"), f"Generating mitigations for {len(threats)} threats...")

        for i, threat in enumerate(threats, 1):
            console.print(Text("[INFO]", style="bold blue"), f"Processing threat {i}/{len(threats)}: {threat.get('name', 'Unknown')}")

            prompt = f"""You are a cybersecurity expert. Generate specific mitigations for this threat:

Threat: {threat.get('name', 'Unknown')}
Severity: {threat.get('severity', 'Unknown')}
Description: {threat.get('description', 'No description')}
Target Component: {threat.get('target_component', 'Unknown')}

Provide 2-3 specific mitigation controls in JSON format:
[{{
    "name": "mitigation_name",
    "type": "preventive/detective/corrective",
    "implementation": "detailed_implementation_steps",
    "priority": "critical/high/medium/low",
    "effort": "low/medium/high",
    "effectiveness": "high/medium/low"
}}]

Only JSON, no additional text."""

            try:
                response = client.generate_response(prompt, max_tokens=800, temperature=0.1)

                # Parse mitigations from response
                import re
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
                if json_match:
                    parsed_mitigations = json.loads(json_match.group())
                    for mitigation in parsed_mitigations:
                        mitigation['threat_id'] = threat.get('id', f'THREAT_{i}')
                        mitigation['threat_name'] = threat.get('name', 'Unknown')
                        mitigation['source'] = 'llm_generated'
                        mitigations.append(mitigation)

            except Exception as e:
                console.print(Text("[WARN]", style="bold yellow"), f"Failed to generate mitigation for threat {i}: {e}")
                # Add fallback mitigation
                mitigations.append({
                    'name': f'Security Review for {threat.get("name", "Unknown Threat")}',
                    'type': 'preventive',
                    'implementation': f'Conduct security review to address {threat.get("name", "Unknown Threat")}',
                    'priority': threat.get('severity', 'medium').lower(),
                    'effort': 'medium',
                    'effectiveness': 'medium',
                    'threat_id': threat.get('id', f'THREAT_{i}'),
                    'threat_name': threat.get('name', 'Unknown'),
                    'source': 'fallback'
                })

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Mitigation generation failed: {e}")

    return mitigations


def _apply_filters(result, args, console):
    """Apply severity and component type filters to analysis results"""
    if args.severity:
        # Filter threats by severity
        result['threats_found'] = _filter_threats_by_severity(result.get('threats_found', []), args.severity)
        result['llm_threats'] = _filter_threats_by_severity(result.get('llm_threats', []), args.severity)
        console.print(Text("[INFO]", style="bold blue"), f"Applied severity filter: {args.severity}")

    if args.component_type != 'all':
        # Filter threats by component type
        result['threats_found'] = _filter_threats_by_component_type(result.get('threats_found', []), args.component_type)
        result['llm_threats'] = _filter_threats_by_component_type(result.get('llm_threats', []), args.component_type)
        console.print(Text("[INFO]", style="bold blue"), f"Applied component type filter: {args.component_type}")

    return result


def _output_results(result, args, console, mode='analysis'):
    """Output results in the specified format"""
    if args.format == 'screen':
        # Display to screen
        display_results(result)

    elif args.format == 'json':
        # Export to JSON
        json_file = export_threats_to_json(result, args.output_dir)
        console.print(Text("[OK]", style="bold green"), f"Results exported to JSON: {json_file}")

        # Show summary
        total_threats = len(result.get('threats_found', [])) + len(result.get('llm_threats', []))
        console.print(Text("[INFO]", style="bold blue"), f"Total threats exported: {total_threats}")

    elif args.format == 'csv':
        # Export to CSV
        csv_file = export_threats_to_csv(result, args.output_dir)
        console.print(Text("[OK]", style="bold green"), f"Results exported to CSV: {csv_file}")

        # Show summary
        total_threats = len(result.get('threats_found', [])) + len(result.get('llm_threats', []))
        console.print(Text("[INFO]", style="bold blue"), f"Total threats exported: {total_threats}")

    elif args.format == 'html':
        # HTML format (future implementation)
        console.print(Text("[WARN]", style="bold yellow"), "HTML format not yet implemented - showing on screen instead")
        display_results(result)


if __name__ == "__main__":
    main()
