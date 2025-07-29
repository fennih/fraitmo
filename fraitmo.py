#!/usr/bin/env python3
"""
FRAITMO - Framework for Robust AI Threat Modeling Operations
Main entry point for the FRAITMO threat modeling tool.
"""

import sys
import os
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.align import Align

# Import local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from utils.console import set_console_verbosity, console
    from dfd_parser.xml_parser import extract_from_xml
    from rag.llm_client import UnifiedLLMClient
    from pipeline.graph import run_fraitmo_analysis
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all dependencies are installed and modules are in the correct location.")
    sys.exit(1)


def format_components_summary(ai_components, traditional_components):
    """Format component classification summary"""
    console.print(Text("[INFO]", style="bold blue"), "COMPONENT CLASSIFICATION:")
    console.print(Text("[INFO]", style="bold blue"), f"AI Components: {len(ai_components)}")

    if ai_components:
        for comp in ai_components:
            comp_name = comp.get('name', 'Unknown')
            comp_type = comp.get('component_type', 'Unknown')
            risk_factors = comp.get('risk_factors', [])
            console.print(f"  - {comp_name} ({comp_type})")
            if risk_factors:
                console.print(f"    Risk factors: {', '.join(risk_factors)}")

    console.print(Text("[INFO]", style="bold blue"), f"Traditional Components: {len(traditional_components)}")


def format_threat_summary(threats_found, ai_threats, traditional_threats):
    """Format threat identification summary"""
    console.print(Text("[INFO]", style="bold blue"), "THREAT IDENTIFICATION:")
    console.print(Text("[INFO]", style="bold blue"), f"Total Threats Found: {len(threats_found)}")
    console.print(Text("[INFO]", style="bold blue"), f"AI-Specific Threats: {len(ai_threats)}")
    console.print(Text("[INFO]", style="bold blue"), f"Traditional Threats: {len(traditional_threats)}")

    if threats_found:
        console.print("All Threats Found:")
        for i, threat in enumerate(threats_found, 1):
            console.print(f"  {i}. {threat.get('name', 'Unknown Threat')}")
    else:
        console.print(Text("[INFO]", style="bold blue"), "No threats identified")


def format_mitigation_summary(mitigations, implementation_plan):
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


def format_llm_analysis(threat_analysis, risk_assessment):
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


def format_direct_analysis_summary(result: Dict[str, Any]):
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


def display_results_progressive(result: Dict[str, Any]):
    """Display analysis results progressively as they're processed"""
    if not result:
        print("ERROR: No results to display")
        return result

    print("\n" + "="*80)
    print("🚨 FRAITMO THREAT ANALYSIS RESULTS")
    print("="*80)

    # Collect threats from all sources
    all_threats = []
    possible_threat_fields = [
        'threats_found', 'llm_threats', 'traditional_threats', 'ai_threats',
        'cross_component_threats', 'rag_threats', 'filtered_threats',
        'final_threats', 'threats', 'all_threats'
    ]

    for field in possible_threat_fields:
        threats = result.get(field, [])
        if threats and isinstance(threats, list):
            all_threats.extend(threats)

    # Remove duplicates by name
    unique_threats = []
    seen_names = set()
    for threat in all_threats:
        if isinstance(threat, dict):
            name = threat.get('name', threat.get('threat_name', f"Threat_{len(unique_threats)}"))
            if name not in seen_names:
                unique_threats.append(threat)
                seen_names.add(name)

    # NO PROBABILITY FILTERING: Treat all threats as relevant
    relevant_threats = unique_threats  # Keep ALL threats
    speculative_threats = []  # No threats are considered speculative anymore

    print(f"🎯 Found {len(relevant_threats)} threats")

    # Sort by severity: Critical > High > Medium > Low > Unknown
    severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'unknown': 5}
    relevant_threats.sort(key=lambda x: severity_order.get(x.get('severity', 'unknown').lower(), 5))

    print("\n" + "="*80)
    print("📋 THREAT ANALYSIS RESULTS")
    print("="*80)

    if relevant_threats or speculative_threats:
        # Sort relevant threats by severity (Critical > High > Medium > Low)
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4}
        relevant_threats.sort(key=lambda t: severity_order.get(t.get('severity', 'Unknown'), 4))

        # Display relevant threats
        if relevant_threats:
            pass  # Start displaying directly

        # Display threats ordered by severity
        for i, threat in enumerate(relevant_threats, 1):
            print(f"\n🚨 THREAT #{i} of {len(relevant_threats)}")
            print("-" * 50)

            if isinstance(threat, dict):
                name = threat.get('name', 'Unknown Threat')
                severity = threat.get('severity', 'Unknown')
                description = threat.get('description', 'No description')
                component = threat.get('component', threat.get('target_component', 'Unknown'))

                print(f"📌 Name: {name}")
                print(f"⚠️  Severity: {severity}")
                prob_score = threat.get('probability_score', 0)
                print(f"🎯 Probability: {prob_score}% (likelihood of being present)")

                # Extract component info in a more conversational way
                target_details = []
                comp_name = "Unknown Component"
                comp_zone = ""

                if isinstance(component, dict):
                    comp_name = component.get('name', 'Unknown Component')
                    comp_zone = component.get('zone', component.get('trust_zone', ''))
                elif isinstance(component, str) and component != 'Unknown':
                    comp_name = component

                # Display Component in conversational format
                component_display = comp_name
                if comp_zone:
                    component_display = f"{comp_name} in trust zone {comp_zone}"
                print(f"🏛️  Component: {component_display}")
                print(f"📝 Description: {description[:200]}{'...' if len(description) > 200 else ''}")

                # Create conversational component description for Target Object
                if comp_name != "Unknown Component":
                    if comp_zone:
                        # Conversational format: "FastAPI in trust zone 2"
                        target_details.append(f"{comp_name} in trust zone {comp_zone}")
                    else:
                        # Just component name if no zone
                        target_details.append(comp_name)

                # Add AI-specific indicator
                if threat.get('ai_specific'):
                    target_details.append("🤖 AI-Specific Component")

                # Add attack vector if available (more concise)
                if threat.get('attack_vector'):
                    attack_vector = threat.get('attack_vector')
                    # Shorten attack vector if too long
                    if len(attack_vector) > 80:
                        attack_vector = attack_vector[:77] + "..."
                    target_details.append(f"Attack Vector: {attack_vector}")

                if target_details:
                    print(f"🏗️  Target Object: {' | '.join(target_details)}")

                # Show applicability reasoning if available from intelligent assessment
                if threat.get('applicability_score') is not None:
                    app_score = threat.get('applicability_score', 'N/A')
                    app_reasoning = threat.get('applicability_reasoning', '')
                    if app_reasoning:
                        print(f"🧠 Applicability Assessment: {app_score}% - {app_reasoning}")
                    else:
                        print(f"🧠 Applicability Score: {app_score}%")

            else:
                print(f"Threat data: {threat}")

                        # Show progress every 20 threats
            if i % 20 == 0:
                print(f"\n📈 Progress: {i}/{len(relevant_threats)} threats processed")

    else:
        print("❌ NO THREATS TO DISPLAY")

    print("\n" + "="*80)
    if relevant_threats:
        print(f"✅ Analysis complete: {len(relevant_threats)} threats identified")
    else:
        print(f"✅ Analysis complete: No threats identified")
    print("="*80)

    # Prepare modified result for reports - all threats are now included
    modified_result = result.copy()
    modified_result['all_threats_for_export'] = relevant_threats  # All threats, no flags needed
    modified_result['displayed_threats_count'] = len(relevant_threats)
    modified_result['hidden_threats_count'] = 0  # No hidden threats anymore

    return modified_result


def main():
    """Main entry point for FRAITMO analysis"""
    # Parse command line arguments first to get verbosity settings
    parser = argparse.ArgumentParser(description="FRAITMO - Framework for Robust AI Threat Modeling Operations")

    # Input options
    parser.add_argument("dfd_file", help="Path to the DFD XML file to analyze")

    # Analysis modes
    parser.add_argument("--threats", action="store_true", help="Generate threats only (skip mitigations)")
    parser.add_argument("--full", action="store_true", help="Full analysis with threats and mitigations")
    parser.add_argument("--mitigation", action="store_true", help="Generate mitigations from existing threats")
    parser.add_argument("--validate", action="store_true", help="Validate DFD structure")

    # Configuration options
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", choices=["json", "txt", "html"], default="txt", help="Output format")

    # Verbosity control
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress all output except errors")

    args = parser.parse_args()

    # Initialize global console for all modules
    set_console_verbosity(args.verbose, args.quiet)

    # Show banner
    console.print(Text("[INFO] FRAITMO - Framework for Robust AI Threat Modeling Operations", style="bold blue"))

    # Detect LLM providers first
    if not _detect_llm_providers():
        return 1

    # Determine analysis mode
    if args.mitigation:
        return _run_mitigation_mode(args)
    elif args.validate:
        return _run_validation_mode(args)
    else:
        return _run_analysis_mode(args)


def _run_mitigation_mode(args):
    """Run mitigation generation from existing threats file"""
    threats_file = args.input_file

    if not Path(threats_file).exists():
        console.print(Text("[ERROR]", style="bold red"), f"Threats file not found: {threats_file}")
        return 1

    console.print(Text("[INFO]", style="bold blue"), f"Generating mitigations from: {threats_file}")

    try:
        with open(threats_file, 'r') as f:
            threats_data = json.load(f)

        mitigations = _generate_mitigations_from_threats(threats_data['threats'])

        # Save results
        output_file = args.output or f"{Path(threats_file).stem}_mitigations.json"

        with open(output_file, 'w') as f:
            json.dump({"mitigations": mitigations}, f, indent=2)

        console.print(Text("[OK]", style="bold green"), f"Mitigations saved to: {output_file}")
        return 0

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Failed to generate mitigations: {e}")
        return 1


def _run_analysis_mode(args):
    """Run main threat analysis mode"""
    # Validate input file
    dfd_file = Path(args.dfd_file)
    if not dfd_file.exists():
        console.print(Text("[ERROR]", style="bold red"), f"DFD file not found: {dfd_file}")
        return 1

    # Show mode info
    mode = "Threats Only" if args.threats else "Full Analysis" if args.full else "Threats Only (default)"
    console.print(Text("[INFO]", style="bold blue"), f"Mode: {mode}")
    console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")

    # Detect LLM providers early
    if not _detect_llm_providers():
        return 1

    # Load configuration
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
            console.print(Text("[OK]", style="bold green"), f"Configuration loaded from: {args.config}")
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Failed to load config: {e}")

    # Determine mitigation mode
    skip_mitigation = args.threats or not args.full

    try:
        # Start progress
        console.start_progress("Running FRAITMO threat analysis...")

        # Run analysis with progress updates
        result = run_fraitmo_analysis_with_progress(dfd_file, config=config, skip_mitigation=skip_mitigation, verbose=args.verbose, quiet=args.quiet)

        # Stop progress
        console.stop_progress()

        if not result:
            console.print(Text("[ERROR]", style="bold red"), "Analysis failed!")
            return 1

        # Display results (this will now show progressive results)
        modified_result = display_results_progressive(result)

        # Export results if requested (use modified result with [LOW PROB] flags)
        if args.output:
            _output_results(modified_result, args)

        return 0

    except Exception as e:
        console.stop_progress()
        console.print(Text("[ERROR]", style="bold red"), f"FRAITMO analysis failed: {e}")
        console.print(Text("[ERROR]", style="bold red"), "Analysis failed!")
        if "errors" in str(e):
            for error in str(e).split("\\n"):
                if error.strip():
                    console.print(Text("[ERROR]", style="bold red"), f"  - {error.strip()}")
        return 1


def run_fraitmo_analysis_with_progress(dfd_xml_path: str, config: Dict[str, Any] = None, skip_mitigation: bool = False, verbose: bool = False, quiet: bool = False):
    """Run FRAITMO analysis with REAL-TIME progress updates from actual node execution"""

    console.update_progress(1, "🔧 Initializing FRAITMO pipeline...")

    # Import here to avoid circular dependency
    from pipeline.graph import create_graph
    import threading

    # REAL progress tracking based on actual work completed
    progress_lock = threading.Lock()
    current_progress = 5

    def progress_callback(progress_percent: int, message: str):
        """Callback for nodes to report REAL progress"""
        nonlocal current_progress
        with progress_lock:
            if progress_percent > current_progress:
                current_progress = progress_percent
                console.update_progress(progress_percent, message)

    try:
        # Create the graph with progress callback
        app = create_graph(skip_mitigation=skip_mitigation, progress_callback=progress_callback)

        # Prepare initial state
        from pipeline.state import ThreatAnalysisState
        initial_state = ThreatAnalysisState(
            dfd_xml_path=dfd_xml_path,
            dfd_content=None,
            parsed_data=None,
            dfd_model=None,
            ai_components=[],
            traditional_components=[],
            component_classification={},
            ai_knowledge_base=[],
            general_knowledge_base=[],
            routing_strategy=[],
            threats_found=[],
            ai_threats=[],
            traditional_threats=[],
            cross_zone_threats=[],
            llm_threats=[],
            llm_analysis_summary={},
            cross_component_threats=[],
            trust_boundary_count=0,
            data_flow_count=0,
            threat_analysis={},
            risk_assessment={},
            rag_mitigations=[],
            rag_implementation_plan={},
            llm_mitigations=[],
            llm_implementation_plan={},
            llm_mitigation_summary={},
            implementation_tracker={},
            filtered_threats=[],
            filtered_mitigations=[],
            threat_mitigation_mapping={},
            quality_filter_applied=False,
            processing_status="starting",
            llm_analysis_status="pending",
            llm_mitigation_status="pending",
            current_node="start",
            errors=[],
            warnings=[],
            skip_mitigation=skip_mitigation
        )

        config = config or {"configurable": {"thread_id": "fraitmo-analysis"}}

        # Use streaming - nodes will report their own REAL progress
        final_result = None

        for chunk in app.stream(initial_state, config=config):
            for node_name, node_output in chunk.items():
                # Nodes report their own progress via callback
                # Just store the final result
                if isinstance(node_output, dict):
                    final_result = node_output

        # Final progress update
        with progress_lock:
            console.update_progress(100, "✅ Analysis complete!")

        return final_result

    except Exception as e:
        with progress_lock:
            console.update_progress(100, "❌ Analysis failed!")
        raise e


def _run_validation_mode(args):
    """Run DFD validation mode"""
    dfd_file = Path(args.dfd_file)
    if not dfd_file.exists():
        console.print(Text("[ERROR]", style="bold red"), f"DFD file not found: {dfd_file}")
        return 1

    console.print(Text("[INFO]", style="bold blue"), f"Validating DFD structure: {dfd_file}")

    try:
        result = extract_from_xml(str(dfd_file))

        console.print(Text("[OK]", style="bold green"), "DFD validation successful!")
        console.print(Text("[INFO]", style="bold blue"), f"Components found: {len(result.get('components', {}))}")
        console.print(Text("[INFO]", style="bold blue"), f"Connections found: {len(result.get('connections', []))}")
        console.print(Text("[INFO]", style="bold blue"), f"Trust boundaries found: {len(result.get('trust_boundaries', []))}")

        return 0

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"DFD validation failed: {e}")
        return 1


def _detect_llm_providers():
    """Detect available LLM providers"""
    console.print(Text("[INFO]", style="bold blue"), "Detecting available LLM providers...")

    try:
        test_client = UnifiedLLMClient()

        if not test_client.available_models:
            console.print(Text("[ERROR]", style="bold red"), "No LLM models detected!")
            console.print(Text("[ERROR]", style="bold red"), "FRAITMO requires an active LLM model to function.")
            console.print(Text("[INFO]", style="bold blue"), "Please start one of the following:")
            console.print(Text("[INFO]", style="bold blue"), "  • Ollama: ollama serve")
            console.print(Text("[INFO]", style="bold blue"), "  • LM Studio: Start LM Studio and load a model")
            return False

        # Count models by provider
        provider_counts = {}
        for model in test_client.available_models:
            provider = getattr(model, 'provider', 'unknown')
            provider_counts[provider] = provider_counts.get(provider, 0) + 1

        # Show detected models
        for provider, count in provider_counts.items():
            console.print(Text("[INFO]", style="bold blue"), f"Found {count} models in {provider}")

        console.print(Text("[OK]", style="bold green"), f"Using: {test_client.active_model} via {test_client.active_provider}")
        return True

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Failed to detect LLM provider: {e}")
        return False


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


def _generate_mitigations_from_threats(threats):
    """Generate mitigations from existing threats using LLM"""
    mitigations = []

    try:
        client = UnifiedLLMClient()

        for threat in threats:
            prompt = f"""
            Generate specific mitigation strategies for this security threat:

            Threat: {threat.get('name', 'Unknown')}
            Description: {threat.get('description', 'No description')}
            Severity: {threat.get('severity', 'Unknown')}
            Component: {threat.get('component', 'Unknown')}

            Provide practical, actionable mitigation steps.
            """

            response = client.generate_response(prompt, max_tokens=300)

            mitigation = {
                "threat_name": threat.get('name'),
                "mitigation_strategy": response,
                "component": threat.get('component'),
                "severity": threat.get('severity')
            }

            mitigations.append(mitigation)

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Failed to generate mitigations: {e}")

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


def _output_results(result: Dict[str, Any], args):
    """Output results to file"""
    if not args.output:
        return

    try:
        output_path = Path(args.output)

        if args.format == "json":
            with open(output_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)
        elif args.format == "txt":
            with open(output_path, 'w') as f:
                f.write("FRAITMO THREAT ANALYSIS RESULTS\n")
                f.write("=" * 50 + "\n\n")

                threats = result.get('threats_found', [])
                f.write(f"Total Threats Found: {len(threats)}\n")

                for i, threat in enumerate(threats, 1):
                    f.write(f"\n{i}. {threat.get('name', 'Unknown')}\n")
                    f.write(f"   Severity: {threat.get('severity', 'Unknown')}\n")
                    f.write(f"   Component: {threat.get('component', 'Unknown')}\n")
                    f.write(f"   Description: {threat.get('description', 'No description')}\n")

        console.print(Text("[OK]", style="bold green"), f"Results saved to: {output_path}")

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Failed to save results: {e}")


def _display_threats_table(threats):
    """Display threats in a formatted table"""
    table = Table(title="🚨 Identified Threats")
    table.add_column("Threat", style="cyan", no_wrap=True)
    table.add_column("Component", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Description", style="white")

    for threat in threats:
        threat_name = threat.get('name', 'Unknown Threat')
        component = threat.get('component_name', 'Unknown')
        severity = threat.get('severity', 'Unknown')
        description = threat.get('description', 'No description available')[:80] + "..."

        table.add_row(threat_name, component, severity, description)

    console.print(table)


def _display_mitigations_table(mitigations):
    """Display mitigations in a formatted table"""
    table = Table(title="🛡️ Proposed Mitigations")
    table.add_column("Mitigation", style="green", no_wrap=True)
    table.add_column("Priority", style="yellow")
    table.add_column("Description", style="white")

    for mitigation in mitigations:
        mit_name = mitigation.get('name', 'Unknown Mitigation')
        priority = mitigation.get('priority', 'Unknown')
        description = mitigation.get('description', 'No description available')[:80] + "..."

        table.add_row(mit_name, priority, description)

    console.print(table)


def _display_comprehensive_summary(result):
    """Display comprehensive analysis summary"""
    direct_threats = result.get('llm_threats', [])
    direct_mitigations = result.get('llm_mitigations', [])
    mitigation_summary = result.get('mitigation_summary', {})

    console.print(Text("[INFO]", style="bold blue"), "DIRECT LLM ANALYSIS SUMMARY:")

    if direct_threats:
        ai_threats = len([t for t in direct_threats if t.get('ai_specific', False)])
        traditional_threats = len([t for t in direct_threats if not t.get('ai_specific', False)])

        console.print(Text("[INFO]", style="bold blue"), f"Direct Threats Found: {len(direct_threats)}")
        console.print(Text("[INFO]", style="bold blue"), f"Direct Mitigations Generated: {len(direct_mitigations)}")

        if ai_threats > 0 or traditional_threats > 0:
            console.print(Text("[INFO]", style="bold blue"), f"AI-Specific Threats: {ai_threats}")
            console.print(Text("[INFO]", style="bold blue"), f"Traditional Threats: {traditional_threats}")

    if mitigation_summary:
        console.print(Text("[INFO]", style="bold blue"), f"Estimated Timeline: {mitigation_summary.get('estimated_timeline', 'Unknown')}")


def _display_detailed_threat_analysis(detailed_analysis):
    """Display detailed threat analysis if available"""
    if isinstance(detailed_analysis, str):
        panel = Panel(detailed_analysis, title="🔍 Detailed Threat Analysis", border_style="blue")
        console.print(panel)


def _display_final_summary(result):
    """Display final analysis summary"""
    all_threats = result.get('threats_found', []) + result.get('llm_threats', []) + result.get('rag_threats', [])
    all_mitigations = result.get('rag_mitigations', []) + result.get('llm_mitigations', [])

    # Filter threats that actually have mitigations
    threats_with_mitigations = []
    if result.get('skip_mitigation', True):
        console.print(Text("[INFO]", style="bold blue"), "MITIGATION PROPOSAL:")
        console.print(Text("[INFO]", style="dim"), "Mitigation generation skipped (use --mitigation flag to enable)")
    else:
        threats_with_mitigations = [t for t in all_threats if any(m.get('threat_id') == t.get('id') for m in all_mitigations)]

    console.print(Text("[INFO]", style="bold blue"), "PROCESSING STATUS:")
    console.print(f"✓ Threats identified: {len(all_threats)}")
    if not result.get('skip_mitigation', True):
        console.print(f"✓ Mitigations proposed: {len(all_mitigations)}")
        console.print(f"✓ Threats with mitigations: {len(threats_with_mitigations)}")

    console.print(Text("[OK]", style="bold green"), "FRAITMO Analysis Complete!")


if __name__ == "__main__":
    sys.exit(main())
