#!/usr/bin/env python3
"""
FRAITMO - Framework for Robust AI Threat Modeling Operations
Main entry point for threat analysis pipeline
"""

import os
import sys
import argparse
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from rich.console import Console
from rich.text import Text

# Add the project root to Python path for imports
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import the complete pipeline
from pipeline.graph import run_fraitmo_analysis
from export_results import export_threats_to_json, export_threats_to_csv  # Export functions


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
    parser = argparse.ArgumentParser(description='FRAITMO - Framework for Robust AI Threat Modeling Operations')
    parser.add_argument('dfd_file', help='Path to the DFD XML file')
    parser.add_argument('--mitigation', action='store_true', 
                       help='Generate mitigations (slower, includes threat mitigation analysis)')
    parser.add_argument('--output', choices=['json', 'csv'], 
                       help='Output format: json or csv (default: display to screen)')
    
    args = parser.parse_args()
    dfd_file = args.dfd_file
    
    if not os.path.exists(dfd_file):
        console.print(Text("[ERROR]", style="bold red"), f"DFD file not found: {dfd_file}")
        sys.exit(1)
    
    console.print(Text("[INFO]", style="bold blue"), "FRAITMO - Framework for Robust AI Threat Modeling Operations")
    console.print("=" * 80)
    
    # Initialize unified LLM client to detect available providers
    console.print(Text("[INFO]", style="bold blue"), "Detecting available LLM providers...")
    from rag.llm_client import UnifiedLLMClient
    
    try:
        test_client = UnifiedLLMClient()
        
        # Check if any models are available
        if not test_client.available_models:
            console.print(Text("[OK]", style="bold green"), "Running in offline mode - parsing and classification only")
            console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")
        else:
            console.print(Text("[OK]", style="bold green"), "LLM models detected")
            console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")
            
    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), "LLM detection failed but continuing in offline mode")
        console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")
    
    # Run the complete analysis
    try:
        # Run the analysis
        result = run_fraitmo_analysis(dfd_file, skip_mitigation=not args.mitigation)
        
        if result:
            # Handle different output formats
            if args.output == 'json':
                # Export to JSON
                json_file = export_threats_to_json(result)
                console.print(Text("[OK]", style="bold green"), f"Threats exported to JSON: {json_file}")
                
                # Show quick summary
                all_threats = result.get('threats_found', []) + result.get('llm_threats', [])
                console.print(Text("[INFO]", style="bold blue"), f"Total threats exported: {len(all_threats)}")
                
            elif args.output == 'csv':
                # Export to CSV  
                csv_file = export_threats_to_csv(result)
                console.print(Text("[OK]", style="bold green"), f"Threats exported to CSV: {csv_file}")
                
                # Show quick summary
                all_threats = result.get('threats_found', []) + result.get('llm_threats', [])
                console.print(Text("[INFO]", style="bold blue"), f"Total threats exported: {len(all_threats)}")
                
            else:
                # Default: Display results to screen
                display_results(result)
            
            # Check if there were errors during analysis
            errors = result.get('errors', [])
            if errors:
                console.print(Text("[WARN]", style="bold yellow"), f"Analysis completed with {len(errors)} error(s):")
                for error in errors:
                    console.print(Text("[ERROR]", style="bold red"), f"  - {error}")
                console.print("=" * 80)
            else:
                # Success message only if no errors
                console.print(Text("[OK]", style="bold green"), "Analysis completed successfully!")
                console.print("=" * 80)
            
        else:
            console.print(Text("[ERROR]", style="bold red"), "Analysis failed - no results returned")
            sys.exit(1)
            
    except KeyboardInterrupt:
        console.print(Text("[WARN]", style="bold yellow"), "Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()