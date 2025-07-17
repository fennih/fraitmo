#!/usr/bin/env python3
"""
FRAITMO - Framework for Robust AI Threat Modeling Operations
Main application entry point using LangGraph pipeline
"""

import os
import sys
import argparse
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from rich.console import Console
from rich.text import Text

# Import the complete pipeline
from pipeline.graph import run_fraitmo_analysis


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
        console.print("Top Threats:")
        for i, threat in enumerate(threats_found[:5], 1):
            console.print(f"  {i}. {threat.get('name', 'Unknown Threat')}")
            console.print(f"     Severity: {threat.get('severity', 'Unknown')}")
            console.print(f"     Target: {threat.get('target_component', {}).get('name', 'Unknown')}")


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
    all_threats = result.get('threats_found', []) + result.get('direct_threats', [])
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
    
    # Mitigation proposal (combined from both paths)
    all_mitigations = result.get('mitigations', []) + result.get('direct_mitigations_kb', [])
    format_mitigation_summary(
        console,
        all_mitigations,
        result.get('implementation_plan', {})
    )
    
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
    """Main application entry point"""
    # Load environment variables
    load_dotenv()
    
    # Initialize rich console for styled output
    console = Console()
    
    console.print(Text("[INFO]", style="bold blue"), "FRAITMO - Framework for Robust AI Threat Modeling Operations")
    console.print("=" * 80)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='FRAITMO - Framework for Robust AI Threat Modeling Operations')
    parser.add_argument('dfd_file', help='Path to the DFD XML file')
    parser.add_argument('--offline', action='store_true', 
                       help='Run in offline mode (parsing and classification only, no LLM analysis)')
    
    args = parser.parse_args()
    dfd_file = args.dfd_file
    
    # Validate DFD file exists
    if not os.path.exists(dfd_file):
        console.print(Text("[ERROR]", style="bold red"), f"DFD file '{dfd_file}' not found")
        sys.exit(1)
    
    # Initialize unified LLM client to detect available providers
    console.print(Text("[INFO]", style="bold blue"), "Detecting available LLM providers...")
    from rag.llm_client import UnifiedLLMClient
    
    try:
        test_client = UnifiedLLMClient()
        
        # Check if any models are available
        if not test_client.available_models:
            if args.offline:
                console.print(Text("[OK]", style="bold green"), "Running in offline mode - parsing and classification only")
                console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")
            else:
                console.print(Text("[ERROR]", style="bold red"), "No LLM models found")
                console.print(Text("[HINT]", style="dim cyan"), "Start Ollama or LM Studio for full analysis, or use --offline for basic parsing")
                sys.exit(1)
        else:
            console.print(Text("[OK]", style="bold green"), "LLM models detected")
            console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")
            
    except Exception as e:
        if args.offline:
            console.print(Text("[WARN]", style="bold yellow"), "LLM detection failed but continuing in offline mode")
            console.print(Text("[INFO]", style="bold blue"), f"Analyzing DFD: {dfd_file}")
        else:
            console.print(Text("[ERROR]", style="bold red"), f"LLM detection failed: {e}")
            console.print(Text("[HINT]", style="dim cyan"), "Start Ollama or LM Studio, or use --offline for basic parsing")
            sys.exit(1)
    
    # Run the complete analysis
    try:
        result = run_fraitmo_analysis(dfd_file)
        
        if result:
            # Display results
            display_results(result)
            
            # Success message
            console.print(Text("[OK]", style="bold green"), "Analysis completed successfully!")
            console.print("=" * 80)
            
        else:
            console.print(Text("[ERROR]", style="bold red"), "Analysis failed - no results returned")
            sys.exit(1)
            
    except KeyboardInterrupt:
        console.print(Text("[WARN]", style="bold yellow"), "Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Analysis failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()