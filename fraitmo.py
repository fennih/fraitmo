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

# Import the complete pipeline
from pipeline.graph import run_fraitmo_analysis


def format_components_summary(ai_components, traditional_components):
    """Format component classification summary"""
    print("\n📊 COMPONENT CLASSIFICATION:")
    print(f"   🤖 AI Components: {len(ai_components)}")
    for comp in ai_components:
        name = comp.get('name', 'Unknown')
        # Remove everything in parentheses
        clean_name = name.split('(')[0].strip()
        print(f"     - {clean_name}")
        
    print(f"   🏗️ Traditional Components: {len(traditional_components)}")
    for comp in traditional_components:
        name = comp.get('name', 'Unknown')
        # Remove everything in parentheses
        clean_name = name.split('(')[0].strip()
        print(f"     - {clean_name}")


def format_threat_summary(threats_found, ai_threats, traditional_threats):
    """Format threat identification summary"""
    print("\n🚨 THREAT IDENTIFICATION:")
    print(f"   📊 Total Threats Found: {len(threats_found)}")
    print(f"   🤖 AI-Specific Threats: {len(ai_threats)}")
    print(f"   🏗️ Traditional Threats: {len(traditional_threats)}")
    
    if threats_found:
        print("\n   Top Threats:")
        for i, threat in enumerate(threats_found[:5], 1):
            print(f"     {i}. {threat.get('name', 'Unknown Threat')}")
            print(f"        Severity: {threat.get('severity', 'Unknown')}")
            print(f"        Target: {threat.get('target_component', {}).get('name', 'Unknown')}")


def format_mitigation_summary(mitigations, implementation_plan):
    """Format mitigation proposal summary"""
    print("\n💡 MITIGATION PROPOSAL:")
    print(f"   📋 Total Mitigations: {len(mitigations)}")
    
    if mitigations:
        print("\n   Priority Mitigations:")
        for i, mitigation in enumerate(mitigations[:5], 1):
            print(f"     {i}. {mitigation.get('name', 'Unknown Mitigation')}")
            print(f"        Effectiveness: {mitigation.get('effectiveness', 'Unknown')}")
            print(f"        Implementation: {mitigation.get('implementation_time', 'Unknown')}")
            print(f"        Cost: {mitigation.get('cost', 'Unknown')}")
    
    if implementation_plan:
        print(f"\n   📅 Implementation Plan:")
        print(f"     Total Tasks: {implementation_plan.get('total_tasks', 0)}")
        print(f"     Critical Tasks: {implementation_plan.get('critical_tasks', 0)}")
        print(f"     Estimated Completion: {implementation_plan.get('estimated_completion', 'Unknown')}")


def format_llm_analysis(threat_analysis, risk_assessment):
    """Format LLM analysis results"""
    print("\n🤖 LLM ANALYSIS:")
    print(f"   🎯 Overall Risk: {risk_assessment.get('overall_risk', 'Unknown')}")
    print(f"   📊 Model Used: {threat_analysis.get('model_used', 'Unknown')}")
    
    breakdown = risk_assessment.get('threat_breakdown', {})
    if breakdown:
        print(f"   📈 Threat Breakdown:")
        for level, count in breakdown.items():
            if count > 0:
                print(f"     {level.title()}: {count}")
    
    llm_response = threat_analysis.get('llm_response', '')
    if llm_response:
        print(f"\n   📝 LLM Analysis Summary:")
        # Display first 500 characters of LLM response
        summary = llm_response[:500]
        if len(llm_response) > 500:
            summary += "..."
        print(f"     {summary}")


def display_results(result: Dict[str, Any]):
    """Display comprehensive analysis results"""
    print("\n" + "="*80)
    print("🎉 FRAITMO THREAT ANALYSIS RESULTS")
    print("="*80)
    
    # Component classification
    format_components_summary(
        result.get('ai_components', []),
        result.get('traditional_components', [])
    )
    
    # Threat identification (combined from both paths)
    all_threats = result.get('threats_found', []) + result.get('direct_threats', [])
    format_threat_summary(
        all_threats,
        result.get('ai_threats', []),
        result.get('traditional_threats', [])
    )
    
    # LLM analysis
    format_llm_analysis(
        result.get('threat_analysis', {}),
        result.get('risk_assessment', {})
    )
    
    # Mitigation proposal (combined from both paths)
    all_mitigations = result.get('mitigations', []) + result.get('direct_mitigations_kb', [])
    format_mitigation_summary(
        all_mitigations,
        result.get('implementation_plan', {})
    )
    
    # Direct LLM Analysis Summary
    if result.get('direct_threats') or result.get('direct_mitigations_kb'):
        format_direct_analysis_summary(result)
    
    # Processing status
    print("\n🔄 PROCESSING STATUS:")
    print(f"   Status: {result.get('processing_status', 'Unknown')}")
    
    if result.get('errors'):
        print(f"   ❌ Errors: {len(result.get('errors', []))}")
        for error in result.get('errors', []):
            print(f"     - {error}")
    
    if result.get('warnings'):
        print(f"   ⚠️ Warnings: {len(result.get('warnings', []))}")
        for warning in result.get('warnings', []):
            print(f"     - {warning}")


def format_direct_analysis_summary(result: Dict[str, Any]):
    """Format direct LLM analysis summary"""
    print("\n🧠 DIRECT LLM ANALYSIS SUMMARY:")
    
    direct_summary = result.get('direct_analysis_summary', {})
    direct_threats = result.get('direct_threats', [])
    direct_mitigations = result.get('direct_mitigations_kb', [])
    
    print(f"   🎯 Direct Threats Found: {len(direct_threats)}")
    print(f"   🛡️ Direct Mitigations Generated: {len(direct_mitigations)}")
    
    if direct_summary:
        ai_threats = direct_summary.get('ai_specific_threats', 0)
        traditional_threats = direct_summary.get('traditional_threats', 0)
        print(f"   🤖 AI-Specific Threats: {ai_threats}")
        print(f"   🏗️ Traditional Threats: {traditional_threats}")
    
    # Show mitigation summary
    mitigation_summary = result.get('direct_mitigation_summary', {})
    if mitigation_summary:
        print(f"   ⏱️ Estimated Timeline: {mitigation_summary.get('estimated_timeline', 'Unknown')}")
        
        priority_breakdown = mitigation_summary.get('by_priority', {})
        if priority_breakdown:
            print("   📊 Mitigations by Priority:")
            for priority, count in priority_breakdown.items():
                if count > 0:
                    print(f"     - {priority}: {count}")


def main():
    """Main application entry point"""
    # Load environment variables
    load_dotenv()
    
    print("🚀 FRAITMO - Framework for Robust AI Threat Modeling Operations")
    print("="*80)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='FRAITMO - Framework for Robust AI Threat Modeling Operations')
    parser.add_argument('dfd_file', help='Path to the DFD XML file')
    parser.add_argument('--offline', action='store_true', 
                       help='Run in offline mode (parsing and classification only, no LLM analysis)')
    
    args = parser.parse_args()
    dfd_file = args.dfd_file
    
    # Validate DFD file exists
    if not os.path.exists(dfd_file):
        print(f"❌ Error: DFD file '{dfd_file}' not found")
        sys.exit(1)
    
    print(f"📋 Analyzing DFD: {dfd_file}")
    
    # Initialize unified LLM client to detect available providers
    print("🔍 Detecting available LLM providers...")
    from rag.llm_client import UnifiedLLMClient
    
    try:
        test_client = UnifiedLLMClient()
        
        # Check if any models are available
        if not test_client.available_models:
            if args.offline:
                print("🔌 Running in offline mode - parsing and classification only")
            else:
                print("❌ No LLM models found.")
                print("💡 Start Ollama or LM Studio for full analysis, or use --offline for basic parsing.")
                sys.exit(1)
            
    except Exception as e:
        if args.offline:
            print("🔌 Running in offline mode - LLM detection failed but continuing with parsing")
        else:
            print(f"❌ LLM detection failed: {e}")
            print("💡 Start Ollama or LM Studio, or use --offline for basic parsing.")
            sys.exit(1)
    
    # Run the complete analysis
    try:
        result = run_fraitmo_analysis(dfd_file)
        
        if result:
            # Display results
            display_results(result)
            
            # Success message
            print("\n✅ Analysis completed successfully!")
            print("="*80)
            
        else:
            print("❌ Analysis failed - no results returned")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Analysis failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()