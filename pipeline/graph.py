# LangGraph Pipeline Definition - Defines nodes, edges, and execution flow for threat analysis

import os
import json
from typing import Dict, Any, Optional
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from rich.console import Console
from rich.text import Text

from pipeline.state import ThreatAnalysisState
from pipeline.nodes.ai_detector import ai_component_detector_node
from pipeline.nodes.kb_router import kb_router_node
from pipeline.nodes.rag_threat_searcher import rag_threat_searcher_node
from pipeline.nodes.rag_mitigation_proposer import rag_mitigation_proposer_node
from pipeline.nodes.llm_analyzer import llm_analyzer_node
from pipeline.nodes.llm_mitigation_proposer import llm_mitigation_proposer_node

from dfd_parser.xml_parser import extract_from_xml
from models.schema import DataFlowDiagram
from models.builder import build_dfd_from_parser

console = Console()

def dfd_parser_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Parse DFD XML file and extract components"""
    console.print(Text("[INFO]", style="bold blue"), "DFD Parser Node: Parsing DFD XML...")
    
    dfd_file = state.get('dfd_xml_path')
    if not dfd_file:
        error_msg = "No DFD file specified"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}
    
    try:
        # Parse the DFD XML file
        parsed_data = extract_from_xml(dfd_file)
        
        if not parsed_data:
            error_msg = "Failed to parse DFD file"
            console.print(Text("[ERROR]", style="bold red"), error_msg)
            return {"errors": [error_msg]}
        
        console.print(Text("[OK]", style="bold green"), "DFD Parsed:")
        console.print(Text("[INFO]", style="bold blue"), f"Components: {len(parsed_data.get('components', {}))}")
        console.print(Text("[INFO]", style="bold blue"), f"Connections: {len(parsed_data.get('connections', []))}")
        console.print(Text("[INFO]", style="bold blue"), f"Trust boundaries: {len(parsed_data.get('trust_boundaries', []))}")
        
        # Return only the field we're modifying
        return {"parsed_data": parsed_data}
        
    except Exception as e:
        error_msg = f"DFD Parser Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        state['errors'] = state.get('errors', []) + [error_msg]
        return state


def semantic_modeling_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Build semantic model from parsed DFD data"""
    console.print(Text("[INFO]", style="bold blue"), "Semantic Modeling Node: Building semantic model...")
    
    parsed_data = state.get('parsed_data')
    if not parsed_data:
        error_msg = "No parsed DFD data available"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}
    
    try:
        # Build semantic model
        dfd_model = build_dfd_from_parser(parsed_data)
        
        if not dfd_model:
            error_msg = "Failed to build semantic model"
            console.print(Text("[ERROR]", style="bold red"), error_msg)
            return {"errors": [error_msg]}
        
        console.print(Text("[OK]", style="bold green"), "Semantic Model Built:")
        console.print(Text("[INFO]", style="bold blue"), f"Components: {len(dfd_model.components)}")
        console.print(Text("[INFO]", style="bold blue"), f"Trust zones: {len(dfd_model.trust_zones)}")
        console.print(Text("[INFO]", style="bold blue"), f"Connections: {len(dfd_model.connections)}")
        
        # Return only the field we're modifying
        return {"dfd_model": dfd_model}
        
    except Exception as e:
        error_msg = f"Semantic Modeling Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}


def llm_analysis_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Enhanced LLM Analysis Node with comprehensive threat analysis"""
    console.print(Text("[INFO]", style="bold blue"), "LLM Analysis Node: Analyzing threats with LLM...")
    
    # Initialize LLM client
    from rag.llm_client import UnifiedLLMClient
    
    try:
        client = UnifiedLLMClient()
        
        # Get all available threats from both RAG and direct paths
        threats_found = state.get('threats_found', [])
        if not threats_found:
            console.print(Text("[INFO]", style="bold blue"), "No threats found to analyze")
            return state
        
        # Prepare threat analysis prompt
        threat_summaries = []
        for threat in threats_found:
            summary = f"""
Threat: {threat.get('name', 'Unknown')}
Component: {threat.get('target_component', {}).get('name', 'Unknown')}
Severity: {threat.get('severity', 'Unknown')}
Description: {threat.get('description', 'No description')}
"""
            threat_summaries.append(summary)
        
        prompt = f"""
You are a cybersecurity expert analyzing threats in an AI/LLM system architecture.
Analyze the following {len(threats_found)} threats and provide:
1. Overall risk assessment (Critical/High/Medium/Low)
2. Risk level breakdown by threat count
3. Key concerns and recommendations
4. Priority mitigation areas

THREATS TO ANALYZE:
{chr(10).join(threat_summaries)}

Provide a comprehensive analysis focusing on AI/LLM specific security concerns.
"""
        
        # Generate LLM analysis
        response = client.generate_response(prompt)
        
        if response:
            # Extract risk level from response
            risk_level = "Unknown"
            if "Critical" in response:
                risk_level = "Critical"
            elif "High" in response:
                risk_level = "High"
            elif "Medium" in response:
                risk_level = "Medium"
            elif "Low" in response:
                risk_level = "Low"
            
            # Count threats by severity
            severity_counts = {}
            for threat in threats_found:
                severity = threat.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            state['threat_analysis'] = {
                'llm_response': response,
                'model_used': client.active_model,
                'provider_used': client.active_provider
            }
            
            state['risk_assessment'] = {
                'overall_risk': risk_level,
                'threat_breakdown': severity_counts,
                'total_threats': len(threats_found)
            }
            
            console.print(Text("[OK]", style="bold green"), "LLM Analysis Complete:")
            console.print(Text("[INFO]", style="bold blue"), f"Threats Analyzed: {len(threats_found)}")
            console.print(Text("[INFO]", style="bold blue"), f"Overall Risk: {risk_level}")
            console.print(Text("[INFO]", style="bold blue"), f"Model Used: {client.active_model} via {client.active_provider}")
        
        return state
        
    except Exception as e:
        error_msg = f"LLM Analysis Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        state['errors'] = state.get('errors', []) + [error_msg]
        return state


def create_threat_analysis_prompt(threats, ai_components, traditional_components, dfd_model):
    """Create a comprehensive prompt for threat analysis"""
    prompt = f"""You are a cybersecurity expert analyzing a system architecture for threats.

SYSTEM OVERVIEW:
- AI/LLM Components: {len(ai_components)}
- Traditional Components: {len(traditional_components)}
- Total Components: {len(dfd_model.components) if dfd_model else 'Unknown'}
- Cross-zone Connections: {len(dfd_model.cross_zone_connections) if dfd_model else 'Unknown'}

THREATS IDENTIFIED ({len(threats)} total):
"""
    
    for i, threat in enumerate(threats[:10], 1):  # Limit to first 10 for context
        prompt += f"\n{i}. {threat.get('name', 'Unknown Threat')}"
        prompt += f"\n   Severity: {threat.get('severity', 'Unknown')}"
        prompt += f"\n   Target: {threat.get('target_component', {}).get('name', 'Unknown')}"
        prompt += f"\n   Description: {threat.get('description', 'No description')[:200]}..."
    
    if len(threats) > 10:
        prompt += f"\n... and {len(threats) - 10} more threats."
    
    prompt += f"""

Please provide a comprehensive security analysis including:
1. Overall risk assessment for this architecture
2. Key security concerns, especially for AI/LLM components if present
3. Critical threats that should be prioritized
4. Recommendations for improving security posture
5. Specific concerns about cross-zone communications

Keep your analysis practical and actionable, focusing on the most critical security issues.
"""
    
    return prompt


def assess_risk_level(threats):
    """Simple risk level assessment based on threat severity"""
    if not threats:
        return "low"
    
    critical_count = len([t for t in threats if t.get('severity', '').lower() == 'critical'])
    high_count = len([t for t in threats if t.get('severity', '').lower() == 'high'])
    
    if critical_count > 0:
        return "critical"
    elif high_count > 2:
        return "high"
    elif high_count > 0:
        return "medium"
    else:
        return "low"


def create_fraitmo_graph(skip_mitigation: bool = False):
    """
    Create the complete FRAITMO threat analysis graph
    
    Args:
        skip_mitigation: If True, skip mitigation generation for faster execution
        
    Returns:
        Compiled LangGraph application
    """
    # Load environment variables
    load_dotenv()
    
    console.print(Text("[INFO]", style="bold blue"), "Creating FRAITMO LangGraph pipeline...")
    
    # Create the graph
    workflow = StateGraph(ThreatAnalysisState)
    
    # Add nodes in the order of execution
    workflow.add_node("dfd_parser", dfd_parser_node)
    workflow.add_node("semantic_modeling", semantic_modeling_node)
    workflow.add_node("ai_detector", ai_component_detector_node)
    workflow.add_node("kb_router", kb_router_node)
    workflow.add_node("rag_threat_search", rag_threat_searcher_node)
    workflow.add_node("llm_analysis", llm_analysis_node)
    workflow.add_node("llm_analyzer", llm_analyzer_node)
    workflow.add_node("rag_mitigation_proposer", rag_mitigation_proposer_node)
    workflow.add_node("llm_mitigation_proposer", llm_mitigation_proposer_node)
    
    # Set entry point
    workflow.set_entry_point("dfd_parser")
    
    # Define the execution flow
    workflow.add_edge("dfd_parser", "semantic_modeling")
    workflow.add_edge("semantic_modeling", "ai_detector")
    workflow.add_edge("ai_detector", "kb_router")
    workflow.add_edge("kb_router", "rag_threat_search")
    workflow.add_edge("rag_threat_search", "llm_analysis")
    
    # Add parallel LLM analysis after ai_detector
    workflow.add_edge("ai_detector", "llm_analyzer")
    
    if skip_mitigation:
        # Skip mitigation generation - end after threat analysis
        workflow.add_edge("llm_analysis", END)
        workflow.add_edge("llm_analyzer", END)
        console.print(Text("[INFO]", style="bold blue"), "Mitigation generation disabled - threats only mode")
    else:
        # Both paths have their own mitigation proposers
        workflow.add_edge("llm_analysis", "rag_mitigation_proposer")
        workflow.add_edge("llm_analyzer", "llm_mitigation_proposer")
        
        # Both mitigation paths end
        workflow.add_edge("rag_mitigation_proposer", END)
        workflow.add_edge("llm_mitigation_proposer", END)
        console.print(Text("[INFO]", style="bold blue"), "Full analysis mode - threats and mitigations")
    
    # Compile with memory saver for state persistence
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)
    
    console.print(Text("[OK]", style="bold green"), "FRAITMO LangGraph pipeline created successfully!")
    
    return app


def run_fraitmo_analysis(dfd_xml_path: str, config: Dict[str, Any] = None, skip_mitigation: bool = False):
    """
    Run complete FRAITMO threat analysis
    
    Args:
        dfd_xml_path: Path to DFD XML file
        config: Optional configuration for the graph execution
        skip_mitigation: If True, skip mitigation generation for faster execution
    """
    console.print(Text("[INFO]", style="bold blue"), "Starting FRAITMO LangGraph Threat Analysis")
    console.print("=" * 60)
    
    # Create the graph
    app = create_fraitmo_graph(skip_mitigation=skip_mitigation)
    
    # Initial state with all required fields
    initial_state = ThreatAnalysisState(
        dfd_xml_path=dfd_xml_path,
        dfd_content=None,
        dfd_model=None,
        parsed_data=None,
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
        threat_analysis={},
        risk_assessment={},
        rag_mitigations=[],
        rag_implementation_plan={},
        llm_mitigations=[],
        llm_implementation_plan={},
        llm_mitigation_summary={},
        implementation_tracker={},
        processing_status="started",
        llm_analysis_status="pending",
        llm_mitigation_status="pending",
        current_node="initializing",
        errors=[],
        warnings=[],
        skip_mitigation=skip_mitigation
    )
    
    # Configure execution
    if config is None:
        config = {"configurable": {"thread_id": "fraitmo-analysis-1"}}
    
    try:
        # Execute the graph
        console.print(Text("[INFO]", style="bold blue"), "Executing LangGraph pipeline...")
        result = app.invoke(initial_state, config=config)
        
        console.print(Text("[OK]", style="bold green"), "FRAITMO Analysis Complete!")
        console.print("=" * 60)
        
        # Display summary
        display_analysis_summary(result)
        
        return result
        
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"FRAITMO Analysis Failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def display_analysis_summary(result):
    """Display a summary of the analysis results"""
    console.print(Text("[INFO]", style="bold blue"), "ANALYSIS SUMMARY:")
    console.print(f"Status: {result.get('processing_status', 'unknown')}")
    console.print(Text("[INFO]", style="bold blue"), f"AI Components: {len(result.get('ai_components', []))}")
    console.print(Text("[INFO]", style="bold blue"), f"Traditional Components: {len(result.get('traditional_components', []))}")
    
    # Combined threats and mitigations from both paths
    total_threats = len(result.get('threats_found', [])) + len(result.get('llm_threats', []))
    total_mitigations = len(result.get('rag_mitigations', [])) + len(result.get('llm_mitigations', []))
    
    console.print(Text("[INFO]", style="bold blue"), f"Total Threats Found: {total_threats}")
    console.print(f"  RAG Path: {len(result.get('threats_found', []))}")
    console.print(f"  LLM Path: {len(result.get('llm_threats', []))}")
    
    console.print(Text("[INFO]", style="bold blue"), f"Total Mitigations: {total_mitigations}")
    console.print(f"  RAG Path: {len(result.get('rag_mitigations', []))}")
    console.print(f"  LLM Path: {len(result.get('llm_mitigations', []))}")
    
    console.print(Text("[INFO]", style="bold blue"), f"Overall Risk: {result.get('risk_assessment', {}).get('overall_risk', 'unknown')}")
    
    if result.get('errors'):
        console.print(Text("[ERROR]", style="bold red"), f"Errors: {len(result.get('errors', []))}")
        for error in result.get('errors', []):
            console.print(f"  - {error}")


if __name__ == "__main__":
    # Test the pipeline
    import sys
    if len(sys.argv) > 1:
        dfd_path = sys.argv[1]
        run_fraitmo_analysis(dfd_path)
    else:
        console.print(Text("[INFO]", style="bold blue"), "Usage: python pipeline/graph.py <path_to_dfd.xml>")
