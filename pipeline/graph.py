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
from pipeline.nodes.llm_quality_filter import llm_quality_filter_node
from pipeline.nodes.cross_component_analyzer import cross_component_analyzer_node

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
    workflow.add_node("llm_analyzer", llm_analyzer_node)
    workflow.add_node("cross_component_analyzer", cross_component_analyzer_node)  # New node
    workflow.add_node("rag_mitigation_proposer", rag_mitigation_proposer_node)
    workflow.add_node("llm_mitigation_proposer", llm_mitigation_proposer_node)
    workflow.add_node("quality_filter", llm_quality_filter_node)

    # Set entry point
    workflow.set_entry_point("dfd_parser")

    # Define the execution flow
    workflow.add_edge("dfd_parser", "semantic_modeling")
    workflow.add_edge("semantic_modeling", "ai_detector")
    workflow.add_edge("ai_detector", "kb_router")
    workflow.add_edge("kb_router", "rag_threat_search")
    # Remove the redundant llm_analysis edge that causes context overflow
    # workflow.add_edge("rag_threat_search", "llm_analysis")

    # Add parallel LLM analysis after ai_detector
    workflow.add_edge("ai_detector", "llm_analyzer")

    # Add cross-component analysis after both threat identification paths
    workflow.add_edge("rag_threat_search", "cross_component_analyzer")
    workflow.add_edge("llm_analyzer", "cross_component_analyzer")

    if skip_mitigation:
        # Skip mitigation generation - go directly to quality filter from cross-component analyzer
        workflow.add_edge("cross_component_analyzer", "quality_filter")
        console.print(Text("[INFO]", style="bold blue"), "Mitigation generation disabled - threats only mode")
    else:
        # Both paths have their own mitigation proposers after cross-component analysis
        workflow.add_edge("cross_component_analyzer", "rag_mitigation_proposer")
        workflow.add_edge("cross_component_analyzer", "llm_mitigation_proposer")

        # Both mitigation paths converge to quality filter
        workflow.add_edge("rag_mitigation_proposer", "quality_filter")
        workflow.add_edge("llm_mitigation_proposer", "quality_filter")
        console.print(Text("[INFO]", style="bold blue"), "Full analysis mode - threats and mitigations")

    # Quality filter is the final step before ending
    workflow.add_edge("quality_filter", END)

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
        cross_component_threats=[],  # New field
        trust_boundary_count=0,      # New field
        data_flow_count=0,          # New field
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

        # Calculate and add overall risk to result before displaying summary
        overall_risk = _calculate_overall_risk(result)
        result['overall_risk'] = overall_risk

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

    # Check if we're in threats-only mode
    skip_mitigation = result.get('skip_mitigation', False)

    # Show quality filtering results if applied
    if result.get('quality_filter_applied', False):
        console.print(Text("[OK]", style="bold green"), "🔍 LLM Quality Filter Applied")

        # Original counts
        total_threats = len(result.get('threats_found', [])) + len(result.get('llm_threats', []))
        total_mitigations = len(result.get('rag_mitigations', [])) + len(result.get('llm_mitigations', []))

        # Filtered counts
        filtered_threats = len(result.get('filtered_threats', []))
        filtered_mitigations = len(result.get('filtered_mitigations', []))

        console.print(Text("[INFO]", style="bold blue"), f"Threats: {total_threats} → {filtered_threats} (after deduplication)")

        # Only show mitigation stats if we're not in threats-only mode
        if not skip_mitigation:
            console.print(Text("[INFO]", style="bold blue"), f"Mitigations: {total_mitigations} → {filtered_mitigations} (relevant only)")

            # Show threat-mitigation mapping stats only if we have mitigations
            mapping_count = len(result.get('threat_mitigation_mapping', {}))
            if mapping_count > 0:
                console.print(Text("[INFO]", style="bold blue"), f"Threat-Mitigation Mappings: {mapping_count}")

    else:
        # Fallback to original counts
        total_threats = len(result.get('threats_found', [])) + len(result.get('llm_threats', []))
        total_mitigations = len(result.get('rag_mitigations', [])) + len(result.get('llm_mitigations', []))

        console.print(Text("[WARN]", style="bold yellow"), "Quality Filter Not Applied")
        console.print(Text("[INFO]", style="bold blue"), f"Total Threats Found: {total_threats}")
        console.print(f"  RAG Path: {len(result.get('threats_found', []))}")
        console.print(f"  LLM Path: {len(result.get('llm_threats', []))}")

        # Only show mitigation stats if we're not in threats-only mode
        if not skip_mitigation:
            console.print(Text("[INFO]", style="bold blue"), f"Total Mitigations: {total_mitigations}")
            console.print(f"  RAG Path: {len(result.get('rag_mitigations', []))}")
            console.print(f"  LLM Path: {len(result.get('llm_mitigations', []))}")

    # Calculate and show overall risk
    overall_risk = _calculate_overall_risk(result)
    console.print(Text("[INFO]", style="bold blue"), f"Overall Risk: {overall_risk}")

    if result.get('errors'):
        console.print(Text("[ERROR]", style="bold red"), f"Errors: {len(result.get('errors', []))}")
        for error in result.get('errors', []):
            console.print(f"  - {error}")

def _calculate_overall_risk(result: Dict[str, Any]) -> str:
    """Calculate overall risk based on threat severity distribution"""

    # Get threats from filtered results if available, otherwise from original
    if result.get('quality_filter_applied', False):
        threats = result.get('filtered_threats', [])
    else:
        threats = result.get('threats_found', []) + result.get('llm_threats', [])

    if not threats:
        return "Unknown (No threats identified)"

    # Count threats by severity
    critical_count = sum(1 for t in threats if t.get('severity', '').lower() == 'critical')
    high_count = sum(1 for t in threats if t.get('severity', '').lower() == 'high')
    medium_count = sum(1 for t in threats if t.get('severity', '').lower() == 'medium')
    low_count = sum(1 for t in threats if t.get('severity', '').lower() == 'low')

    total_threats = len(threats)

    # Risk calculation logic
    if critical_count >= 3 or (critical_count >= 1 and high_count >= 5):
        return f"Critical ({critical_count} critical, {high_count} high threats)"
    elif critical_count >= 1 or high_count >= 3:
        return f"High ({critical_count} critical, {high_count} high threats)"
    elif high_count >= 1 or medium_count >= 5:
        return f"Medium ({high_count} high, {medium_count} medium threats)"
    elif medium_count >= 1 or total_threats >= 3:
        return f"Low ({medium_count} medium, {total_threats} total threats)"
    else:
        return f"Minimal ({total_threats} threats identified)"


if __name__ == "__main__":
    # Test the pipeline
    import sys
    if len(sys.argv) > 1:
        dfd_path = sys.argv[1]
        run_fraitmo_analysis(dfd_path)
    else:
        console.print(Text("[INFO]", style="bold blue"), "Usage: python pipeline/graph.py <path_to_dfd.xml>")
