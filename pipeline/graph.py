"""
LangGraph-based pipeline for FRAITMO threat analysis
"""

import os
import json
from typing import Dict, Any, Optional
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from rich.text import Text

# Import console from utils
from utils.console import console

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


def dfd_parser_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """DFD Parser Node: Parse DFD XML and extract components"""
    console.print(Text("[INFO]", style="bold blue"), "DFD Parser Node: Parsing DFD XML...")

    # Report start of parsing - REALISTIC percentages for fast operations
    if progress_callback:
        progress_callback(2, "📄 Reading DFD file...")

    try:
        dfd_xml_path = state.get("dfd_xml_path")

        # Read the DFD file content for storage
        with open(dfd_xml_path, 'r', encoding='utf-8') as file:
            dfd_content = file.read()

        if progress_callback:
            progress_callback(4, "📄 Parsing DFD structure...")

        # Parse the DFD using the file path (not content)
        parsed_data = extract_from_xml(dfd_xml_path)

        if not parsed_data:
            return {"errors": ["Failed to parse DFD XML"]}

        if progress_callback:
            progress_callback(6, f"📄 DFD parsed: {len(parsed_data.get('components', {}))} components")

        console.print(Text("[OK]", style="bold green"), "DFD Parsed:")
        console.print(Text("[INFO]", style="bold blue"), f"Components: {len(parsed_data.get('components', {}))}")
        console.print(Text("[INFO]", style="bold blue"), f"Connections: {len(parsed_data.get('connections', []))}")
        console.print(Text("[INFO]", style="bold blue"), f"Trust boundaries: {len(parsed_data.get('trust_boundaries', []))}")

        return {
            "dfd_content": dfd_content,
            "parsed_data": parsed_data
        }

    except Exception as e:
        error_msg = f"DFD Parser failed: {str(e)}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}


def semantic_modeling_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """Semantic Modeling Node: Build semantic model from parsed data"""
    console.print(Text("[INFO]", style="bold blue"), "Semantic Modeling Node: Building semantic model...")

    if progress_callback:
        progress_callback(8, "🏗️ Building semantic model...")

    try:
        parsed_data = state.get("parsed_data")
        if not parsed_data:
            return {"errors": ["No parsed data available for semantic modeling"]}

        # Build the DFD model
        dfd_model = build_dfd_from_parser(parsed_data)

        if not dfd_model:
            return {"errors": ["Failed to build semantic model"]}

        console.print(Text("[OK]", style="bold green"), "Semantic Model Built:")
        console.print(Text("[INFO]", style="bold blue"), f"Components: {len(dfd_model.components)}")
        console.print(Text("[INFO]", style="bold blue"), f"Trust zones: {len(dfd_model.trust_zones)}")
        console.print(Text("[INFO]", style="bold blue"), f"Connections: {len(dfd_model.connections)}")

        return {
            "dfd_model": dfd_model
        }

    except Exception as e:
        error_msg = f"Semantic modeling failed: {str(e)}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}


def create_graph(skip_mitigation: bool = False, progress_callback=None) -> StateGraph:
    """
    Create and configure the LangGraph pipeline

    Args:
        skip_mitigation: If True, skip mitigation generation nodes

    Returns:
        Compiled StateGraph ready for execution
    """
    # Load environment variables
    load_dotenv()

    console.print(Text("[INFO]", style="bold blue"), "Creating FRAITMO LangGraph pipeline...")

    # Create the graph
    workflow = StateGraph(ThreatAnalysisState)

    # Add nodes with progress callback support for REAL-TIME progress reporting
    workflow.add_node("dfd_parser", lambda state: dfd_parser_node(state, progress_callback))
    workflow.add_node("semantic_modeling", lambda state: semantic_modeling_node(state, progress_callback))
    workflow.add_node("ai_detector", lambda state: ai_component_detector_node(state, progress_callback))
    workflow.add_node("kb_router", lambda state: kb_router_node(state, progress_callback))
    workflow.add_node("rag_threat_search", lambda state: rag_threat_searcher_node(state, progress_callback))
    workflow.add_node("llm_analyzer", lambda state: llm_analyzer_node(state, progress_callback))
    workflow.add_node("cross_component_analyzer", lambda state: cross_component_analyzer_node(state, progress_callback))
    workflow.add_node("rag_mitigation_proposer", lambda state: rag_mitigation_proposer_node(state, progress_callback))
    workflow.add_node("llm_mitigation_proposer", lambda state: llm_mitigation_proposer_node(state, progress_callback))
    workflow.add_node("quality_filter", lambda state: llm_quality_filter_node(state, progress_callback))

    # Set entry point
    workflow.set_entry_point("dfd_parser")

    # Define the execution flow
    workflow.add_edge("dfd_parser", "semantic_modeling")
    workflow.add_edge("semantic_modeling", "ai_detector")
    workflow.add_edge("ai_detector", "kb_router")
    workflow.add_edge("kb_router", "rag_threat_search")

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

    # End after quality filter
    workflow.add_edge("quality_filter", END)

    # Compile the graph
    memory = MemorySaver()
    app = workflow.compile(checkpointer=memory)

    console.print(Text("[OK]", style="bold green"), "FRAITMO LangGraph pipeline created successfully")

    return app


def run_fraitmo_analysis(dfd_xml_path: str, config: Dict[str, Any] = None, skip_mitigation: bool = False, verbose: bool = False, quiet: bool = False):
    """
    Run the complete FRAITMO analysis using LangGraph

    Args:
        dfd_xml_path: Path to the DFD XML file
        config: Optional configuration dictionary
        skip_mitigation: Skip mitigation generation if True
        verbose: Enable verbose output
        quiet: Enable quiet mode

    Returns:
        Dict containing analysis results
    """
    # Configure global console for pipeline
    console.print(Text("[INFO]", style="bold blue"), "Starting FRAITMO LangGraph Threat Analysis")
    console.print("=" * 60)

    try:
        # Create the graph
        app = create_graph(skip_mitigation=skip_mitigation)

        console.print(Text("[INFO]", style="bold blue"), "Executing LangGraph pipeline...")

        # Initial state with all required fields
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

        # Execute the pipeline
        config = config or {"configurable": {"thread_id": "fraitmo-analysis"}}
        result = app.invoke(initial_state, config=config)

        if result:
            console.print(Text("[OK]", style="bold green"), "LangGraph execution completed successfully")

            # Process and summarize results
            console.print("=" * 60)
            console.print(Text("[INFO]", style="bold blue"), "ANALYSIS SUMMARY:")
            console.print("=" * 60)
            console.print(Text("[INFO]", style="bold blue"), f"AI Components: {len(result.get('ai_components', []))}")
            console.print(Text("[INFO]", style="bold blue"), f"Traditional Components: {len(result.get('traditional_components', []))}")

            # Count threats
            total_threats = 0
            filtered_threats = 0
            rag_threats = len(result.get('rag_threats', []))
            llm_threats = len(result.get('llm_threats', []))
            cross_component_threats = len(result.get('cross_component_threats', []))
            final_threats = len(result.get('final_threats', []))

            total_threats = rag_threats + llm_threats + cross_component_threats
            filtered_threats = final_threats

            console.print(Text("[INFO]", style="bold blue"), f"Threats: {total_threats} → {filtered_threats} (after deduplication)")

            # Count mitigations if generated
            if not skip_mitigation:
                total_mitigations = len(result.get('rag_mitigations', [])) + len(result.get('llm_mitigations', []))
                filtered_mitigations = len(result.get('final_mitigations', []))
                console.print(Text("[INFO]", style="bold blue"), f"Mitigations: {total_mitigations} → {filtered_mitigations} (relevant only)")

                # Count threat-mitigation mappings
                mapping_count = len(result.get('threat_mitigation_mappings', []))
                console.print(Text("[INFO]", style="bold blue"), f"Threat-Mitigation Mappings: {mapping_count}")

            # Show final counts
            console.print("=" * 60)
            console.print(Text("[INFO]", style="bold blue"), f"Total Threats Found: {total_threats}")

            if not skip_mitigation:
                total_mitigations = len(result.get('rag_mitigations', [])) + len(result.get('llm_mitigations', []))
                console.print(Text("[INFO]", style="bold blue"), f"Total Mitigations: {total_mitigations}")

            # Risk assessment if available
            risk_assessment = result.get('risk_assessment', {})
            if risk_assessment:
                overall_risk = risk_assessment.get('overall_risk', 'Unknown')
                console.print(Text("[INFO]", style="bold blue"), f"Overall Risk: {overall_risk}")

            return result
        else:
            console.print(Text("[ERROR]", style="bold red"), "LangGraph execution failed - no results returned")
            return {"errors": ["Pipeline execution failed"]}

    except Exception as e:
        error_msg = f"FRAITMO analysis failed: {str(e)}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)

        if verbose:
            import traceback
            traceback.print_exc()

        return {"errors": [error_msg]}


# Test execution
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        console.print(Text("[ERROR]", style="bold red"), "Usage: python pipeline/graph.py <path_to_dfd.xml>")
        console.print(Text("[INFO]", style="bold blue"), "Usage: python pipeline/graph.py <path_to_dfd.xml>")
        sys.exit(1)

    dfd_path = sys.argv[1]
    if not os.path.exists(dfd_path):
        console.print(Text("[ERROR]", style="bold red"), f"DFD file not found: {dfd_path}")
        sys.exit(1)

    # Run analysis
    result = run_fraitmo_analysis(dfd_path, skip_mitigation=True)

    if result and "errors" not in result:
        console.print(Text("[OK]", style="bold green"), "Analysis completed successfully!")
    else:
        console.print(Text("[ERROR]", style="bold red"), "Analysis failed!")
        if result and "errors" in result:
            for error in result["errors"]:
                console.print(f"  - {error}")
        sys.exit(1)
