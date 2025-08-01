# Threat Analysis Workflow - Complete LangGraph workflow for AI-aware threat modeling

from typing import Dict, Any
from langgraph.graph import StateGraph, END
from pipeline.state import ThreatAnalysisState
from pipeline.nodes.ai_detector import ai_detector_node
from pipeline.nodes.kb_router import kb_router_node
from pipeline.nodes.rag_threat_searcher import rag_threat_searcher_node
from pipeline.nodes.llm_analyzer import llm_analyzer_node
from pipeline.nodes.cross_component_analyzer import cross_component_analyzer_node
from pipeline.nodes.rag_mitigation_proposer import rag_mitigation_proposer_node
from pipeline.nodes.llm_mitigation_proposer import llm_mitigation_proposer_node
from pipeline.nodes.llm_quality_filter import llm_quality_filter_node
from pipeline.nodes.tracker import tracker_node


def create_threat_analysis_workflow(skip_mitigation: bool = False) -> StateGraph:
    """Create the complete threat analysis workflow"""
    
    # Create the workflow graph
    workflow = StateGraph(ThreatAnalysisState)
    
    # Add nodes
    workflow.add_node("ai_detector", ai_detector_node)
    workflow.add_node("kb_router", kb_router_node)
    workflow.add_node("rag_threat_searcher", rag_threat_searcher_node)
    workflow.add_node("llm_analyzer", llm_analyzer_node)
    workflow.add_node("cross_component_analyzer", cross_component_analyzer_node)
    
    if not skip_mitigation:
        workflow.add_node("rag_mitigation_proposer", rag_mitigation_proposer_node)
        workflow.add_node("llm_mitigation_proposer", llm_mitigation_proposer_node)
    
    workflow.add_node("llm_quality_filter", llm_quality_filter_node)
    workflow.add_node("tracker", tracker_node)
    
    # Define workflow edges
    workflow.set_entry_point("ai_detector")
    
    # AI Detection -> KB Router
    workflow.add_edge("ai_detector", "kb_router")
    
    # KB Router -> Parallel threat analysis
    workflow.add_edge("kb_router", "rag_threat_searcher")
    workflow.add_edge("kb_router", "llm_analyzer")
    workflow.add_edge("kb_router", "cross_component_analyzer")
    
    if not skip_mitigation:
        # Threat analysis -> Mitigation generation
        workflow.add_edge("rag_threat_searcher", "rag_mitigation_proposer")
        workflow.add_edge("llm_analyzer", "llm_mitigation_proposer")
        
        # Mitigation generation -> Quality filter
        workflow.add_edge("rag_mitigation_proposer", "llm_quality_filter")
        workflow.add_edge("llm_mitigation_proposer", "llm_quality_filter")
    else:
        # Direct to quality filter for threats-only mode
        workflow.add_edge("rag_threat_searcher", "llm_quality_filter")
        workflow.add_edge("llm_analyzer", "llm_quality_filter")
    
    # Cross-component analysis -> Quality filter
    workflow.add_edge("cross_component_analyzer", "llm_quality_filter")
    
    # Quality filter -> Tracker -> End
    workflow.add_edge("llm_quality_filter", "tracker")
    workflow.add_edge("tracker", END)
    
    return workflow.compile()


def run_threat_analysis(dfd_xml_path: str, config: Dict[str, Any] = None, skip_mitigation: bool = False) -> Dict[str, Any]:
    """Run the complete threat analysis workflow"""
    
    # Create workflow
    app = create_threat_analysis_workflow(skip_mitigation=skip_mitigation)
    
    # Prepare initial state
    initial_state = ThreatAnalysisState(
        dfd_xml_path=dfd_xml_path,
        skip_mitigation=skip_mitigation
    )
    
    # Run workflow
    config = config or {"configurable": {"thread_id": "threat-analysis"}}
    
    final_result = None
    for chunk in app.stream(initial_state, config=config):
        for node_name, node_output in chunk.items():
            if isinstance(node_output, dict):
                final_result = node_output
    
    return final_result