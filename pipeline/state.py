# LangGraph State Schema - Defines the state structure for threat analysis pipeline

from typing import Dict, List, Any, Optional, TypedDict, Annotated
# Removed redundant import - already imported from typing above
import operator
from models.schema import DataFlowDiagram

class ThreatAnalysisState(TypedDict):
    """
    State schema for FRAITMO threat analysis pipeline

    This defines all the data that flows through the LangGraph pipeline,
    from initial DFD parsing to final threat analysis and mitigation proposal.
    """

    # Input data
    dfd_xml_path: str  # Path to DFD XML file
    dfd_content: Optional[str]   # Raw DFD content

    # Parsed and processed data
    parsed_data: Optional[Dict[str, Any]]  # Raw parsed DFD data
    dfd_model: Optional[DataFlowDiagram]          # Semantic DFD model

    # Component classification
    ai_components: Annotated[List[Dict[str, Any]], operator.add]        # AI/LLM components
    traditional_components: Annotated[List[Dict[str, Any]], operator.add]  # Traditional components
    component_classification: Dict[str, Any]   # Classification metadata

    # Knowledge base data
    ai_knowledge_base: Annotated[List[Dict[str, Any]], operator.add]      # AI-specific threat knowledge
    general_knowledge_base: Annotated[List[Dict[str, Any]], operator.add]  # General threat knowledge
    routing_strategy: Annotated[List[str], operator.add]                  # KB routing strategy used

    # Threat identification
    threats_found: Annotated[List[Dict[str, Any]], operator.add]        # All identified threats
    ai_threats: Annotated[List[Dict[str, Any]], operator.add]           # AI-specific threats
    traditional_threats: Annotated[List[Dict[str, Any]], operator.add]   # Traditional threats
    cross_zone_threats: Annotated[List[Dict[str, Any]], operator.add]   # Cross-zone threats

    # LLM analysis (parallel path)
    llm_threats: Annotated[List[Dict[str, Any]], operator.add]       # LLM identified threats
    llm_analysis_summary: Dict[str, Any]

    # Cross-Component Analysis Results
    cross_component_threats: Annotated[List[Dict[str, Any]], operator.add]  # Data flow and trust boundary threats
    trust_boundary_count: int                                               # Number of trust boundaries
    data_flow_count: int                                                    # Number of data flows analyzed

    # LLM analysis
    threat_analysis: Dict[str, Any]  # LLM analysis results
    risk_assessment: Dict[str, Any]  # Risk assessment results

    # RAG mitigation proposal (from knowledge base)
    rag_mitigations: Annotated[List[Dict[str, Any]], operator.add]         # Proposed mitigations (from KB)
    rag_implementation_plan: Dict[str, Any]       # Implementation plan with tasks

    # LLM mitigation proposal (parallel path)
    llm_mitigations: Annotated[List[Dict[str, Any]], operator.add]         # LLM mitigations
    llm_implementation_plan: Dict[str, Any]       # LLM implementation plan
    llm_mitigation_summary: Dict[str, Any]        # LLM mitigation summary

    # Implementation tracking
    implementation_tracker: Dict[str, Any]  # Progress tracking

    # Quality Filter Results
    filtered_threats: Annotated[List[Dict[str, Any]], operator.add]         # LLM-filtered unique threats
    filtered_mitigations: Annotated[List[Dict[str, Any]], operator.add]     # LLM-filtered relevant mitigations
    threat_mitigation_mapping: Dict[str, Any]                               # Explicit threat-mitigation mappings
    quality_filter_applied: bool                                            # Whether quality filtering was successful

    # Pipeline state
    processing_status: str       # Current processing status (RAG path)
    llm_analysis_status: str     # LLM analysis status
    llm_mitigation_status: str   # LLM mitigation status
    current_node: str           # Current node being processed
    errors: Annotated[List[str], operator.add]           # Error messages
    warnings: Annotated[List[str], operator.add]         # Warning messages

    # Configuration (now handled by UnifiedLLMClient)
    # No specific LLM configuration needed - auto-detected
    skip_mitigation: bool  # Flag to skip mitigation generation for faster execution
