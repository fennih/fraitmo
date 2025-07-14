# LangGraph State Schema - Defines the state structure for threat analysis pipeline

from typing import Dict, List, Any, Optional, TypedDict
from models.schema import DataFlowDiagram

class ThreatAnalysisState(TypedDict):
    """
    State schema for FRAITMO threat analysis pipeline
    
    This defines all the data that flows through the LangGraph pipeline,
    from initial DFD parsing to final threat analysis and mitigation proposal.
    """
    
    # Input data
    dfd_xml_path: Optional[str]  # Path to DFD XML file
    dfd_content: Optional[str]   # Raw DFD content
    
    # Parsed and processed data
    parsed_data: Optional[Dict[str, Any]]  # Raw parsed DFD data
    dfd_model: Optional[DataFlowDiagram]          # Semantic DFD model
    
    # Component classification
    ai_components: List[Dict[str, Any]]        # AI/LLM components
    traditional_components: List[Dict[str, Any]]  # Traditional components
    component_classification: Dict[str, Any]   # Classification metadata
    
    # Knowledge base data
    ai_knowledge_base: List[Dict[str, Any]]      # AI-specific threat knowledge
    general_knowledge_base: List[Dict[str, Any]]  # General threat knowledge
    routing_strategy: List[str]                  # KB routing strategy used
    
    # Threat identification
    threats_found: List[Dict[str, Any]]        # All identified threats
    ai_threats: List[Dict[str, Any]]           # AI-specific threats
    traditional_threats: List[Dict[str, Any]]   # Traditional threats
    cross_zone_threats: List[Dict[str, Any]]   # Cross-zone threats
    
    # LLM analysis
    threat_analysis: Dict[str, Any]  # LLM analysis results
    risk_assessment: Dict[str, Any]  # Risk assessment results
    
    # Mitigation proposal
    mitigations: List[Dict[str, Any]]         # Proposed mitigations
    implementation_plan: Dict[str, Any]       # Implementation plan with tasks
    
    # Implementation tracking
    implementation_tracker: Dict[str, Any]  # Progress tracking
    
    # Pipeline state
    processing_status: str       # Current processing status
    current_node: str           # Current node being processed
    errors: List[str]           # Error messages
    warnings: List[str]         # Warning messages
    
    # Configuration
    ollama_model: Optional[str]      # Ollama model to use
    ollama_base_url: Optional[str]   # Ollama base URL
