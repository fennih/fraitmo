# LangGraph Pipeline Definition - Defines nodes, edges, and execution flow for threat analysis

import os
from typing import Dict, Any
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from pipeline.state import ThreatAnalysisState
from pipeline.nodes.ai_detector import ai_component_detector_node
from pipeline.nodes.kb_router import knowledge_base_router_node, threat_search_node
from pipeline.nodes.mitigation_proposer import mitigation_proposer_node
from pipeline.nodes.direct_llm_analyzer import direct_llm_analyzer_node
from pipeline.nodes.direct_mitigation_proposer import direct_mitigation_proposer_node

from dfd_parser.xml_parser import extract_from_xml
from models.builder import DFDBuilder

def dfd_parser_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    DFD Parser Node - Parses DFD XML input
    """
    print("📋 DFD Parser Node: Parsing DFD XML...")
    
    try:
        xml_path = state.get('dfd_xml_path')
        if not xml_path:
            return {
                "errors": state.get('errors', []) + ["No DFD XML path provided"],
                "processing_status": "error",
                "current_node": "dfd_parser"
            }
        
        # Parse XML using existing parser
        parsed_data = extract_from_xml(xml_path)
        
        print(f"✅ DFD Parsed:")
        print(f"   📊 Components: {len(parsed_data.get('components', {}))}")
        print(f"   🔗 Connections: {len(parsed_data.get('connections', []))}")
        print(f"   🏰 Trust Zones: {len(parsed_data.get('trust_zones', {}))}")
        
        return {
            "parsed_data": parsed_data,
            "processing_status": "dfd_parsed",
            "current_node": "dfd_parser"
        }
        
    except Exception as e:
        print(f"❌ DFD Parser Error: {e}")
        return {
            "errors": state.get('errors', []) + [f"DFD parsing failed: {str(e)}"],
            "processing_status": "error",
            "current_node": "dfd_parser"
        }


def semantic_modeling_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Semantic Modeling Node - Builds semantic DFD model
    """
    print("🏗️ Semantic Modeling Node: Building semantic model...")
    
    try:
        parsed_data = state.get('parsed_data')
        if not parsed_data:
            return {
                "errors": state.get('errors', []) + ["No parsed data available for semantic modeling"],
                "processing_status": "error",
                "current_node": "semantic_modeling"
            }
        
        # Build semantic model using existing builder
        builder = DFDBuilder()
        dfd_model = builder.from_parser_output(parsed_data).build(
            name="FRAITMO Threat Analysis",
            description=f"Generated from {state.get('dfd_xml_path', 'DFD')}"
        )
        
        print(f"✅ Semantic Model Built:")
        print(f"   📊 Components: {len(dfd_model.components)}")
        print(f"   🔗 Connections: {len(dfd_model.connections)}")
        print(f"   🚨 Cross-zone connections: {len(dfd_model.cross_zone_connections)}")
        
        return {
            "dfd_model": dfd_model,
            "processing_status": "semantic_model_built",
            "current_node": "semantic_modeling"
        }
        
    except Exception as e:
        print(f"❌ Semantic Modeling Error: {e}")
        return {
            "errors": state.get('errors', []) + [f"Semantic modeling failed: {str(e)}"],
            "processing_status": "error",
            "current_node": "semantic_modeling"
        }


def llm_analysis_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    LLM Analysis Node - Contextualizes threats using UnifiedLLMClient
    """
    print("🤖 LLM Analysis Node: Analyzing threats with LLM...")
    
    try:
        from rag.llm_client import UnifiedLLMClient
        
        # Initialize unified LLM client
        client = UnifiedLLMClient(preferred_model="foundation-sec")
        
        # Get threats and components for analysis
        threats_found = state.get('threats_found', [])
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        dfd_model = state.get('dfd_model')
        
        if not threats_found:
            print("   ℹ️ No threats found to analyze")
            return {
                "threat_analysis": {"summary": "No threats identified for analysis"},
                "risk_assessment": {"overall_risk": "low", "reason": "No threats detected"},
                "processing_status": "llm_analysis_complete",
                "current_node": "llm_analysis"
            }
        
        # Create analysis prompt
        prompt = create_threat_analysis_prompt(
            threats_found, ai_components, traditional_components, dfd_model
        )
        
        print(f"   📤 Sending {len(threats_found)} threats to LLM for analysis...")
        response = client.query(prompt, max_tokens=800, temperature=0.1)
        
        # Simple risk assessment
        risk_level = assess_risk_level(threats_found)
        
        threat_analysis = {
            "llm_response": response,
            "total_threats": len(threats_found),
            "ai_threats_count": len(state.get('ai_threats', [])),
            "traditional_threats_count": len(state.get('traditional_threats', [])),
            "analysis_timestamp": "now",  # You could use actual timestamp
            "model_used": f"{client.active_model} via {client.active_provider}"
        }
        
        risk_assessment = {
            "overall_risk": risk_level,
            "threat_breakdown": {
                "critical": len([t for t in threats_found if t.get('severity', '').lower() == 'critical']),
                "high": len([t for t in threats_found if t.get('severity', '').lower() == 'high']),
                "medium": len([t for t in threats_found if t.get('severity', '').lower() == 'medium']),
                "low": len([t for t in threats_found if t.get('severity', '').lower() == 'low'])
            }
        }
        
        print(f"✅ LLM Analysis Complete:")
        print(f"   📊 Threats Analyzed: {len(threats_found)}")
        print(f"   🚨 Overall Risk: {risk_level}")
        print(f"   🤖 Model Used: {client.active_model} via {client.active_provider}")
        
        return {
            "threat_analysis": threat_analysis,
            "risk_assessment": risk_assessment,
            "processing_status": "llm_analysis_complete",
            "current_node": "llm_analysis"
        }
        
    except Exception as e:
        print(f"❌ LLM Analysis Error: {e}")
        return {
            "errors": state.get('errors', []) + [f"LLM analysis failed: {str(e)}"],
            "processing_status": "error", 
            "current_node": "llm_analysis"
        }


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


def create_fraitmo_graph():
    """
    Create the complete FRAITMO threat analysis graph
    
    Returns:
        Compiled LangGraph application
    """
    # Load environment variables
    load_dotenv()
    
    print("🔄 Creating FRAITMO LangGraph pipeline...")
    
    # Create the graph
    workflow = StateGraph(ThreatAnalysisState)
    
    # Add nodes in the order of execution
    workflow.add_node("dfd_parser", dfd_parser_node)
    workflow.add_node("semantic_modeling", semantic_modeling_node)
    workflow.add_node("ai_detector", ai_component_detector_node)
    workflow.add_node("kb_router", knowledge_base_router_node)
    workflow.add_node("threat_search", threat_search_node)
    workflow.add_node("llm_analysis", llm_analysis_node)
    workflow.add_node("direct_llm_analyzer", direct_llm_analyzer_node)
    workflow.add_node("mitigation_proposer", mitigation_proposer_node)
    workflow.add_node("direct_mitigation_proposer", direct_mitigation_proposer_node)
    
    # Set entry point
    workflow.set_entry_point("dfd_parser")
    
    # Define the execution flow
    workflow.add_edge("dfd_parser", "semantic_modeling")
    workflow.add_edge("semantic_modeling", "ai_detector")
    workflow.add_edge("ai_detector", "kb_router")
    workflow.add_edge("kb_router", "threat_search")
    workflow.add_edge("threat_search", "llm_analysis")
    
    # Add parallel direct LLM analysis after ai_detector
    workflow.add_edge("ai_detector", "direct_llm_analyzer")
    
    # Both paths have their own mitigation proposers
    workflow.add_edge("llm_analysis", "mitigation_proposer")
    workflow.add_edge("direct_llm_analyzer", "direct_mitigation_proposer")
    
    # Both mitigation paths end
    workflow.add_edge("mitigation_proposer", END)
    workflow.add_edge("direct_mitigation_proposer", END)
    
    # Compile with memory saver for state persistence
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)
    
    print("✅ FRAITMO LangGraph pipeline created successfully!")
    
    return app


def run_fraitmo_analysis(dfd_xml_path: str, config: Dict[str, Any] = None):
    """
    Run complete FRAITMO threat analysis
    
    Args:
        dfd_xml_path: Path to DFD XML file
        config: Optional configuration for the graph execution
    """
    print("🚀 Starting FRAITMO LangGraph Threat Analysis")
    print("=" * 60)
    
    # Create the graph
    app = create_fraitmo_graph()
    
    # Initial state
    initial_state = {
        "dfd_xml_path": dfd_xml_path,
        "dfd_content": None,
        "dfd_model": None,
        "parsed_data": None,
        "ai_components": [],
        "traditional_components": [],
        "component_classification": {},
        "ai_knowledge_base": [],
        "general_knowledge_base": [],
        "threats_found": [],
        "ai_threats": [],
        "traditional_threats": [],
        "cross_zone_threats": [],
        "direct_threats": [],
        "direct_mitigations": [],
        "direct_analysis_summary": {},
        "threat_analysis": {},
        "risk_assessment": {},
        "mitigations": [],
        "implementation_plan": {},
        "direct_mitigations_kb": [],
        "direct_implementation_plan": {},
        "direct_mitigation_summary": {},
        "implementation_tracker": {},
        "processing_status": "started",
        "direct_analysis_status": "pending",
        "direct_mitigation_status": "pending",
        "current_node": "initializing",
        "errors": [],
        "warnings": []
    }
    
    # Configure execution
    if config is None:
        config = {"configurable": {"thread_id": "fraitmo-analysis-1"}}
    
    try:
        # Execute the graph
        print("🔄 Executing LangGraph pipeline...")
        result = app.invoke(initial_state, config=config)
        
        print("\n🎉 FRAITMO Analysis Complete!")
        print("=" * 60)
        
        # Display summary
        display_analysis_summary(result)
        
        return result
        
    except Exception as e:
        print(f"❌ FRAITMO Analysis Failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def display_analysis_summary(result):
    """Display a summary of the analysis results"""
    print(f"\n📊 ANALYSIS SUMMARY:")
    print(f"   Status: {result.get('processing_status', 'unknown')}")
    print(f"   🤖 AI Components: {len(result.get('ai_components', []))}")
    print(f"   🏗️ Traditional Components: {len(result.get('traditional_components', []))}")
    
    # Combined threats and mitigations from both paths
    total_threats = len(result.get('threats_found', [])) + len(result.get('direct_threats', []))
    total_mitigations = len(result.get('mitigations', [])) + len(result.get('direct_mitigations_kb', []))
    
    print(f"   🚨 Total Threats Found: {total_threats}")
    print(f"     📚 KB Path: {len(result.get('threats_found', []))}")
    print(f"     🧠 Direct LLM: {len(result.get('direct_threats', []))}")
    
    print(f"   💡 Total Mitigations: {total_mitigations}")
    print(f"     📚 KB Path: {len(result.get('mitigations', []))}")
    print(f"     🧠 Direct LLM: {len(result.get('direct_mitigations_kb', []))}")
    
    print(f"   🎯 Overall Risk: {result.get('risk_assessment', {}).get('overall_risk', 'unknown')}")
    
    if result.get('errors'):
        print(f"   ❌ Errors: {len(result.get('errors', []))}")
        for error in result.get('errors', []):
            print(f"     - {error}")


if __name__ == "__main__":
    # Test the pipeline
    import sys
    if len(sys.argv) > 1:
        dfd_path = sys.argv[1]
        run_fraitmo_analysis(dfd_path)
    else:
        print("Usage: python pipeline/graph.py <path_to_dfd.xml>")
