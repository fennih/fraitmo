# RAG Mitigation Proposer Node - Generates and proposes security mitigations using knowledge base

from typing import Dict, List, Any
from pipeline.state import ThreatAnalysisState
from rag.document_loader import load_knowledge_base

def rag_mitigation_proposer_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    RAG Mitigation Proposer Node
    
    Loads appropriate mitigations knowledge base and proposes specific mitigations
    for identified threats based on component classification using RAG.
    
    Args:
        state: Current threat analysis state
        
    Returns:
        Updated state with proposed mitigations
    """
    print("💡 RAG Mitigation Proposer Node: Loading and proposing mitigations from knowledge base...")
    
    try:
        # Combine threats from both knowledge base and direct LLM analysis
        threats_found = state.get('threats_found', [])
        llm_threats = state.get('llm_threats', [])
        llm_mitigations = state.get('llm_mitigations', [])
        
        all_threats = threats_found + llm_threats
        
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        
        if not all_threats:
            print("   ℹ️ No threats found - no mitigations needed")
            return {
                "rag_mitigations": llm_mitigations,  # Include LLM mitigations even if no KB threats
                "implementation_plan": {"status": "no_threats", "tasks": []},
                "processing_status": "mitigation_complete",
                "current_node": "rag_mitigation_proposer"
            }
        
        # Load mitigation knowledge bases
        ai_mitigations_kb = []
        general_mitigations_kb = []
        
        # Load AI mitigations if we have AI components/threats
        if ai_components:
            print(f"   🤖 Loading AI mitigations for {len(ai_components)} AI components...")
            try:
                ai_mitigations_kb = load_knowledge_base("knowledge_base/mitigations/ai_mitigations")
            except Exception as e:
                print(f"   ⚠️ Warning: Could not load AI mitigations: {e}")
        
        # Load general mitigations if we have traditional components/threats
        if traditional_components:
            print(f"   🏗️ Loading general mitigations for {len(traditional_components)} traditional components...")
            try:
                general_mitigations_kb = load_knowledge_base("knowledge_base/mitigations/general_mitigations")
            except Exception as e:
                print(f"   ⚠️ Warning: Could not load general mitigations: {e}")
        
        # Match threats to mitigations
        proposed_mitigations = []
        
        for threat in threats_found:
            threat_mitigations = find_mitigations_for_threat(
                threat, ai_mitigations_kb, general_mitigations_kb
            )
            proposed_mitigations.extend(threat_mitigations)
        
        # Remove duplicates and prioritize
        unique_mitigations = deduplicate_mitigations(proposed_mitigations)
        prioritized_mitigations = prioritize_mitigations(unique_mitigations)
        
        # Create implementation plan
        implementation_plan = create_implementation_plan(prioritized_mitigations)
        
        print(f"✅ RAG Mitigation Proposal Complete:")
        print(f"   💡 Mitigations Proposed: {len(prioritized_mitigations)}")
        print(f"   📋 Implementation Tasks: {len(implementation_plan.get('tasks', []))}")
        
        return {
            "rag_mitigations": prioritized_mitigations,
            "rag_implementation_plan": implementation_plan,
            "processing_status": "rag_mitigation_complete",
            "current_node": "rag_mitigation_proposer"
        }
        
    except Exception as e:
        print(f"❌ RAG Mitigation Proposer Error: {e}")
        return {
            "errors": state.get('errors', []) + [f"RAG mitigation proposal failed: {str(e)}"],
            "processing_status": "error",
            "current_node": "rag_mitigation_proposer"
        }


def find_mitigations_for_threat(threat: Dict[str, Any], ai_mitigations: List[Dict], general_mitigations: List[Dict]) -> List[Dict[str, Any]]:
    """
    Find appropriate mitigations for a specific threat
    
    Args:
        threat: Threat to find mitigations for
        ai_mitigations: AI-specific mitigations knowledge base
        general_mitigations: General mitigations knowledge base
        
    Returns:
        List of relevant mitigations
    """
    relevant_mitigations = []
    
    threat_name = threat.get('name', '').lower()
    threat_category = threat.get('category', '').lower()
    threat_source = threat.get('threat_source', 'unknown')
    
    # Choose appropriate mitigation KB
    mitigations_kb = ai_mitigations if threat_source == 'ai' else general_mitigations
    
    # Also search in both if one is empty
    if not mitigations_kb:
        mitigations_kb = ai_mitigations + general_mitigations
    
    # Search for relevant mitigations
    for mitigation in mitigations_kb:
        is_relevant = False
        
        # Check if mitigation addresses this threat
        addresses_threats = mitigation.get('addresses_threats', [])
        for addressed_threat in addresses_threats:
            if (addressed_threat.lower() in threat_name or 
                threat_name in addressed_threat.lower() or
                addressed_threat.lower() in threat_category):
                is_relevant = True
                break
        
        # Check by category matching
        mitigation_categories = mitigation.get('categories', [])
        for cat in mitigation_categories:
            if cat.lower() in threat_category or threat_category in cat.lower():
                is_relevant = True
                break
        
        if is_relevant:
            mitigation_copy = mitigation.copy()
            mitigation_copy['source_threat'] = threat
            mitigation_copy['relevance_reason'] = f"Addresses {threat.get('name', 'threat')}"
            relevant_mitigations.append(mitigation_copy)
    
    return relevant_mitigations


def deduplicate_mitigations(mitigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate mitigations based on name/id
    """
    seen = set()
    unique = []
    
    for mitigation in mitigations:
        mitigation_id = mitigation.get('id') or mitigation.get('name', 'unknown')
        if mitigation_id not in seen:
            seen.add(mitigation_id)
            unique.append(mitigation)
    
    return unique


def prioritize_mitigations(mitigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prioritize mitigations by effectiveness and implementation ease
    """
    def get_priority_score(mitigation):
        # Priority factors
        effectiveness = mitigation.get('effectiveness', 'medium').lower()
        implementation_difficulty = mitigation.get('implementation_difficulty', 'medium').lower()
        cost = mitigation.get('cost', 'medium').lower()
        
        # Scoring system
        effectiveness_score = {'high': 3, 'medium': 2, 'low': 1}.get(effectiveness, 2)
        difficulty_score = {'low': 3, 'medium': 2, 'high': 1}.get(implementation_difficulty, 2)
        cost_score = {'low': 3, 'medium': 2, 'high': 1}.get(cost, 2)
        
        return effectiveness_score + difficulty_score + cost_score
    
    # Sort by priority score (highest first)
    return sorted(mitigations, key=get_priority_score, reverse=True)


def create_implementation_plan(mitigations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Create an implementation plan based on proposed mitigations
    """
    if not mitigations:
        return {"status": "no_mitigations", "tasks": []}
    
    tasks = []
    
    for i, mitigation in enumerate(mitigations, 1):
        task = {
            "id": f"task_{i}",
            "name": mitigation.get('name', f'Mitigation {i}'),
            "description": mitigation.get('description', 'No description available'),
            "priority": get_task_priority(mitigation),
            "estimated_effort": mitigation.get('implementation_time', 'Unknown'),
            "cost": mitigation.get('cost', 'Unknown'),
            "dependencies": mitigation.get('dependencies', []),
            "status": "pending"
        }
        tasks.append(task)
    
    # Calculate overall plan metrics
    critical_tasks = len([t for t in tasks if t['priority'] == 'critical'])
    high_tasks = len([t for t in tasks if t['priority'] == 'high'])
    
    plan = {
        "status": "planned",
        "total_tasks": len(tasks),
        "critical_tasks": critical_tasks,
        "high_priority_tasks": high_tasks,
        "estimated_completion": estimate_completion_time(tasks),
        "tasks": tasks
    }
    
    return plan


def get_task_priority(mitigation: Dict[str, Any]) -> str:
    """
    Determine task priority based on mitigation characteristics
    """
    effectiveness = mitigation.get('effectiveness', 'medium').lower()
    addresses_threats = mitigation.get('addresses_threats', [])
    
    # Critical if high effectiveness or addresses many threats
    if effectiveness == 'high' or len(addresses_threats) >= 3:
        return 'critical'
    elif effectiveness == 'medium' or len(addresses_threats) >= 2:
        return 'high'
    else:
        return 'medium'


def estimate_completion_time(tasks: List[Dict[str, Any]]) -> str:
    """
    Estimate overall completion time for implementation plan
    """
    if not tasks:
        return "immediate"
    
    critical_count = len([t for t in tasks if t['priority'] == 'critical'])
    total_count = len(tasks)
    
    if critical_count >= 5:
        return "3-6 months"
    elif critical_count >= 3:
        return "2-3 months"
    elif total_count >= 10:
        return "1-2 months"
    else:
        return "2-4 weeks" 