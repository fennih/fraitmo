# RAG Mitigation Proposer Node - Generates and proposes security mitigations using knowledge base

from typing import Dict, Any, List
from rich.console import Console
from rich.text import Text

console = Console()

def rag_mitigation_proposer_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    RAG Mitigation Proposer Node
    Loads and proposes mitigations from knowledge base using RAG
    """
    console.print(Text("[INFO]", style="bold blue"), "RAG Mitigation Proposer Node: Loading and proposing mitigations from knowledge base...")
    
    try:
        # Import here to avoid circular dependencies
        from rag.document_loader import load_threat_knowledge_base, search_threats
        
        # Get threats and component data
        threats_found = state.get('threats_found', [])
        ai_components = state.get('ai_components', [])
        traditional_components = state.get('traditional_components', [])
        
        if not threats_found and not ai_components and not traditional_components:
            console.print(Text("[INFO]", style="bold blue"), "No threats found - no mitigations needed")
            return {
                "rag_mitigations": [],
                "rag_implementation_plan": {}
            }
        
        # Load mitigation knowledge bases
        ai_mitigations_kb = []
        general_mitigations_kb = []
        
        # Load AI-specific mitigations
        if ai_components:
            try:
                console.print(Text("[INFO]", style="bold blue"), f"Loading AI mitigations for {len(ai_components)} AI components...")
                ai_mitigations_kb = load_threat_knowledge_base("knowledge_base/mitigations/ai_mitigations")
            except Exception as e:
                console.print(Text("[WARN]", style="bold yellow"), f"Warning: Could not load AI mitigations: {e}")
        
        # Load general mitigations
        try:
            console.print(Text("[INFO]", style="bold blue"), f"Loading general mitigations for {len(traditional_components)} traditional components...")
            general_mitigations_kb = load_threat_knowledge_base("knowledge_base/mitigations")
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Warning: Could not load general mitigations: {e}")
        
        # Search for relevant mitigations
        mitigations = []
        
        # Search mitigations for each threat
        for threat in threats_found:
            threat_name = threat.get('name', 'Unknown')
            search_query = f"{threat_name} mitigation prevention control"
            
            # Search in appropriate knowledge base
            relevant_mitigations = search_threats(
                ai_mitigations_kb + general_mitigations_kb, 
                search_query, 
                max_results=3
            )
            
            for mitigation in relevant_mitigations:
                mitigation['target_threat'] = threat_name
                mitigation['source_path'] = 'rag_mitigation'
                mitigations.append(mitigation)
        
        # Prioritize and structure mitigations
        prioritized_mitigations = _prioritize_mitigations(mitigations)
        
        # Generate implementation plan
        implementation_plan = _generate_implementation_plan(prioritized_mitigations)
        
        # Store results
        # Results calculated above
        
        console.print(Text("[OK]", style="bold green"), "RAG Mitigation Proposal Complete:")
        console.print(Text("[INFO]", style="bold blue"), f"Mitigations Proposed: {len(prioritized_mitigations)}")
        console.print(Text("[INFO]", style="bold blue"), f"Implementation Tasks: {len(implementation_plan.get('tasks', []))}")
        console.print(Text("[INFO]", style="bold blue"), f"Estimated Timeline: {implementation_plan.get('timeline', 'Unknown')}")
        
        # Return only the fields we're modifying
        return {
            "rag_mitigations": prioritized_mitigations,
            "rag_implementation_plan": implementation_plan
        }
        
    except Exception as e:
        error_msg = f"RAG Mitigation Proposer Error: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {"errors": [error_msg]}


def _prioritize_mitigations(mitigations: List[Dict]) -> List[Dict]:
    """Prioritize mitigations based on effectiveness and implementation difficulty"""
    # Simple prioritization logic
    priority_scores = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1
    }
    
    for mitigation in mitigations:
        severity = mitigation.get('severity', 'medium').lower()
        mitigation['priority_score'] = priority_scores.get(severity, 2)
    
    # Sort by priority score (descending)
    return sorted(mitigations, key=lambda x: x.get('priority_score', 0), reverse=True)


def _generate_implementation_plan(mitigations: List[Dict]) -> Dict[str, Any]:
    """Generate implementation plan for mitigations"""
    if not mitigations:
        return {'tasks': [], 'timeline': 'N/A'}
    
    tasks = []
    for i, mitigation in enumerate(mitigations[:10], 1):  # Top 10 mitigations
        task = {
            'id': f"MIT_{i:02d}",
            'name': mitigation.get('name', 'Unknown Mitigation'),
            'description': mitigation.get('description', ''),
            'priority': mitigation.get('severity', 'medium'),
            'estimated_effort': mitigation.get('effort', 'medium'),
            'target_threat': mitigation.get('target_threat', 'Unknown')
        }
        tasks.append(task)
    
    # Simple timeline estimation
    critical_tasks = len([t for t in tasks if t['priority'].lower() == 'critical'])
    high_tasks = len([t for t in tasks if t['priority'].lower() == 'high'])
    
    if critical_tasks > 3:
        timeline = "8-12 weeks"
    elif critical_tasks > 0 or high_tasks > 5:
        timeline = "4-8 weeks"
    else:
        timeline = "2-4 weeks"
    
    return {
        'tasks': tasks,
        'timeline': timeline,
        'total_tasks': len(tasks),
        'critical_tasks': critical_tasks,
        'high_priority_tasks': high_tasks
    } 